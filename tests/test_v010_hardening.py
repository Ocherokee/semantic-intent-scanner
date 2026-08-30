import json

import pytest

from scanner.mcp_adapter import (
    MAX_MCP_INPUT_BYTES, MAX_MCP_NESTING_DEPTH, _walk_descriptions, audit_mcp_tools,
)
from scanner.composite_audit import MAX_LOCAL_ARTIFACT_BYTES, semantic_adapter
from scanner.cli import MAX_PUBLIC_ERROR_LENGTH, _public_error
from scanner.directory_audit import MAX_AUDITED_FILE_BYTES, _audit_file
from scanner.remote_fetch import (
    RemoteFetchBlocked, _chain_crossed_origin, guarded_fetch,
    resolve_and_validate,
)
from scanner.surface_inventory import (
    MAX_STRUCTURED_DOCUMENT_BYTES, DiscoveryRecord, InventoryEntry, InventoryError,
    SurfaceInventory, SurfaceObservation, SurfaceRelationship, _parse_api_schema,
    _parse_manifest, canonical_origin, canonicalize_url,
)
from scanner.finding_contract import finding_contract_as_dict
from scanner.trust_analysis import analyze_trust_boundaries


@pytest.mark.parametrize(("raw", "expected"), [
    ("https://EXAMPLE.com./a/../b#x", "https://example.com/b"),
    ("https://bücher.example:443/", "https://xn--bcher-kva.example/"),
    ("https://[2001:0db8::1]:443/a", "https://[2001:db8::1]/a"),
    ("https://example.com:8443/A%2fb?x=%2e", "https://example.com:8443/A%2fb?x=%2e"),
    ("https://example.com/%2e%2e/admin", "https://example.com/%2e%2e/admin"),
])
def test_url_canonicalization_security_cases(raw, expected):
    assert canonicalize_url(raw) == expected


def test_idn_and_punycode_origins_are_equivalent():
    assert canonical_origin("https://bücher.example") == canonical_origin("https://xn--bcher-kva.example")


@pytest.mark.parametrize(("start", "redirect"), [
    ("https://EXAMPLE.com./a", "https://example.com/b"),
    ("https://bücher.example/a", "https://xn--bcher-kva.example/b"),
    ("https://example.com:443/a", "https://example.com/b"),
    ("https://[2001:0db8::1]/a", "https://[2001:db8::1]:443/b"),
])
def test_redirect_origin_uses_authoritative_equivalence(start, redirect):
    assert not _chain_crossed_origin(start, [{"url": redirect, "status": 200}])


@pytest.mark.parametrize(("start", "redirect"), [
    ("https://example.com/a", "https://example.com:8443/b"),
    ("https://example.com/a", "https://other.example/b"),
])
def test_redirect_origin_preserves_real_boundaries(start, redirect):
    assert _chain_crossed_origin(start, [{"url": redirect, "status": 200}])


def test_fetch_guard_rejects_malformed_hostname_before_resolution():
    called = False
    def resolver(_host):
        nonlocal called
        called = True
        return ["93.184.216.34"]
    with pytest.raises(RemoteFetchBlocked, match="malformed"):
        resolve_and_validate("https://bad_host.example/", resolver)
    assert not called


def test_fetch_failure_does_not_publish_raw_exception_detail():
    def transport(*_args, **_kwargs):
        raise OSError(r"secret C:\Users\operator\token.txt")
    outcome = guarded_fetch(
        "https://example.com/", transport=transport,
        resolver=lambda _host: ["93.184.216.34"],
    )
    assert outcome.error == "transport failure (OSError)"
    assert "operator" not in outcome.error


def test_fetch_block_reason_is_bounded():
    def transport(*_args, **_kwargs):
        raise RemoteFetchBlocked("x" * 1000)
    outcome = guarded_fetch(
        "https://example.com/", transport=transport,
        resolver=lambda _host: ["93.184.216.34"],
    )
    assert len(outcome.blocked_reason) == 240
    assert outcome.blocked_reason.endswith("...")


def test_cli_public_errors_are_sanitized_and_bounded():
    assert _public_error(OSError(r"secret C:\Users\operator\token.txt")) == "input cannot be read"
    assert len(_public_error(ValueError("x" * 1000))) == MAX_PUBLIC_ERROR_LENGTH


@pytest.mark.parametrize("url", [
    "//example.com/path", "https://user@example.com/", "https://bad_host.example/",
    "https://-bad.example/", "https://example..com/",
])
def test_unsafe_or_malformed_absolute_urls_are_rejected(url):
    with pytest.raises(InventoryError):
        canonicalize_url(url)


def test_malformed_manifest_declaration_is_visible():
    found, metadata = _parse_manifest('{"api":{"url":"http://unsafe.example"}}', "https://example.com/manifest.json")
    assert found == []
    assert "api.url is invalid" in metadata["declaration_error"]


@pytest.mark.parametrize("field", ["mcp_endpoint", "agent_endpoint"])
def test_malformed_manifest_capability_declaration_is_visible(field):
    found, metadata = _parse_manifest(json.dumps({field: 7}), "https://example.com/manifest.json")
    assert found == []
    assert metadata[f"{field}_declaration_error"] == f"{field} must be a string"


def test_openapi_locator_and_malformed_declaration_are_visible():
    found, metadata = _parse_api_schema(json.dumps({"servers": [{"url": "https://api.example/v1"}, {"url": 4}]}), "https://example.com/openapi.json")
    assert found[0][2]["source_field"] == "servers[0].url"
    assert metadata["declaration_error_1"] == "servers[1].url must be a string"


def test_multiple_openapi_server_locator_indexes_do_not_collapse():
    found, metadata = _parse_api_schema(json.dumps({"servers": [
        {"url": "https://one.example/v1"}, {"url": "https://two.example/v1"},
    ]}), "https://example.com/openapi.json")
    assert metadata == {}
    assert [item[2]["source_field"] for item in found] == ["servers[0].url", "servers[1].url"]


def test_openapi_index_locator_survives_finding_contract():
    source = "https://example.com/openapi.json"
    target = "https://api.example/v1"
    inventory = SurfaceInventory("https://example.com", (
        InventoryEntry("api_schema", source, (DiscoveryRecord("scanner_known_path"),), SurfaceObservation("retrieved")),
        InventoryEntry("advertised_endpoint", target, (DiscoveryRecord("schema_declaration", source),), SurfaceObservation("advertised"), (SurfaceRelationship("declared_by", source),), {"endpoint_kind": "openapi_server", "source_field": "servers[2].url"}),
    ))
    finding = finding_contract_as_dict(analyze_trust_boundaries(inventory)[0])
    assert finding["context"]["authority_edge"]["source_field"] == "servers[2].url"
    assert any(item["kind"] == "source_field" and item["value"] == "servers[2].url" for item in finding["observation"]["evidence"])


@pytest.mark.parametrize(("target_type", "metadata", "expected"), [
    ("api_schema", {}, "api.url"),
    ("advertised_endpoint", {"endpoint_kind": "mcp_endpoint"}, "mcp_endpoint"),
    ("advertised_endpoint", {"endpoint_kind": "agent_endpoint"}, "agent_endpoint"),
])
def test_manifest_locator_survives_finding_contract(target_type, metadata, expected):
    source = "https://example.com/.well-known/ai-plugin.json"
    target = "https://other.example/resource"
    inventory = SurfaceInventory("https://example.com", (
        InventoryEntry("ai_manifest", source, (DiscoveryRecord("well_known_path"),), SurfaceObservation("retrieved")),
        InventoryEntry(target_type, target, (DiscoveryRecord("manifest_declaration", source),), SurfaceObservation("advertised"), (SurfaceRelationship("declared_by", source),), metadata),
    ))
    finding = finding_contract_as_dict(analyze_trust_boundaries(inventory)[0])
    assert finding["context"]["authority_edge"]["source_field"] == expected
    assert any(item["kind"] == "source_field" and item["value"] == expected for item in finding["observation"]["evidence"])


def test_structured_document_limit_is_visible():
    found, metadata = _parse_manifest(" " * (MAX_STRUCTURED_DOCUMENT_BYTES + 1), "https://example.com/manifest.json")
    assert found == []
    assert metadata["resource_limit"] == MAX_STRUCTURED_DOCUMENT_BYTES


def test_structured_document_exact_limit_is_accepted():
    prefix = '{"name_for_model":"x"}'
    text = prefix + " " * (MAX_STRUCTURED_DOCUMENT_BYTES - len(prefix))
    _found, metadata = _parse_manifest(text, "https://example.com/manifest.json")
    assert "parse_error" not in metadata


def test_mcp_input_byte_limit_fails_visibly(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(" " * (MAX_MCP_INPUT_BYTES + 1), encoding="utf-8")
    result = audit_mcp_tools(str(path))
    assert "byte limit" in result["parse_error"]
    assert result["findings"] == []


def test_mcp_exact_byte_limit_is_accepted(tmp_path):
    prefix = '{"tools":[]}'
    path = tmp_path / "tools.json"
    path.write_text(prefix + " " * (MAX_MCP_INPUT_BYTES - len(prefix)), encoding="utf-8")
    result = audit_mcp_tools(str(path))
    assert result["parse_error"] is None
    assert "no tool definitions" in result["note"]


@pytest.mark.parametrize("payload", [
    {"tools": [7]},
    {"tools": [{"name": "broken", "inputSchema": "not-a-schema"}]},
])
def test_malformed_mcp_structures_are_visible(tmp_path, payload):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = audit_mcp_tools(str(path))
    assert result.get("parse_error") or any(doc.get("error") for doc in result["documents"])
    assert result["findings"] == []


def test_mcp_read_failure_does_not_publish_os_path(tmp_path):
    missing = tmp_path / "private" / "tools.json"
    result = audit_mcp_tools(str(missing))
    assert result["parse_error"] == "input cannot be read"
    assert str(missing) not in result["note"]


def test_mcp_traversal_depth_boundary_is_explicit():
    exact = {"description": "ok"}
    for _ in range(MAX_MCP_NESTING_DEPTH):
        exact = {"x": exact}
    output = []
    _walk_descriptions(exact, ["parameters"], "inputSchema", output)
    assert output
    above = {"x": exact}
    with pytest.raises(ValueError, match="nesting depth"):
        _walk_descriptions(above, ["parameters"], "inputSchema", [])


def test_composite_local_skill_limit_fails_visibly(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("x" * (MAX_LOCAL_ARTIFACT_BYTES + 1), encoding="utf-8")
    outcome = semantic_adapter("semantic", path).run()
    assert outcome.status == "failed_invalid_input"
    assert "byte limit" in outcome.reason


def test_composite_local_skill_exact_limit_reaches_evaluator(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("x" * MAX_LOCAL_ARTIFACT_BYTES, encoding="utf-8")
    outcome = semantic_adapter("semantic", path, evaluator=lambda *_a, **_kw: {
        "overall_risk": "low", "chunks": [], "violations": [],
    }).run()
    assert outcome.status == "success"


def test_directory_file_limit_is_visible_and_exact_boundary_is_scanned(tmp_path):
    exact = tmp_path / "exact.py"
    exact.write_text("x" * MAX_AUDITED_FILE_BYTES, encoding="utf-8")
    assert "resource_limit_exceeded" not in _audit_file(exact)
    above = tmp_path / "above.py"
    above.write_text("x" * (MAX_AUDITED_FILE_BYTES + 1), encoding="utf-8")
    finding = _audit_file(above)
    assert finding["resource_limit_exceeded"] is True
    assert "not analyzed" in finding["reason"]
