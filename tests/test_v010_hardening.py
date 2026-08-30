import json

import pytest

from scanner.mcp_adapter import MAX_MCP_INPUT_BYTES, audit_mcp_tools
from scanner.composite_audit import MAX_LOCAL_ARTIFACT_BYTES, semantic_adapter
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


def test_openapi_locator_and_malformed_declaration_are_visible():
    found, metadata = _parse_api_schema(json.dumps({"servers": [{"url": "https://api.example/v1"}, {"url": 4}]}), "https://example.com/openapi.json")
    assert found[0][2]["source_field"] == "servers[0].url"
    assert metadata["declaration_error_1"] == "servers[1].url must be a string"


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


def test_structured_document_limit_is_visible():
    found, metadata = _parse_manifest(" " * (MAX_STRUCTURED_DOCUMENT_BYTES + 1), "https://example.com/manifest.json")
    assert found == []
    assert metadata["resource_limit"] == MAX_STRUCTURED_DOCUMENT_BYTES


def test_mcp_input_byte_limit_fails_visibly(tmp_path):
    path = tmp_path / "tools.json"
    path.write_text(" " * (MAX_MCP_INPUT_BYTES + 1), encoding="utf-8")
    result = audit_mcp_tools(str(path))
    assert "byte limit" in result["parse_error"]
    assert result["findings"] == []


def test_composite_local_skill_limit_fails_visibly(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text("x" * (MAX_LOCAL_ARTIFACT_BYTES + 1), encoding="utf-8")
    outcome = semantic_adapter("semantic", path).run()
    assert outcome.status == "failed_invalid_input"
    assert "byte limit" in outcome.reason
