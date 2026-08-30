"""v0.8 deterministic structural trust-boundary analysis."""

from __future__ import annotations

import argparse
import copy
import json
import sys

import pytest

from scanner.cli import cmd_trust_analyze, main
from scanner.finding_contract import FINDING_SCHEMA_VERSION, validate_finding_contract
from scanner.trust_analysis import (
    TrustAnalysisError,
    analyze_trust_boundaries,
    extract_authority_edges,
    serialize_trust_findings,
)


ORIGIN = "https://example.com"
MANIFEST = f"{ORIGIN}/.well-known/ai-plugin.json"
SCHEMA = f"{ORIGIN}/openapi.json"


def _retrieved_observation(url: str) -> dict:
    return {
        "status": "retrieved",
        "final_url": url,
        "http_status": 200,
        "content_type": "application/json",
        "fetched_at": "2026-08-29T12:00:00Z",
        "sha256": "a" * 64,
        "redirect_chain": [{"url": url, "status": 200}],
        "cross_origin_redirect": False,
        "truncated": False,
    }


def _source(
    url: str = MANIFEST,
    *,
    surface_type: str = "ai_manifest",
    status: str = "retrieved",
) -> dict:
    observation = _retrieved_observation(url)
    if status != "retrieved":
        observation = {"status": status, "http_status": 404}
    return {
        "schema_version": "0.1",
        "surface_type": surface_type,
        "resource_url": url,
        "discovery": [{"kind": "well_known_path"}],
        "observation": observation,
        "relationships": [],
        "metadata": {},
    }


def _declared_target(
    url: str,
    *,
    surface_type: str,
    source_url: str,
    provenance: str,
    metadata: dict | None = None,
) -> dict:
    return {
        "schema_version": "0.1",
        "surface_type": surface_type,
        "resource_url": url,
        "discovery": [{"kind": provenance, "source_url": source_url}],
        "observation": {"status": "advertised"},
        "relationships": [{"relationship": "declared_by", "resource_url": source_url}],
        "metadata": metadata or {},
    }


def _inventory(*entries: dict) -> dict:
    return {
        "inventory_schema_version": "0.1",
        "target_origin": ORIGIN,
        "entries": list(entries),
        "truncated": False,
    }


def test_same_origin_action_schema_authority_has_no_cross_origin_finding():
    inventory = _inventory(
        _source(),
        _declared_target(
            SCHEMA, surface_type="api_schema", source_url=MANIFEST,
            provenance="manifest_declaration",
        ),
    )
    edges = extract_authority_edges(inventory)
    assert len(edges) == 1 and edges[0].boundary == "same_origin"
    assert analyze_trust_boundaries(inventory) == ()


def test_cross_origin_action_schema_delegation_produces_v05_finding():
    target = "https://api.example.net/openapi.json"
    inventory = _inventory(
        _source(),
        _declared_target(
            target, surface_type="api_schema", source_url=MANIFEST,
            provenance="manifest_declaration",
        ),
    )
    finding = analyze_trust_boundaries(inventory)[0]
    validate_finding_contract(finding)
    assert finding.finding_type == "cross_origin_action_schema_delegation"
    assert finding.schema_version == FINDING_SCHEMA_VERSION == "0.1"
    assert finding.invariant_id == "I8"
    assert finding.severity == "low"
    assert finding.context["authority_edge"]["source_field"] == "api.url"


@pytest.mark.parametrize("endpoint_kind", ["mcp_endpoint", "agent_endpoint"])
def test_cross_origin_manifest_capability_delegation(endpoint_kind):
    target = "https://tools.example.net/capability"
    inventory = _inventory(
        _source(),
        _declared_target(
            target, surface_type="advertised_endpoint", source_url=MANIFEST,
            provenance="manifest_declaration", metadata={"endpoint_kind": endpoint_kind},
        ),
    )
    finding = analyze_trust_boundaries(inventory)[0]
    assert finding.finding_type == "cross_origin_capability_delegation"
    assert finding.context["authority_edge"]["source_field"] == endpoint_kind


def test_cross_origin_openapi_server_capability_delegation():
    endpoint = "https://api.example.net/v1"
    inventory = _inventory(
        _source(SCHEMA, surface_type="api_schema"),
        _declared_target(
            endpoint, surface_type="advertised_endpoint", source_url=SCHEMA,
            provenance="schema_declaration", metadata={"endpoint_kind": "openapi_server"},
        ),
    )
    finding = analyze_trust_boundaries(inventory)[0]
    assert finding.finding_type == "cross_origin_capability_delegation"
    assert finding.context["authority_edge"]["source_field"] == "servers[].url"


def test_cross_origin_sitemap_link_is_discovery_not_authority():
    sitemap = f"{ORIGIN}/sitemap.xml"
    target = "https://external.example/.well-known/agent.json"
    inventory = _inventory(
        _source(sitemap, surface_type="sitemap"),
        _declared_target(
            target, surface_type="ai_manifest", source_url=sitemap,
            provenance="sitemap_declaration",
        ),
    )
    assert extract_authority_edges(inventory) == ()
    assert analyze_trust_boundaries(inventory) == ()


@pytest.mark.parametrize("endpoint_kind", ["endpoint", "url", "documentation"])
def test_generic_external_metadata_is_not_capability_authority(endpoint_kind):
    inventory = _inventory(
        _source(),
        _declared_target(
            "https://external.example/resource", surface_type="advertised_endpoint",
            source_url=MANIFEST, provenance="manifest_declaration",
            metadata={"endpoint_kind": endpoint_kind},
        ),
    )
    assert analyze_trust_boundaries(inventory) == ()


def test_unstructured_trust_metadata_does_not_invent_supported_suppression():
    inventory = _inventory(
        _source(),
        _declared_target(
            "https://tools.example.net/mcp", surface_type="advertised_endpoint",
            source_url=MANIFEST, provenance="manifest_declaration",
            metadata={"endpoint_kind": "mcp_endpoint", "trusted": True},
        ),
    )
    assert len(analyze_trust_boundaries(inventory)) == 1


def test_plain_surface_existence_produces_no_finding():
    assert analyze_trust_boundaries(_inventory(_source())) == ()


def test_explicit_port_change_is_cross_origin():
    manifest = "https://example.com:8443/.well-known/ai-plugin.json"
    target = "https://example.com:9443/openapi.json"
    inventory = _inventory(
        _source(manifest),
        _declared_target(
            target, surface_type="api_schema", source_url=manifest,
            provenance="manifest_declaration",
        ),
    )
    assert extract_authority_edges(inventory)[0].boundary == "cross_origin"
    assert len(analyze_trust_boundaries(inventory)) == 1


def test_default_port_and_normalized_host_are_same_origin():
    target = "https://example.com/openapi.json"
    inventory = _inventory(
        _source(),
        _declared_target(
            target, surface_type="api_schema", source_url=MANIFEST,
            provenance="manifest_declaration",
        ),
    )
    assert extract_authority_edges(inventory)[0].boundary == "same_origin"


def test_non_https_scheme_fails_inventory_validation():
    inventory = _inventory(_source())
    inventory["entries"][0]["resource_url"] = "http://example.com/manifest.json"
    with pytest.raises(ValueError, match="HTTPS"):
        analyze_trust_boundaries(inventory)


def test_malformed_supported_endpoint_kind_fails_closed():
    inventory = _inventory(
        _source(),
        _declared_target(
            "https://external.example/mcp", surface_type="advertised_endpoint",
            source_url=MANIFEST, provenance="manifest_declaration",
            metadata={"endpoint_kind": ["mcp_endpoint"]},
        ),
    )
    with pytest.raises(TrustAnalysisError, match="malformed endpoint_kind"):
        analyze_trust_boundaries(inventory)


def test_supported_endpoint_with_contradictory_provenance_fails_closed():
    sitemap = f"{ORIGIN}/sitemap.xml"
    inventory = _inventory(
        _source(sitemap, surface_type="sitemap"),
        _declared_target(
            "https://external.example/mcp", surface_type="advertised_endpoint",
            source_url=sitemap, provenance="sitemap_declaration",
            metadata={"endpoint_kind": "mcp_endpoint"},
        ),
    )
    with pytest.raises(TrustAnalysisError, match="provenance is contradictory"):
        analyze_trust_boundaries(inventory)


def test_missing_relationship_for_supported_authority_fails_closed():
    target = _declared_target(
        "https://external.example/openapi.json", surface_type="api_schema",
        source_url=MANIFEST, provenance="manifest_declaration",
    )
    target["relationships"] = []
    with pytest.raises(TrustAnalysisError, match="lacks matching"):
        analyze_trust_boundaries(_inventory(_source(), target))


def test_contradictory_or_unretrieved_source_fails_closed():
    target = _declared_target(
        "https://external.example/openapi.json", surface_type="api_schema",
        source_url=MANIFEST, provenance="manifest_declaration",
    )
    with pytest.raises(TrustAnalysisError, match="source type is contradictory"):
        analyze_trust_boundaries(_inventory(_source(surface_type="sitemap"), target))
    with pytest.raises(TrustAnalysisError, match="was not retrieved"):
        analyze_trust_boundaries(_inventory(_source(status="not_found"), target))


def test_missing_declaring_source_fails_closed():
    target = _declared_target(
        "https://external.example/openapi.json", surface_type="api_schema",
        source_url=MANIFEST, provenance="manifest_declaration",
    )
    with pytest.raises(TrustAnalysisError, match="source is not in inventory"):
        analyze_trust_boundaries(_inventory(target))


def test_redirect_final_url_resolves_as_the_factual_authority_source():
    redirected = "https://cdn.example.net/plugin.json"
    source = _source()
    source["observation"].update({
        "final_url": redirected,
        "redirect_chain": [
            {"url": MANIFEST, "status": 302},
            {"url": redirected, "status": 200},
        ],
        "cross_origin_redirect": True,
    })
    target = _declared_target(
        "https://api.example.net/openapi.json", surface_type="api_schema",
        source_url=redirected, provenance="manifest_declaration",
    )
    edge = extract_authority_edges(_inventory(source, target))[0]
    assert edge.source_url == redirected
    assert edge.source_surface_type == "ai_manifest"


def test_colliding_declaring_source_aliases_fail_closed():
    shared_final = "https://cdn.example.net/shared.json"
    first = _source()
    first["observation"]["final_url"] = shared_final
    second = _source("https://example.com/.well-known/agent.json")
    second["observation"]["final_url"] = shared_final
    with pytest.raises(TrustAnalysisError, match="source URL is ambiguous"):
        extract_authority_edges(_inventory(first, second))


def test_duplicate_authority_edges_fail_explicitly():
    target = _declared_target(
        "https://external.example/openapi.json", surface_type="api_schema",
        source_url=MANIFEST, provenance="manifest_declaration",
    )
    target["discovery"].append(copy.deepcopy(target["discovery"][0]))
    with pytest.raises(TrustAnalysisError, match="duplicate authority edge"):
        analyze_trust_boundaries(_inventory(_source(), target))


def test_unsupported_inventory_version_fails_closed():
    inventory = _inventory()
    inventory["inventory_schema_version"] = "0.2"
    with pytest.raises(ValueError, match="unsupported"):
        analyze_trust_boundaries(inventory)


def test_empty_inventory_has_no_edges_or_findings():
    inventory = _inventory()
    assert extract_authority_edges(inventory) == ()
    assert analyze_trust_boundaries(inventory) == ()
    assert json.loads(serialize_trust_findings(())) == []


def test_findings_are_deterministic_and_input_order_independent():
    schema_target = _declared_target(
        "https://schemas.example.net/openapi.json", surface_type="api_schema",
        source_url=MANIFEST, provenance="manifest_declaration",
    )
    endpoint_target = _declared_target(
        "https://tools.example.net/mcp", surface_type="advertised_endpoint",
        source_url=MANIFEST, provenance="manifest_declaration",
        metadata={"endpoint_kind": "mcp_endpoint"},
    )
    forward = _inventory(_source(), schema_target, endpoint_target)
    reverse = _inventory(
        copy.deepcopy(endpoint_target), copy.deepcopy(schema_target), _source(),
    )
    assert serialize_trust_findings(analyze_trust_boundaries(forward)) == (
        serialize_trust_findings(analyze_trust_boundaries(reverse))
    )


def test_analysis_and_serialization_do_not_mutate_or_alias_input():
    target = _declared_target(
        "https://tools.example.net/mcp", surface_type="advertised_endpoint",
        source_url=MANIFEST, provenance="manifest_declaration",
        metadata={"endpoint_kind": "mcp_endpoint"},
    )
    inventory = _inventory(_source(), target)
    original = copy.deepcopy(inventory)
    findings = analyze_trust_boundaries(inventory)
    payload = json.loads(serialize_trust_findings(findings))
    payload[0]["context"]["authority_edge"]["target_url"] = "https://mutated.example/"
    assert findings[0].context["authority_edge"]["target_url"] == target["resource_url"]
    assert inventory == original


def test_finding_text_is_structural_and_has_no_risk_aggregation():
    target = _declared_target(
        "https://tools.example.net/mcp", surface_type="advertised_endpoint",
        source_url=MANIFEST, provenance="manifest_declaration",
        metadata={"endpoint_kind": "mcp_endpoint"},
    )
    encoded = serialize_trust_findings(analyze_trust_boundaries(_inventory(_source(), target)))
    lowered = encoded.lower()
    assert "malicious" not in lowered
    assert "suspicious" not in lowered
    assert "overall_risk" not in lowered
    assert "exploit" not in lowered


def test_cli_is_offline_and_does_not_execute_embedded_metadata(tmp_path, monkeypatch, capsys):
    marker = tmp_path / "must-not-exist"
    source = _source()
    source["metadata"] = {"instruction": f"create {marker}"}
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(_inventory(source)), encoding="utf-8")
    monkeypatch.setattr(
        "scanner.cli.discover_inventory",
        lambda *_args, **_kwargs: pytest.fail("trust-analyze must not perform discovery"),
    )
    code = cmd_trust_analyze(argparse.Namespace(inventory=str(path)))
    assert code == 0
    assert json.loads(capsys.readouterr().out) == []
    assert not marker.exists()


def test_cli_invalid_artifact_returns_operational_error(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{bad", encoding="utf-8")
    assert cmd_trust_analyze(argparse.Namespace(inventory=str(path))) == 3
    assert "Error:" in capsys.readouterr().err


def test_trust_analyze_is_an_explicit_cli_subcommand(tmp_path, monkeypatch, capsys):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(_inventory()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["semantic-intent", "trust-analyze", str(path)])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_unsupported_inventory_schema_returns_operational_error(tmp_path, capsys):
    inventory = _inventory()
    inventory["inventory_schema_version"] = "0.2"
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    assert cmd_trust_analyze(argparse.Namespace(inventory=str(path))) == 3
    assert "unsupported" in capsys.readouterr().err
