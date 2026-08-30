import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from scanner.composite_audit import validate_composite_audit
from scanner.finding_contract import validate_finding_contract
from scanner.inventory_diff import validate_change_set
from scanner.surface_inventory import validate_inventory


SCHEMAS = Path(__file__).parents[1] / "schemas"
FIXTURES = Path(__file__).parent / "fixtures" / "contracts"


def _load(name):
    return json.loads((SCHEMAS / name).read_text("utf-8"))


FINDING = {
    "schema_version": "0.1", "finding_type": "example", "severity": "low",
    "observation": {"summary": "Observed state", "evidence": []},
    "rationale": "Existing rationale", "remediation": {"summary": "Correct it", "references": []},
    "retest": {"condition": "observable state no longer exists"},
}
INVENTORY = {"inventory_schema_version": "0.1", "target_origin": "https://example.com", "entries": [], "truncated": False}
CHANGE = {"change_schema_version": "0.1", "target_origin": "https://example.com", "previous_inventory_schema_version": "0.1", "current_inventory_schema_version": "0.1", "changes": []}
COMPOSITE = {"schema_version": "0.1", "requested_analyzers": ["directory"], "executions": [{"analyzer_id": "directory", "status": "success", "finding_count": 0, "semantic_coverage": "not_requested"}], "findings": []}


CASES = [
    ("finding-0.1.schema.json", FINDING, validate_finding_contract),
    ("inventory-0.1.schema.json", INVENTORY, validate_inventory),
    ("change-0.1.schema.json", CHANGE, validate_change_set),
    ("composite-0.1.schema.json", COMPOSITE, validate_composite_audit),
]


def _validator(name):
    schema = _load(name)
    registry = Registry().with_resources(
        (_load(p.name)["$id"], Resource.from_contents(_load(p.name)))
        for p in SCHEMAS.glob("*.json")
    )
    return Draft202012Validator(schema, registry=registry)


@pytest.mark.parametrize("schema_name,artifact,runtime", CASES)
def test_minimal_runtime_and_json_schema_parity(schema_name, artifact, runtime):
    runtime(artifact)
    _validator(schema_name).validate(artifact)


@pytest.mark.parametrize("schema_name,artifact,runtime", CASES)
def test_unexpected_fields_fail_both(schema_name, artifact, runtime):
    malformed = copy.deepcopy(artifact)
    malformed["unexpected"] = True
    with pytest.raises(ValueError):
        runtime(malformed)
    with pytest.raises(ValidationError):
        _validator(schema_name).validate(malformed)


@pytest.mark.parametrize("schema_name,artifact,runtime,version_field", [
    (*CASES[0], "schema_version"), (*CASES[1], "inventory_schema_version"),
    (*CASES[2], "change_schema_version"), (*CASES[3], "schema_version"),
])
def test_unsupported_versions_fail_both(schema_name, artifact, runtime, version_field):
    malformed = copy.deepcopy(artifact)
    malformed[version_field] = "999"
    with pytest.raises(ValueError):
        runtime(malformed)
    with pytest.raises(ValidationError):
        _validator(schema_name).validate(malformed)


def test_runtime_preserves_stronger_nonfinite_rejection():
    malformed = copy.deepcopy(FINDING)
    malformed["context"] = {"score": float("nan")}
    with pytest.raises(ValueError):
        validate_finding_contract(malformed)
    # JSON Schema's mathematical number model has no portable NaN/Infinity
    # representation. The Python validator and JSON serializer intentionally
    # remain stricter than the checked-in schema here.
    _validator("finding-0.1.schema.json").validate(malformed)


@pytest.mark.parametrize("stem,runtime", [
    ("finding", validate_finding_contract), ("inventory", validate_inventory),
    ("change", validate_change_set), ("composite", validate_composite_audit),
])
def test_checked_in_golden_fixtures(stem, runtime):
    valid = json.loads((FIXTURES / f"{stem}-valid.json").read_text("utf-8"))
    invalid = json.loads((FIXTURES / f"{stem}-invalid.json").read_text("utf-8"))
    schema_name = f"{stem}-0.1.schema.json"
    runtime(valid)
    _validator(schema_name).validate(valid)
    with pytest.raises(ValueError):
        runtime(invalid)
    with pytest.raises(ValidationError):
        _validator(schema_name).validate(invalid)


FULL_FINDING = {
    **FINDING, "invariant_id": "I8", "resource": "https://example.com/llms.txt",
    "observation": {"summary": "Observed state", "evidence": [{
        "kind": "text", "value": 1.25, "source": "https://example.com/llms.txt",
        "observed_at": "2026-08-29T00:00:00Z", "metadata": {"nested": [True, None]},
    }]},
    "remediation": {"summary": "Correct it", "references": ["https://example.com/help"]},
    "context": {"authority_edge": {"source_field": "servers[0].url"}},
}
FULL_INVENTORY = {
    "inventory_schema_version": "0.1", "target_origin": "https://example.com",
    "truncated": False, "entries": [{
        "schema_version": "0.1", "surface_type": "api_schema",
        "resource_url": "https://example.com/openapi.json",
        "discovery": [{"kind": "manifest_declaration", "source_url": "https://example.com/manifest.json"}],
        "observation": {"status": "retrieved", "final_url": "https://example.com/openapi.json",
            "http_status": 200, "content_type": "application/json", "fetched_at": "2026-08-29T00:00:00Z",
            "sha256": "abc", "redirect_chain": [{"url": "https://example.com/openapi.json", "status": 200}],
            "cross_origin_redirect": False, "truncated": False},
        "relationships": [{"relationship": "declared_by", "resource_url": "https://example.com/manifest.json"}],
        "metadata": {"declared_schema_version": "3.1.0"},
    }],
}
FULL_CHANGE = {
    "change_schema_version": "0.1", "target_origin": "https://example.com",
    "previous_inventory_schema_version": "0.1", "current_inventory_schema_version": "0.1",
    "changes": [{"schema_version": "0.1", "change_type": "content_type_changed",
        "surface_identity": {"surface_type": "api_schema", "resource_url": "https://example.com/openapi.json"},
        "affected_paths": ["observation.content_type"], "previous": "application/json", "current": "text/plain"}],
}
FULL_COMPOSITE = {
    "schema_version": "0.1", "requested_analyzers": ["remote", "trust"],
    "executions": [
        {"analyzer_id": "remote", "status": "failed_operational", "finding_count": 0, "semantic_coverage": "partial", "reason": "guarded retrieval failed"},
        {"analyzer_id": "trust", "status": "success", "finding_count": 1, "semantic_coverage": "not_requested"},
    ],
    "findings": [{"analyzer_id": "trust", "finding": FULL_FINDING}],
}


@pytest.mark.parametrize("schema_name,artifact,runtime", [
    ("finding-0.1.schema.json", FULL_FINDING, validate_finding_contract),
    ("inventory-0.1.schema.json", FULL_INVENTORY, validate_inventory),
    ("change-0.1.schema.json", FULL_CHANGE, validate_change_set),
    ("composite-0.1.schema.json", FULL_COMPOSITE, validate_composite_audit),
])
def test_full_runtime_and_json_schema_parity(schema_name, artifact, runtime):
    runtime(artifact)
    _validator(schema_name).validate(artifact)


def test_schema_conditional_rules_match_runtime():
    advertised = copy.deepcopy(FULL_INVENTORY)
    advertised["entries"][0]["observation"] = {"status": "advertised", "http_status": 200}
    failed_success = copy.deepcopy(FULL_COMPOSITE)
    failed_success["executions"][0] = {"analyzer_id": "remote", "status": "success", "finding_count": 0, "semantic_coverage": "partial", "reason": "should not exist"}
    for schema_name, artifact, runtime in [
        ("inventory-0.1.schema.json", advertised, validate_inventory),
        ("composite-0.1.schema.json", failed_success, validate_composite_audit),
    ]:
        with pytest.raises(ValueError):
            runtime(artifact)
        with pytest.raises(ValidationError):
            _validator(schema_name).validate(artifact)
