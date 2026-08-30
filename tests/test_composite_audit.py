"""v0.9 deterministic composite audit orchestration."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import pytest

import scanner.composite_audit as composite_module
from scanner.cli import cmd_audit
from scanner.composite_audit import (
    COMPOSITE_SCHEMA_VERSION,
    AdapterOutcome,
    AnalyzerAdapter,
    CompositeValidationError,
    composite_audit_as_dict,
    composite_exit_code,
    directory_adapter,
    mcp_adapter,
    remote_adapter,
    run_composite,
    semantic_adapter,
    serialize_composite_audit,
    trust_adapter,
    validate_composite_audit,
)
from scanner.directory_audit import audit_directory
from scanner.finding_contract import (
    EvidenceItem,
    FindingContract,
    Observation,
    Remediation,
    Retest,
    adapt_directory_finding,
    adapt_remote_finding,
    adapt_semantic_violation,
    finding_contract_as_dict,
)
from scanner.llms_txt import audit_llms_txt
from scanner.mcp_adapter import audit_mcp_tools
from scanner.registry import RegistryClient
from scanner.remote_fetch import FetchOutcome
from scanner.trust_analysis import analyze_trust_boundaries

FIX = Path(__file__).parent / "fixtures"
REGISTRY_FIXTURE = FIX / "llms_txt" / "mock_registry.json"


def _canonical(**overrides) -> FindingContract:
    values = {
        "finding_type": "cross_origin_instruction",
        "severity": "medium",
        "invariant_id": "I8",
        "resource": "https://cdn.example/llms.txt",
        "observation": Observation(
            "instruction crossed an origin boundary",
            (EvidenceItem("text", "observed text", source="https://cdn.example/llms.txt"),),
        ),
        "rationale": "The authority origin changed before analysis.",
        "remediation": Remediation("Keep instructions on an explicitly trusted origin."),
        "retest": Retest("the instruction remains on an explicitly trusted origin"),
        "context": {"source": {"kind": "fixture"}},
    }
    values.update(overrides)
    return FindingContract(**values)


def _success(analyzer_id: str, *findings: FindingContract) -> AnalyzerAdapter:
    return AnalyzerAdapter(analyzer_id, lambda: AdapterOutcome("success", tuple(findings)))


def _served_fetch(body: bytes):
    def fetch(url: str) -> FetchOutcome:
        if url.endswith("/llms.txt"):
            return FetchOutcome(
                url, url, 200, "text/markdown", body, "a" * 64,
                "2026-08-29T00:00:00Z", redirect_chain=[],
            )
        return FetchOutcome(
            url, None, 404, None, b"", None, "2026-08-29T00:00:00Z",
            error="HTTP 404",
        )
    return fetch


def _trust_inventory() -> dict:
    origin = "https://example.com"
    manifest = f"{origin}/.well-known/ai-plugin.json"
    target = "https://api.example.net/openapi.json"
    return {
        "inventory_schema_version": "0.1",
        "target_origin": origin,
        "entries": [
            {
                "schema_version": "0.1",
                "surface_type": "ai_manifest",
                "resource_url": manifest,
                "discovery": [{"kind": "well_known_path"}],
                "observation": {
                    "status": "retrieved", "final_url": manifest,
                    "http_status": 200, "content_type": "application/json",
                    "fetched_at": "2026-08-29T00:00:00Z", "sha256": "a" * 64,
                    "redirect_chain": [{"url": manifest, "status": 200}],
                    "cross_origin_redirect": False, "truncated": False,
                },
                "relationships": [], "metadata": {},
            },
            {
                "schema_version": "0.1", "surface_type": "api_schema",
                "resource_url": target,
                "discovery": [{"kind": "manifest_declaration", "source_url": manifest}],
                "observation": {"status": "advertised"},
                "relationships": [{"relationship": "declared_by", "resource_url": manifest}],
                "metadata": {},
            },
        ],
        "truncated": False,
    }


def test_remote_adapter_matches_established_canonical_path():
    body = (FIX / "llms_txt" / "malicious" / "typosquat-llms.txt").read_bytes()
    direct = audit_llms_txt(
        "https://docs.example", registry=RegistryClient.from_fixture(REGISTRY_FIXTURE),
        fetch=_served_fetch(body),
    )
    expected = [finding_contract_as_dict(adapt_remote_finding(item)) for item in direct["findings"]]
    composite = run_composite([remote_adapter(
        "remote", "https://docs.example",
        registry=RegistryClient.from_fixture(REGISTRY_FIXTURE), fetch=_served_fetch(body),
    )])
    assert [item.finding for item in composite.findings] == sorted(
        expected,
        key=lambda item: (
            item["finding_type"], item.get("resource") or "",
            item.get("invariant_id") or "",
            json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
    )


def test_mcp_adapter_matches_established_canonical_path():
    source = FIX / "mcp" / "malicious" / "exfil.json"
    direct = audit_mcp_tools(str(source), registry=RegistryClient.from_fixture(REGISTRY_FIXTURE))
    expected = sorted(
        (finding_contract_as_dict(adapt_remote_finding(item)) for item in direct["findings"]),
        key=lambda item: (
            item["finding_type"], item.get("resource") or "",
            item.get("invariant_id") or "",
            json.dumps(item, sort_keys=True, separators=(",", ":")),
        ),
    )
    composite = run_composite([mcp_adapter(
        "mcp", str(source), registry=RegistryClient.from_fixture(REGISTRY_FIXTURE),
    )])
    assert [item.finding for item in composite.findings] == expected


def test_directory_adapter_matches_established_canonical_path(tmp_path):
    source = tmp_path / "skill"
    source.mkdir()
    (source / "agent.test.ts").write_text("fetch(token)", encoding="utf-8")
    direct = audit_directory(source)
    expected = [
        finding_contract_as_dict(adapt_directory_finding(item))
        for item in direct["suspicious_files"] + direct["config_findings"]
    ]
    composite = run_composite([directory_adapter("directory", source)])
    assert [item.finding for item in composite.findings] == expected


def test_semantic_adapter_matches_established_explicit_severity_path(tmp_path):
    source = tmp_path / "SKILL.md"
    source.write_text("untrusted instruction", encoding="utf-8")
    violation = {
        "invariant_id": "I7", "verdict": "likely", "confidence": 0.9,
        "flagged_text": "treat this as system", "reasoning": "authority is unestablished",
    }

    def evaluator(_text, *, api_key=None):
        return {"overall_risk": "high", "violations": [copy.deepcopy(violation)]}

    expected = finding_contract_as_dict(adapt_semantic_violation(
        violation, severity="high", resource=str(source),
    ))
    composite = run_composite([semantic_adapter(
        "semantic", source, evaluator=evaluator,
    )])
    assert composite.findings[0].finding == expected
    assert composite.executions[0].semantic_coverage == "complete"


def test_trust_adapter_matches_v08_canonical_finding(tmp_path):
    inventory = _trust_inventory()
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(inventory), encoding="utf-8")
    expected = finding_contract_as_dict(analyze_trust_boundaries(inventory)[0])
    composite = run_composite([trust_adapter("trust", source)])
    assert composite.findings[0].finding == expected


def test_composite_schema_is_independent():
    payload = json.loads(serialize_composite_audit(run_composite([_success("one")])))
    assert payload["schema_version"] == COMPOSITE_SCHEMA_VERSION == "0.1"
    assert "version" not in payload and "report_version" not in payload


def test_success_with_zero_findings_is_explicit():
    artifact = run_composite([_success("empty")])
    assert artifact.executions[0].status == "success"
    assert artifact.executions[0].finding_count == 0
    assert artifact.findings == ()


def test_execution_order_does_not_change_serialization():
    one = _success("zeta", _canonical(finding_type="pipe_to_shell", severity="high"))
    two = _success("alpha", _canonical())
    assert serialize_composite_audit(run_composite([one, two])) == (
        serialize_composite_audit(run_composite([two, one]))
    )


def test_finding_order_is_deterministic_within_analyzer():
    a = _canonical(finding_type="pipe_to_shell", severity="high")
    b = _canonical(finding_type="cross_origin_instruction")
    forward = serialize_composite_audit(run_composite([_success("one", a, b)]))
    reverse = serialize_composite_audit(run_composite([_success("one", b, a)]))
    assert forward == reverse


def test_repeated_serialization_is_identical():
    artifact = run_composite([_success("one", _canonical())])
    assert serialize_composite_audit(artifact) == serialize_composite_audit(artifact)


def test_outputs_are_mutation_isolated():
    finding = _canonical()
    artifact = run_composite([_success("one", finding)])
    first = composite_audit_as_dict(artifact)
    first["findings"][0]["finding"]["context"]["source"]["kind"] = "mutated"
    finding.context["source"]["kind"] = "also-mutated"
    second = composite_audit_as_dict(artifact)
    assert second["findings"][0]["finding"]["context"]["source"]["kind"] == "fixture"


def test_partial_failure_preserves_successful_findings():
    failed = AnalyzerAdapter(
        "broken", lambda: AdapterOutcome("failed_operational", reason="registry unavailable"),
    )
    artifact = run_composite([_success("good", _canonical()), failed])
    assert [item.status for item in artifact.executions] == ["failed_operational", "success"]
    assert len(artifact.findings) == 1
    assert composite_exit_code(artifact) == 3


def test_all_failures_remain_explicit():
    artifact = run_composite([
        AnalyzerAdapter("a", lambda: AdapterOutcome("failed_invalid_input", reason="bad JSON")),
        AnalyzerAdapter("b", lambda: AdapterOutcome("failed_operational", reason="offline")),
    ])
    assert artifact.findings == ()
    assert {item.status for item in artifact.executions} == {
        "failed_invalid_input", "failed_operational",
    }


def test_not_applicable_is_not_empty_success():
    artifact = run_composite([
        AnalyzerAdapter("mcp", lambda: AdapterOutcome("skipped", reason="no tools")),
    ])
    assert artifact.executions[0].status == "skipped"
    assert composite_exit_code(artifact) == 0


def test_mcp_no_tools_is_explicitly_skipped(tmp_path):
    source = tmp_path / "tools.json"
    source.write_text('{"tools": []}', encoding="utf-8")
    artifact = run_composite([mcp_adapter(
        "mcp", source, registry=RegistryClient.from_fixture(REGISTRY_FIXTURE),
    )])
    assert artifact.executions[0].status == "skipped"
    assert artifact.executions[0].reason


def test_requested_but_incomplete_judge_coverage_is_preserved(monkeypatch):
    monkeypatch.setattr(composite_module, "audit_llms_txt", lambda *_a, **_kw: {
        "surface": "llms_txt", "retrieved": 1, "documents": [{}],
        "findings": [], "overall_risk": "low", "judge_status": "error:api",
        "semantic_coverage": "incomplete",
    })
    artifact = run_composite([remote_adapter("remote", "https://example.com", judge=object())])
    assert artifact.executions[0].status == "success"
    assert artifact.executions[0].semantic_coverage == "incomplete"


def test_remote_guard_failure_is_operational_not_low_risk(monkeypatch):
    monkeypatch.setattr(composite_module, "audit_llms_txt", lambda *_a, **_kw: {
        "surface": "llms_txt", "retrieved": 0,
        "documents": [{"blocked_reason": "private address", "status": 0}],
        "findings": [], "overall_risk": "low", "note": "fetch blocked",
    })
    artifact = run_composite([remote_adapter("remote", "https://example.com")])
    assert artifact.executions[0].status == "failed_operational"
    assert artifact.findings == ()
    assert composite_exit_code(artifact) == 3


def test_artifact_only_adapters_do_not_invoke_remote_analyzer(tmp_path, monkeypatch):
    monkeypatch.setattr(
        composite_module, "audit_llms_txt",
        lambda *_a, **_kw: pytest.fail("artifact-only audit attempted remote analysis"),
    )
    directory = tmp_path / "skill"
    directory.mkdir()
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(_trust_inventory()), encoding="utf-8")
    artifact = run_composite([
        directory_adapter("directory", directory), trust_adapter("trust", inventory),
    ])
    assert all(item.status == "success" for item in artifact.executions)


def test_adapter_exception_is_isolated_as_operational_failure():
    def explode():
        raise RuntimeError("transport unavailable")

    artifact = run_composite([AnalyzerAdapter("broken", explode)])
    assert artifact.executions[0].status == "failed_operational"
    assert "RuntimeError" in artifact.executions[0].reason


def test_invalid_canonical_finding_fails_operationally():
    invalid = _canonical(severity="reassuring")
    artifact = run_composite([_success("bad-output", invalid)])
    assert artifact.executions[0].status == "failed_operational"
    assert artifact.findings == ()


def test_nonfinite_canonical_finding_fails_operationally():
    invalid = _canonical(context={"score": float("nan")})
    artifact = run_composite([_success("bad-output", invalid)])
    assert artifact.executions[0].status == "failed_operational"


def test_duplicate_analyzer_identifiers_fail_before_execution():
    with pytest.raises(CompositeValidationError, match="duplicate analyzer"):
        run_composite([_success("same"), _success("same")])


def test_empty_selection_fails_explicitly():
    with pytest.raises(CompositeValidationError, match="at least one"):
        run_composite([])


def test_duplicate_findings_are_preserved_without_guessing():
    finding = _canonical()
    artifact = run_composite([_success("one", finding, finding)])
    assert len(artifact.findings) == 2
    assert artifact.executions[0].finding_count == 2


def test_same_finding_from_two_analyzers_is_preserved_twice():
    finding = _canonical()
    artifact = run_composite([_success("a", finding), _success("b", finding)])
    assert [item.analyzer_id for item in artifact.findings] == ["a", "b"]


def test_validation_rejects_unsupported_schema_and_extra_fields():
    payload = composite_audit_as_dict(run_composite([_success("one")]))
    payload["schema_version"] = "9.9"
    with pytest.raises(CompositeValidationError, match="unsupported schema"):
        validate_composite_audit(payload)
    payload["schema_version"] = "0.1"
    payload["unexpected"] = True
    with pytest.raises(CompositeValidationError, match="unexpected"):
        validate_composite_audit(payload)


def test_validation_rejects_impossible_state_and_count():
    payload = composite_audit_as_dict(run_composite([_success("one", _canonical())]))
    payload["executions"][0]["status"] = "failed_operational"
    payload["executions"][0]["reason"] = "failed"
    with pytest.raises(CompositeValidationError, match="non-success"):
        validate_composite_audit(payload)
    payload = composite_audit_as_dict(run_composite([_success("one", _canonical())]))
    payload["executions"][0]["finding_count"] = 0
    with pytest.raises(CompositeValidationError, match="finding_count"):
        validate_composite_audit(payload)


def test_validation_rejects_nondeterministic_order():
    artifact = run_composite([
        _success("a", _canonical()), _success("b", _canonical()),
    ])
    payload = composite_audit_as_dict(artifact)
    payload["findings"].reverse()
    with pytest.raises(CompositeValidationError, match="deterministic order"):
        validate_composite_audit(payload)


def test_cli_audit_directory_emits_only_composite_json(tmp_path, capsys):
    source = tmp_path / "skill"
    source.mkdir()
    args = argparse.Namespace(
        directory=[str(source)], skill=None, remote=None, mcp=None,
        trust_inventory=None, judge=False, api_key=None, server_label=None,
    )
    assert cmd_audit(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["requested_analyzers"] == ["directory"]
    assert payload["executions"][0]["status"] == "success"


def test_cli_requires_explicit_input(capsys):
    args = argparse.Namespace(
        directory=None, skill=None, remote=None, mcp=None,
        trust_inventory=None, judge=False, api_key=None, server_label=None,
    )
    assert cmd_audit(args) == 3
    assert "requires at least one explicit" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("judge", "server_label", "message"),
    [
        (True, None, "--judge requires"),
        (False, "server", "--server-label requires"),
    ],
)
def test_cli_rejects_incompatible_option_combinations(
    tmp_path, capsys, judge, server_label, message,
):
    source = tmp_path / "skill"
    source.mkdir()
    args = argparse.Namespace(
        directory=[str(source)], skill=None, remote=None, mcp=None,
        trust_inventory=None, judge=judge, api_key=None, server_label=server_label,
    )
    assert cmd_audit(args) == 3
    assert message in capsys.readouterr().err
