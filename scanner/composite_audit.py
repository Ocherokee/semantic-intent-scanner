"""Deterministic v0.9 orchestration over existing finding-producing analyzers."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .directory_audit import audit_directory
from .evaluator import evaluate_skill
from .finding_contract import (
    FindingContract,
    adapt_directory_finding,
    adapt_remote_finding,
    adapt_semantic_violation,
    finding_contract_as_dict,
    validate_finding_contract,
)
from .llms_txt import audit_llms_txt
from .mcp_adapter import audit_mcp_tools
from .report import remote_operational_status
from .trust_analysis import analyze_trust_boundaries

COMPOSITE_SCHEMA_VERSION = "0.1"
SUPPORTED_COMPOSITE_SCHEMA_VERSIONS = frozenset({COMPOSITE_SCHEMA_VERSION})
ANALYZER_STATUSES = frozenset(
    {"success", "skipped", "failed_invalid_input", "failed_operational"}
)
SEMANTIC_COVERAGE = frozenset({"not_requested", "complete", "incomplete"})


class CompositeAuditError(ValueError):
    """Base error for v0.9 contract or orchestration failures."""


class CompositeValidationError(CompositeAuditError):
    """Raised when a composite artifact is malformed or inconsistent."""


@dataclass(frozen=True)
class AdapterOutcome:
    status: str
    findings: tuple[FindingContract, ...] = ()
    reason: str | None = None
    semantic_coverage: str = "not_requested"


@dataclass(frozen=True)
class AnalyzerAdapter:
    analyzer_id: str
    run: Callable[[], AdapterOutcome]


@dataclass(frozen=True)
class AnalyzerExecution:
    analyzer_id: str
    status: str
    finding_count: int
    semantic_coverage: str
    reason: str | None = None


@dataclass(frozen=True)
class SourcedFinding:
    analyzer_id: str
    finding: dict[str, Any]


@dataclass(frozen=True)
class CompositeAudit:
    requested_analyzers: tuple[str, ...]
    executions: tuple[AnalyzerExecution, ...]
    findings: tuple[SourcedFinding, ...]
    schema_version: str = COMPOSITE_SCHEMA_VERSION


def _failed(status: str, reason: str) -> AdapterOutcome:
    return AdapterOutcome(status=status, reason=reason)


def _coverage(result: Mapping[str, Any], judge_requested: bool) -> str:
    if not judge_requested:
        return "not_requested"
    return "complete" if result.get("semantic_coverage") == "complete" else "incomplete"


def _remote_outcome(result: Mapping[str, Any], *, judge_requested: bool) -> AdapterOutcome:
    status = remote_operational_status(dict(result))
    coverage = _coverage(result, judge_requested)
    if status == "ok":
        findings = tuple(adapt_remote_finding(item) for item in result.get("findings", []))
        return AdapterOutcome("success", findings, semantic_coverage=coverage)
    reason = str(result.get("note") or status)
    if status in {"not_found", "no_tools"}:
        return AdapterOutcome("skipped", reason=reason, semantic_coverage=coverage)
    if status == "invalid_input":
        return _failed("failed_invalid_input", reason)
    return AdapterOutcome("failed_operational", reason=reason, semantic_coverage=coverage)


def remote_adapter(
    analyzer_id: str, target: str, *, registry: Any = None,
    fetch: Any = None, judge: Any = None,
) -> AnalyzerAdapter:
    """Wrap the established remote llms.txt analyzer without widening fetch authority."""
    def run() -> AdapterOutcome:
        return _remote_outcome(
            audit_llms_txt(target, registry=registry, fetch=fetch, judge=judge),
            judge_requested=judge is not None,
        )
    return AnalyzerAdapter(analyzer_id, run)


def mcp_adapter(
    analyzer_id: str, source: str, *, registry: Any = None,
    judge: Any = None, server_label: str | None = None,
) -> AnalyzerAdapter:
    """Wrap captured MCP analysis; this never starts a transport or invokes a tool."""
    def run() -> AdapterOutcome:
        return _remote_outcome(
            audit_mcp_tools(
                source, registry=registry, judge=judge, server_label=server_label,
            ),
            judge_requested=judge is not None,
        )
    return AnalyzerAdapter(analyzer_id, run)


def directory_adapter(analyzer_id: str, source: str | Path) -> AnalyzerAdapter:
    """Wrap the legacy directory audit and its reviewed v0.5 adapter."""
    path = Path(source)

    def run() -> AdapterOutcome:
        result = audit_directory(path)
        if "error" in result:
            return _failed("failed_invalid_input", str(result["error"]))
        legacy = [
            *result.get("suspicious_files", []),
            *result.get("config_findings", []),
        ]
        return AdapterOutcome(
            "success", tuple(adapt_directory_finding(item) for item in legacy)
        )
    return AnalyzerAdapter(analyzer_id, run)


def semantic_adapter(
    analyzer_id: str, source: str | Path, *, api_key: str | None = None,
    evaluator: Callable[..., dict[str, Any]] = evaluate_skill,
) -> AnalyzerAdapter:
    """Wrap the existing semantic evaluator and explicit-severity v0.5 adapter."""
    path = Path(source)

    def run() -> AdapterOutcome:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return _failed("failed_invalid_input", f"cannot read input: {exc}")
        if not text.strip():
            return _failed("failed_invalid_input", f"file is empty: {path}")
        result = evaluator(text, api_key=api_key)
        severity = result.get("overall_risk")
        findings = tuple(
            adapt_semantic_violation(item, severity=severity, resource=str(path))
            for item in result.get("violations", [])
        )
        return AdapterOutcome("success", findings, semantic_coverage="complete")
    return AnalyzerAdapter(analyzer_id, run)


def _load_json(path: Path) -> Any:
    def reject(value: str) -> None:
        raise ValueError(f"non-finite JSON number is not allowed: {value}")

    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)


def trust_adapter(analyzer_id: str, source: str | Path) -> AnalyzerAdapter:
    """Wrap offline v0.8 trust analysis over a saved inventory artifact."""
    path = Path(source)

    def run() -> AdapterOutcome:
        try:
            inventory = _load_json(path)
            findings = analyze_trust_boundaries(inventory)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            return _failed("failed_invalid_input", str(exc))
        return AdapterOutcome("success", tuple(findings))
    return AnalyzerAdapter(analyzer_id, run)


def _finding_sort_key(item: SourcedFinding) -> tuple[str, str, str, str, str]:
    finding = item.finding
    canonical = json.dumps(
        finding, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )
    return (
        item.analyzer_id,
        finding["finding_type"],
        finding.get("resource") or "",
        finding.get("invariant_id") or "",
        canonical,
    )


def run_composite(adapters: Sequence[AnalyzerAdapter]) -> CompositeAudit:
    """Run explicit adapters and return a deterministic, mutation-isolated artifact."""
    ids = [adapter.analyzer_id for adapter in adapters]
    for analyzer_id in ids:
        if not isinstance(analyzer_id, str) or not analyzer_id.strip():
            raise CompositeValidationError("analyzer identifiers must be non-empty strings")
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise CompositeValidationError(
            f"duplicate analyzer identifier(s): {', '.join(duplicates)}"
        )
    if not adapters:
        raise CompositeValidationError("at least one analyzer must be requested")

    executions: list[AnalyzerExecution] = []
    sourced: list[SourcedFinding] = []
    for adapter in adapters:
        try:
            outcome = adapter.run()
            _validate_outcome(outcome)
            snapshots: list[dict[str, Any]] = []
            for finding in outcome.findings:
                validate_finding_contract(finding)
                snapshots.append(copy.deepcopy(finding_contract_as_dict(finding)))
        except Exception as exc:  # adapter isolation is part of the public contract
            outcome = AdapterOutcome(
                "failed_operational",
                reason=f"{type(exc).__name__}: {exc}",
            )
            snapshots = []
        executions.append(AnalyzerExecution(
            analyzer_id=adapter.analyzer_id,
            status=outcome.status,
            finding_count=len(snapshots),
            semantic_coverage=outcome.semantic_coverage,
            reason=outcome.reason,
        ))
        sourced.extend(SourcedFinding(adapter.analyzer_id, item) for item in snapshots)

    artifact = CompositeAudit(
        requested_analyzers=tuple(sorted(ids)),
        executions=tuple(sorted(executions, key=lambda item: item.analyzer_id)),
        findings=tuple(sorted(sourced, key=_finding_sort_key)),
    )
    validate_composite_audit(artifact)
    return artifact


def _validate_outcome(outcome: Any) -> None:
    if not isinstance(outcome, AdapterOutcome):
        raise CompositeValidationError("adapter must return AdapterOutcome")
    if outcome.status not in ANALYZER_STATUSES:
        raise CompositeValidationError(f"unsupported analyzer status: {outcome.status!r}")
    if outcome.semantic_coverage not in SEMANTIC_COVERAGE:
        raise CompositeValidationError(
            f"unsupported semantic coverage: {outcome.semantic_coverage!r}"
        )
    if outcome.status != "success" and outcome.findings:
        raise CompositeValidationError("only successful analyzers may return findings")
    if outcome.status == "success" and outcome.reason is not None:
        raise CompositeValidationError("successful analyzer must not have a failure reason")
    if outcome.status != "success" and (
        not isinstance(outcome.reason, str) or not outcome.reason.strip()
    ):
        raise CompositeValidationError("non-success analyzer must have a reason")


def composite_audit_as_dict(value: CompositeAudit) -> dict[str, Any]:
    return {
        "schema_version": value.schema_version,
        "requested_analyzers": list(value.requested_analyzers),
        "executions": [
            {
                "analyzer_id": item.analyzer_id,
                "status": item.status,
                "finding_count": item.finding_count,
                "semantic_coverage": item.semantic_coverage,
                **({"reason": item.reason} if item.reason is not None else {}),
            }
            for item in value.executions
        ],
        "findings": [
            {"analyzer_id": item.analyzer_id, "finding": copy.deepcopy(item.finding)}
            for item in value.findings
        ],
    }


def _exact(value: Mapping[str, Any], required: set[str], allowed: set[str], path: str) -> None:
    if any(not isinstance(key, str) for key in value):
        raise CompositeValidationError(f"{path} keys must be strings")
    missing = sorted(required - set(value))
    extra = sorted(set(value) - allowed)
    if missing:
        raise CompositeValidationError(f"{path} missing field(s): {', '.join(missing)}")
    if extra:
        raise CompositeValidationError(f"{path} unexpected field(s): {', '.join(extra)}")


def _json_value(value: Any, path: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise CompositeValidationError(f"{path} must not contain NaN or infinity")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CompositeValidationError(f"{path} keys must be strings")
            _json_value(item, f"{path}.{key}")
        return
    raise CompositeValidationError(f"{path} must contain only JSON-compatible values")


def validate_composite_audit(value: CompositeAudit | Mapping[str, Any]) -> None:
    data = composite_audit_as_dict(value) if isinstance(value, CompositeAudit) else value
    if not isinstance(data, Mapping):
        raise CompositeValidationError("composite audit must be an object")
    _exact(
        data,
        {"schema_version", "requested_analyzers", "executions", "findings"},
        {"schema_version", "requested_analyzers", "executions", "findings"},
        "composite",
    )
    if data["schema_version"] not in SUPPORTED_COMPOSITE_SCHEMA_VERSIONS:
        raise CompositeValidationError(
            f"unsupported schema_version: {data['schema_version']!r}"
        )
    requested = data["requested_analyzers"]
    if not isinstance(requested, list) or not requested:
        raise CompositeValidationError("requested_analyzers must be a non-empty array")
    if any(not isinstance(item, str) or not item.strip() for item in requested):
        raise CompositeValidationError("requested analyzer identifiers must be non-empty strings")
    if requested != sorted(requested) or len(requested) != len(set(requested)):
        raise CompositeValidationError("requested_analyzers must be unique and sorted")

    executions = data["executions"]
    if not isinstance(executions, list) or len(executions) != len(requested):
        raise CompositeValidationError("executions must contain one record per request")
    counts: dict[str, int] = {}
    execution_ids: list[str] = []
    for index, execution in enumerate(executions):
        path = f"executions[{index}]"
        if not isinstance(execution, Mapping):
            raise CompositeValidationError(f"{path} must be an object")
        _exact(
            execution,
            {"analyzer_id", "status", "finding_count", "semantic_coverage"},
            {"analyzer_id", "status", "finding_count", "semantic_coverage", "reason"},
            path,
        )
        analyzer_id = execution["analyzer_id"]
        if not isinstance(analyzer_id, str) or not analyzer_id.strip():
            raise CompositeValidationError(f"{path}.analyzer_id must be non-empty")
        execution_ids.append(analyzer_id)
        status = execution["status"]
        if status not in ANALYZER_STATUSES:
            raise CompositeValidationError(f"{path}.status is unsupported")
        count = execution["finding_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise CompositeValidationError(f"{path}.finding_count must be non-negative")
        if status != "success" and count:
            raise CompositeValidationError(f"{path} non-success cannot contain findings")
        coverage = execution["semantic_coverage"]
        if coverage not in SEMANTIC_COVERAGE:
            raise CompositeValidationError(f"{path}.semantic_coverage is unsupported")
        if status == "success" and "reason" in execution:
            raise CompositeValidationError(f"{path} success must not have reason")
        if status != "success" and (
            not isinstance(execution.get("reason"), str) or not execution["reason"].strip()
        ):
            raise CompositeValidationError(f"{path} non-success requires reason")
        counts[analyzer_id] = count
    if execution_ids != requested:
        raise CompositeValidationError("executions must match requested analyzer order")

    findings = data["findings"]
    if not isinstance(findings, list):
        raise CompositeValidationError("findings must be an array")
    actual = {item: 0 for item in requested}
    sort_keys: list[tuple[str, str, str, str, str]] = []
    for index, item in enumerate(findings):
        path = f"findings[{index}]"
        if not isinstance(item, Mapping):
            raise CompositeValidationError(f"{path} must be an object")
        _exact(item, {"analyzer_id", "finding"}, {"analyzer_id", "finding"}, path)
        analyzer_id = item["analyzer_id"]
        if analyzer_id not in actual:
            raise CompositeValidationError(f"{path} references an unrequested analyzer")
        validate_finding_contract(item["finding"])
        actual[analyzer_id] += 1
        sort_keys.append(_finding_sort_key(SourcedFinding(analyzer_id, dict(item["finding"]))))
    if sort_keys != sorted(sort_keys):
        raise CompositeValidationError("findings must be in deterministic order")
    if actual != counts:
        raise CompositeValidationError("execution finding_count does not match findings")
    _json_value(data, "composite")


def serialize_composite_audit(value: CompositeAudit) -> str:
    if not isinstance(value, CompositeAudit):
        raise CompositeValidationError("serializer requires CompositeAudit")
    validate_composite_audit(value)
    return json.dumps(
        composite_audit_as_dict(value), indent=2, sort_keys=True,
        ensure_ascii=False, allow_nan=False,
    )


def composite_exit_code(value: CompositeAudit) -> int:
    """Return 3 for partial/all failure; findings never drive composite scoring."""
    return 3 if any(item.status.startswith("failed_") for item in value.executions) else 0
