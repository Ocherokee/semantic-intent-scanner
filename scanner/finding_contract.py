"""Stable v0.5 machine-readable finding contract.

The public contract is deliberately separate from detector implementations and
from legacy report envelopes. Existing detector findings enter through explicit
adapters; serializers accept only the canonical :class:`FindingContract`.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .invariants import INVARIANT_MAP

FINDING_SCHEMA_VERSION = "0.1"
SUPPORTED_FINDING_SCHEMA_VERSIONS = frozenset({FINDING_SCHEMA_VERSION})
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class FindingContractError(ValueError):
    """Base error for contract validation and legacy adaptation."""


class FindingContractValidationError(FindingContractError):
    """Raised when a canonical finding does not satisfy schema ``0.1``."""


class LegacyFindingAdapterError(FindingContractError):
    """Raised when a legacy finding cannot be mapped without inventing semantics."""


@dataclass(frozen=True)
class EvidenceItem:
    kind: str
    value: str | int | float | bool | None
    source: str | None = None
    observed_at: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class Observation:
    summary: str
    evidence: tuple[EvidenceItem, ...] = ()


@dataclass(frozen=True)
class Remediation:
    summary: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Retest:
    condition: str


@dataclass(frozen=True)
class FindingContract:
    finding_type: str
    severity: str
    observation: Observation
    rationale: str
    remediation: Remediation
    retest: Retest
    schema_version: str = FINDING_SCHEMA_VERSION
    invariant_id: str | None = None
    resource: str | None = None
    context: dict[str, Any] | None = None


@dataclass(frozen=True)
class _OutcomePolicy:
    remediation: str
    retest: str
    rationale: str


_REMOTE_POLICIES: dict[str, _OutcomePolicy] = {
    "cross_origin_instruction": _OutcomePolicy(
        "Agent-readable instructions remain bound to an explicitly trusted origin.",
        "the requested instruction resource resolves without an unapproved cross-origin authority change",
        "Untrusted content crossed an origin boundary before being presented as agent-readable instruction.",
    ),
    "pipe_to_shell": _OutcomePolicy(
        "Remote documentation no longer grants downloaded content direct shell-execution authority.",
        "the resource contains no instruction that pipes remotely retrieved content directly to a command interpreter",
        "Piping remote content to a shell collapses the boundary between documentation and executable authority.",
    ),
    "script_download": _OutcomePolicy(
        "Remote scripts are separated from authoritative instructions and require an explicit trust decision before execution.",
        "the resource contains no unverified instruction to download and execute a remote script",
        "The document presents externally controlled code as an operational step without establishing its authority.",
    ),
    "index_url_override": _OutcomePolicy(
        "Package installation remains bound to an explicitly trusted registry origin.",
        "the install reference uses an approved package index whose authority is established independently of the document",
        "An alternate registry extends trust to a package source that the document itself cannot authorize.",
    ),
    "vcs_install": _OutcomePolicy(
        "Direct VCS dependencies have independently established source and publisher authority.",
        "the referenced VCS dependency is removed or its source authority is independently established",
        "A direct VCS install bypasses ordinary registry provenance signals and creates a transitive trust decision.",
    ),
    "dangling_package": _OutcomePolicy(
        "Install instructions reference only packages with independently established provenance.",
        "the unclaimed package reference is removed or replaced by a package whose provenance is independently established",
        "An unclaimed package name is a writable authority slot that an attacker can register later.",
    ),
    "unverified_package_provenance": _OutcomePolicy(
        "The referenced package's publisher and source authority are independently established.",
        "the package reference is removed or independent evidence establishes its publisher and source authority",
        "Registry existence alone does not establish that a package is controlled by the party whose documentation names it.",
    ),
    "dangling_domain": _OutcomePolicy(
        "Agent-readable content references only domains with independently established control and purpose.",
        "the unclaimed domain reference is removed or replaced by a domain whose control is independently established",
        "An unclaimed domain is a writable authority slot that can later serve attacker-controlled content.",
    ),
    "unverified_domain_provenance": _OutcomePolicy(
        "The referenced domain's relationship to the documented authority is independently established.",
        "the domain reference is removed or independent evidence establishes its authorized relationship to the resource",
        "A resolving domain does not prove that it is controlled or authorized by the document publisher.",
    ),
    "judge_semantic": _OutcomePolicy(
        "Untrusted content is clearly separated from authoritative agent instructions.",
        "the resource no longer presents untrusted content as instruction or authority capable of directing agent behavior",
        "Semantic review found content that may cross an agent trust or authority boundary.",
    ),
    "judge_pass_disagreement": _OutcomePolicy(
        "Ambiguous authority-bearing language is removed or made unambiguously non-authoritative.",
        "the resource's authority-bearing language is unambiguous and no longer supports conflicting reasonable classifications under the identified invariant",
        "Independent semantic passes disagreed, leaving the authority or intent of the content unresolved.",
    ),
}


_INVARIANT_POLICIES: dict[str, _OutcomePolicy] = {
    "I1": _OutcomePolicy(
        "Material behavior and consequences remain visible to the user.",
        "the resource contains no instruction to hide material behavior, output, or consequences from the user",
        "The finding indicates a potential No Concealment invariant violation.",
    ),
    "I2": _OutcomePolicy(
        "Credentials and secrets are accessed only with explicit, task-relevant authority.",
        "the resource contains no unauthorized instruction to access, expose, or transmit credentials or secrets",
        "The finding indicates a potential No Unauthorized Credential Access invariant violation.",
    ),
    "I3": _OutcomePolicy(
        "Requested actions remain within the user's authorized task scope.",
        "the resource contains no instruction that expands action beyond the user's authorized scope",
        "The finding indicates a potential No Scope Override invariant violation.",
    ),
    "I4": _OutcomePolicy(
        "Actions requiring consent remain contingent on explicit user authorization.",
        "the resource contains no instruction to bypass, assume, or fabricate required user consent",
        "The finding indicates a potential No Consent Override invariant violation.",
    ),
    "I5": _OutcomePolicy(
        "Operational commands remain visibly identified and independently authorized.",
        "the resource contains no operational command disguised as documentation, data, or routine explanation",
        "The finding indicates a potential No Command Laundering invariant violation.",
    ),
    "I6": _OutcomePolicy(
        "The user and system retain an accurate, reviewable record of agent actions.",
        "the resource contains no instruction to disable logging, erase history, or otherwise suppress action auditability",
        "The finding indicates a potential No Auditability Suppression invariant violation.",
    ),
    "I7": _OutcomePolicy(
        "Untrusted content cannot impersonate system, platform, developer, operator, or user authority.",
        "the resource contains no untrusted content represented as system, developer, platform, operator, or user authority",
        "The finding indicates a potential No Authority Laundering invariant violation.",
    ),
    "I8": _OutcomePolicy(
        "External content remains data until an explicit trust and authority decision is made.",
        "the resource contains no unverified external content capable of directing agent behavior or extending trusted authority",
        "The finding indicates a potential No Unverified External Instruction invariant violation.",
    ),
}


_DIRECTORY_POLICIES: dict[str, _OutcomePolicy] = {
    "pytest_plugin": _OutcomePolicy(
        "Test collection does not automatically execute unreviewed package code.",
        "the package contains no unreviewed pytest plugin code that auto-executes during test collection",
        "Pytest loads conftest.py during collection, creating an automatic execution surface.",
    ),
    "test_file": _OutcomePolicy(
        "Test discovery does not automatically execute unreviewed package code.",
        "the package contains no unreviewed test hook or test body that performs security-sensitive operations during discovery or execution",
        "Common test runners automatically discover and execute test files and hooks.",
    ),
    "test_runner_config": _OutcomePolicy(
        "Test-runner configuration cannot silently introduce unreviewed execution hooks.",
        "the configuration contains no unreviewed setup file, execution hook, or discovery override",
        "Test-runner configuration can redirect discovery and add code that executes automatically.",
    ),
    "config_file": _OutcomePolicy(
        "Configuration changes to permissions, tools, and agent behavior remain explicit and authorized.",
        "the configuration contains no unreviewed setting that enables tools, changes permissions, or alters agent authority",
        "Configuration files can change tool access, permissions, and agent behavior outside ordinary instruction review.",
    ),
    "suspicious_file": _OutcomePolicy(
        "Files with automatic or security-sensitive behavior have an explicit, reviewed purpose.",
        "the file is removed or its security-sensitive behavior and package purpose are explicitly reviewed and authorized",
        "The file occupies an execution or configuration surface that requires explicit review.",
    ),
    "suspicious_directory": _OutcomePolicy(
        "The package contains only directories with an explicit, reviewed purpose.",
        "the unexplained directory is removed or its package purpose is explicitly reviewed and authorized",
        "The directory has no established purpose in the scanned package shape.",
    ),
}


_TOP_LEVEL_FIELDS = {
    "schema_version", "finding_type", "severity", "invariant_id", "resource",
    "observation", "rationale", "remediation", "retest", "context",
}
_REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version", "finding_type", "severity", "observation", "rationale",
    "remediation", "retest",
}


def _nonempty_string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise FindingContractValidationError(f"{path} must be a non-empty string")


def _exact_fields(value: Mapping[str, Any], required: set[str], allowed: set[str], path: str) -> None:
    if any(not isinstance(key, str) for key in value):
        raise FindingContractValidationError(f"{path} keys must be strings")
    missing = sorted(required - set(value))
    unexpected = sorted(set(value) - allowed)
    if missing:
        raise FindingContractValidationError(f"{path} missing required field(s): {', '.join(missing)}")
    if unexpected:
        raise FindingContractValidationError(f"{path} has unexpected field(s): {', '.join(unexpected)}")


def _json_compatible(value: Any, path: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise FindingContractValidationError(f"{path} must not contain NaN or infinity")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_compatible(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise FindingContractValidationError(f"{path} keys must be strings")
            _json_compatible(item, f"{path}.{key}")
        return
    raise FindingContractValidationError(f"{path} must contain only JSON-compatible values")


def finding_contract_as_dict(finding: FindingContract) -> dict[str, Any]:
    """Convert a canonical finding to its public JSON-compatible shape."""
    observation: dict[str, Any] = {
        "summary": finding.observation.summary,
        "evidence": [],
    }
    for item in finding.observation.evidence:
        evidence: dict[str, Any] = {"kind": item.kind, "value": item.value}
        if item.source is not None:
            evidence["source"] = item.source
        if item.observed_at is not None:
            evidence["observed_at"] = item.observed_at
        if item.metadata is not None:
            evidence["metadata"] = item.metadata
        observation["evidence"].append(evidence)

    out: dict[str, Any] = {
        "schema_version": finding.schema_version,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "observation": observation,
        "rationale": finding.rationale,
        "remediation": {
            "summary": finding.remediation.summary,
            "references": list(finding.remediation.references),
        },
        "retest": {"condition": finding.retest.condition},
    }
    if finding.invariant_id is not None:
        out["invariant_id"] = finding.invariant_id
    if finding.resource is not None:
        out["resource"] = finding.resource
    if finding.context is not None:
        out["context"] = finding.context
    return out


def validate_finding_contract(value: FindingContract | Mapping[str, Any]) -> None:
    """Validate a canonical model or serialized contract; never repair it."""
    data = finding_contract_as_dict(value) if isinstance(value, FindingContract) else value
    if not isinstance(data, Mapping):
        raise FindingContractValidationError("finding must be an object")
    _exact_fields(data, _REQUIRED_TOP_LEVEL_FIELDS, _TOP_LEVEL_FIELDS, "finding")

    version = data["schema_version"]
    _nonempty_string(version, "schema_version")
    if version not in SUPPORTED_FINDING_SCHEMA_VERSIONS:
        raise FindingContractValidationError(f"unsupported schema_version: {version!r}")
    _nonempty_string(data["finding_type"], "finding_type")
    if not isinstance(data["severity"], str) or data["severity"] not in SEVERITIES:
        raise FindingContractValidationError("severity must be one of: low, medium, high, critical")
    for optional in ("invariant_id", "resource"):
        if optional in data:
            _nonempty_string(data[optional], optional)

    observation = data["observation"]
    if not isinstance(observation, Mapping):
        raise FindingContractValidationError("observation must be an object")
    _exact_fields(observation, {"summary", "evidence"}, {"summary", "evidence"}, "observation")
    _nonempty_string(observation["summary"], "observation.summary")
    evidence_items = observation["evidence"]
    if not isinstance(evidence_items, list):
        raise FindingContractValidationError("observation.evidence must be an array")
    for index, evidence in enumerate(evidence_items):
        path = f"observation.evidence[{index}]"
        if not isinstance(evidence, Mapping):
            raise FindingContractValidationError(f"{path} must be an object")
        _exact_fields(
            evidence, {"kind", "value"},
            {"kind", "value", "source", "observed_at", "metadata"}, path,
        )
        _nonempty_string(evidence["kind"], f"{path}.kind")
        evidence_value = evidence["value"]
        if not (evidence_value is None or isinstance(evidence_value, (str, int, float, bool))):
            raise FindingContractValidationError(f"{path}.value must be a JSON scalar")
        if isinstance(evidence_value, float) and not math.isfinite(evidence_value):
            raise FindingContractValidationError(f"{path}.value must not contain NaN or infinity")
        for optional in ("source", "observed_at"):
            if optional in evidence:
                _nonempty_string(evidence[optional], f"{path}.{optional}")
        if "metadata" in evidence:
            if not isinstance(evidence["metadata"], dict):
                raise FindingContractValidationError(f"{path}.metadata must be an object")
            _json_compatible(evidence["metadata"], f"{path}.metadata")

    _nonempty_string(data["rationale"], "rationale")
    remediation = data["remediation"]
    if not isinstance(remediation, Mapping):
        raise FindingContractValidationError("remediation must be an object")
    _exact_fields(remediation, {"summary", "references"}, {"summary", "references"}, "remediation")
    _nonempty_string(remediation["summary"], "remediation.summary")
    if not isinstance(remediation["references"], list):
        raise FindingContractValidationError("remediation.references must be an array")
    for index, reference in enumerate(remediation["references"]):
        _nonempty_string(reference, f"remediation.references[{index}]")

    retest = data["retest"]
    if not isinstance(retest, Mapping):
        raise FindingContractValidationError("retest must be an object")
    _exact_fields(retest, {"condition"}, {"condition"}, "retest")
    _nonempty_string(retest["condition"], "retest.condition")

    if "context" in data:
        if not isinstance(data["context"], dict):
            raise FindingContractValidationError("context must be an object")
        _json_compatible(data["context"], "context")


def serialize_finding_contract(finding: FindingContract) -> str:
    """Validate and deterministically serialize one canonical finding."""
    if not isinstance(finding, FindingContract):
        raise FindingContractValidationError("serializer requires a FindingContract")
    validate_finding_contract(finding)
    return json.dumps(
        finding_contract_as_dict(finding), indent=2, sort_keys=True,
        ensure_ascii=False, allow_nan=False,
    )


def serialize_finding_contracts(findings: Sequence[FindingContract]) -> str:
    """Validate and deterministically serialize a list of canonical findings."""
    payload: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, FindingContract):
            raise FindingContractValidationError(f"findings[{index}] must be a FindingContract")
        validate_finding_contract(finding)
        payload.append(finding_contract_as_dict(finding))
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _legacy_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    fields = (
        "invariant_id", "finding_type", "risk", "summary", "evidence",
        "analysis_method", "observed_at", "provenance_state", "detail",
    )
    if all(hasattr(value, field) for field in fields):
        return {field: getattr(value, field) for field in fields}
    raise LegacyFindingAdapterError("remote finding must be a Finding or compatible mapping")


def _resource_from_detail(detail: Mapping[str, Any]) -> str | None:
    for key in (
        "mcp_source_url", "source_url", "path", "index_url", "package", "domain",
        "mcp_json_path", "documented_origin",
    ):
        value = detail.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def adapt_remote_finding(value: Any) -> FindingContract:
    """Adapt an existing remote/MCP ``Finding`` without changing its risk."""
    legacy = _legacy_mapping(value)
    finding_type = legacy.get("finding_type")
    invariant_id = legacy.get("invariant_id")
    policy = _REMOTE_POLICIES.get(finding_type)
    if policy is None and finding_type in {"judge_semantic", "judge_pass_disagreement"}:
        policy = _INVARIANT_POLICIES.get(invariant_id)
    if policy is None:
        raise LegacyFindingAdapterError(
            f"no reviewed remediation/retest policy for remote finding_type {finding_type!r}"
        )
    detail = legacy.get("detail") or {}
    if not isinstance(detail, dict):
        raise LegacyFindingAdapterError("remote finding detail must be an object")
    source = detail.get("source_url") if isinstance(detail.get("source_url"), str) else None
    evidence = EvidenceItem(
        kind="text",
        value=legacy.get("evidence", ""),
        source=source,
        observed_at=legacy.get("observed_at"),
    )
    context = {
        "analysis_method": legacy.get("analysis_method"),
        "provenance_state": legacy.get("provenance_state"),
        "detail": detail,
    }
    contract = FindingContract(
        finding_type=finding_type,
        severity=legacy.get("risk"),
        invariant_id=invariant_id,
        resource=_resource_from_detail(detail),
        observation=Observation(summary=legacy.get("summary", ""), evidence=(evidence,)),
        rationale=policy.rationale,
        remediation=Remediation(policy.remediation),
        retest=Retest(policy.retest),
        context=context,
    )
    validate_finding_contract(contract)
    return contract


def adapt_semantic_violation(
    violation: Mapping[str, Any], *, severity: str, resource: str | None = None,
) -> FindingContract:
    """Adapt one ``aggregate_results`` violation with caller-preserved severity.

    Legacy semantic violations do not carry per-finding risk, so the adapter
    requires the existing severity decision explicitly and never derives one.
    """
    invariant_id = violation.get("invariant_id")
    policy = _INVARIANT_POLICIES.get(invariant_id)
    if policy is None:
        raise LegacyFindingAdapterError(f"no reviewed policy for invariant {invariant_id!r}")
    summary = violation.get("reasoning")
    evidence_items: list[EvidenceItem] = []
    flagged = violation.get("flagged_text")
    if flagged is not None:
        evidence_items.append(EvidenceItem(kind="text", value=flagged, source=resource))
    context = {
        key: violation[key]
        for key in (
            "verdict", "confidence", "chunk_index", "chunk_excerpt",
            "mechanism_failure", "mechanism_bridge",
        )
        if key in violation
    }
    inv = INVARIANT_MAP.get(invariant_id, {})
    if inv:
        context["invariant_name"] = inv.get("name")
    contract = FindingContract(
        finding_type="semantic_invariant_violation",
        severity=severity,
        invariant_id=invariant_id,
        resource=resource,
        observation=Observation(summary=summary, evidence=tuple(evidence_items)),
        rationale=policy.rationale,
        remediation=Remediation(policy.remediation),
        retest=Retest(policy.retest),
        context=context or None,
    )
    validate_finding_contract(contract)
    return contract


def adapt_directory_finding(value: Mapping[str, Any]) -> FindingContract:
    """Adapt one legacy directory-audit finding without changing its risk."""
    finding_type = value.get("type")
    policy = _DIRECTORY_POLICIES.get(finding_type)
    if policy is None:
        raise LegacyFindingAdapterError(
            f"no reviewed remediation/retest policy for directory finding type {finding_type!r}"
        )
    resource = value.get("path")
    evidence_items: list[EvidenceItem] = []
    for pattern in value.get("dangerous_patterns", []):
        if not isinstance(pattern, Mapping):
            raise LegacyFindingAdapterError("dangerous_patterns entries must be objects")
        evidence_items.append(EvidenceItem(
            kind="pattern",
            value=pattern.get("pattern"),
            source=resource,
            metadata={
                "category": pattern.get("category"),
                "match_count": pattern.get("match_count"),
            },
        ))
    for setting in value.get("dangerous_settings", []):
        evidence_items.append(EvidenceItem(kind="setting", value=setting, source=resource))
    summary = value.get("reason")
    context = {
        key: value[key]
        for key in value
        if key not in {"path", "type", "risk", "reason", "dangerous_patterns", "dangerous_settings"}
    }
    contract = FindingContract(
        finding_type=finding_type,
        severity=value.get("risk"),
        resource=resource,
        observation=Observation(summary=summary, evidence=tuple(evidence_items)),
        rationale=policy.rationale,
        remediation=Remediation(policy.remediation),
        retest=Retest(policy.retest),
        context=context or None,
    )
    validate_finding_contract(contract)
    return contract
