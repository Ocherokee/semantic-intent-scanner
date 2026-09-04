"""Execute the manifest's credential-free deterministic regression lane."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scanner.llms_txt import audit_llms_txt
from scanner.mcp_adapter import audit_mcp_tools
from scanner.registry import RegistryClient
from scanner.remote_fetch import FetchOutcome


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ASSERTIONS = {"exact", "floor", "none"}
ANALYZERS = {"remote", "mcp"}


class ManifestError(ValueError):
    """The regression manifest cannot be executed as written."""


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot load manifest: {exc}") from exc
    if not isinstance(value, dict) or value.get("manifest_version") != "0.1":
        raise ManifestError("manifest_version must be '0.1'")
    if not isinstance(value.get("entries"), list):
        raise ManifestError("entries must be an array")
    return value


def _required_object(value: Any, field: str, case_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{case_id}: {field} must be an object")
    return value


def _validate_entry(entry: Any, index: int) -> tuple[str, str]:
    if not isinstance(entry, dict):
        raise ManifestError(f"entry {index}: must be an object")
    case_id = entry.get("id")
    if not isinstance(case_id, str) or not case_id:
        raise ManifestError(f"entry {index}: id must be a non-empty string")
    evaluation = _required_object(entry.get("evaluation"), "evaluation", case_id)
    intended = evaluation.get("intended_detector")
    if intended not in {"deterministic", "model"}:
        raise ManifestError(f"{case_id}: intended_detector must be deterministic or model")
    if not isinstance(entry.get("fixture"), str) or not entry["fixture"]:
        raise ManifestError(f"{case_id}: fixture must be a non-empty string")
    _required_object(entry.get("invocation"), "invocation", case_id)
    if intended == "deterministic":
        if entry.get("analyzer") not in ANALYZERS:
            raise ManifestError(f"{case_id}: unsupported deterministic analyzer")
        regression = _required_object(entry.get("regression"), "regression", case_id)
        contract = _required_object(regression.get("deterministic"), "regression.deterministic", case_id)
        assertion = contract.get("test_assertion")
        if assertion not in ASSERTIONS:
            raise ManifestError(f"{case_id}: test_assertion must be exact, floor, or none")
        risk = contract.get("observed_risk")
        if risk not in RISK_ORDER:
            raise ManifestError(f"{case_id}: observed_risk must be a supported risk")
        types = contract.get("observed_finding_types")
        if types is not None and (
            not isinstance(types, list)
            or any(not isinstance(item, str) or not item for item in types)
            or len(types) != len(set(types))
        ):
            raise ManifestError(f"{case_id}: observed_finding_types must be unique non-empty strings")
    return case_id, intended


def _fixture_fetch(fixture: Path, served_path: str):
    body = fixture.read_bytes()

    def fetch(url: str) -> FetchOutcome:
        if url.rstrip("/").endswith("/" + served_path):
            return FetchOutcome(
                requested_url=url,
                final_url=url,
                status=200,
                content_type="text/markdown",
                body=body,
                sha256="regression-fixture",
                fetched_at="1970-01-01T00:00:00Z",
            )
        return FetchOutcome(
            url, None, 404, None, b"", None, "1970-01-01T00:00:00Z", error="HTTP 404"
        )

    return fetch


def _execute(entry: dict[str, Any], root: Path) -> dict[str, Any]:
    fixture = root / entry["fixture"]
    if not fixture.is_file():
        raise ManifestError(f"{entry['id']}: fixture does not exist: {entry['fixture']}")
    registry_path = root / "tests/fixtures/llms_txt/mock_registry.json"
    registry = RegistryClient.from_fixture(registry_path)
    if entry["analyzer"] == "remote":
        invocation = entry["invocation"]
        target = invocation.get("target")
        served_path = invocation.get("served_path")
        if not isinstance(target, str) or not target or not isinstance(served_path, str) or not served_path:
            raise ManifestError(f"{entry['id']}: remote invocation requires target and served_path")
        return audit_llms_txt(
            target,
            registry=registry,
            fetch=_fixture_fetch(fixture, served_path),
        )
    return audit_mcp_tools(str(fixture), registry=registry)


def run_manifest(path: Path) -> dict[str, Any]:
    manifest = load_manifest(path)
    root = path.resolve().parent.parent
    entries: list[tuple[dict[str, Any], str]] = []
    ignored_model = 0
    seen: set[str] = set()
    for index, entry in enumerate(manifest["entries"]):
        case_id, intended = _validate_entry(entry, index)
        if case_id in seen:
            raise ManifestError(f"duplicate case id: {case_id}")
        seen.add(case_id)
        if intended == "model":
            ignored_model += 1
        else:
            entries.append((entry, case_id))

    cases = []
    counts = {"pass": 0, "fail": 0, "not-asserted": 0}
    for entry, case_id in sorted(entries, key=lambda item: item[1]):
        result = _execute(entry, root)
        contract = entry["regression"]["deterministic"]
        assertion = contract["test_assertion"]
        actual_risk = result.get("overall_risk")
        actual_types = sorted({item.get("finding_type") for item in result.get("findings", [])})
        recorded_types = sorted(contract.get("observed_finding_types", []))
        reasons = []
        if assertion == "exact" and actual_risk != contract["observed_risk"]:
            reasons.append(f"risk recorded {contract['observed_risk']}, observed {actual_risk}")
        elif assertion == "floor" and (
            actual_risk not in RISK_ORDER
            or RISK_ORDER[actual_risk] < RISK_ORDER[contract["observed_risk"]]
        ):
            reasons.append(f"risk floor {contract['observed_risk']}, observed {actual_risk}")
        missing_types = sorted(set(recorded_types) - set(actual_types))
        if missing_types:
            reasons.append("missing finding types: " + ", ".join(missing_types))
        status = "not-asserted" if assertion == "none" and not reasons else ("fail" if reasons else "pass")
        counts[status] += 1
        cases.append(
            {
                "id": case_id,
                "status": status,
                "assertion": assertion,
                "recorded_risk": contract["observed_risk"],
                "observed_risk": actual_risk,
                "recorded_finding_types": recorded_types,
                "observed_finding_types": actual_types,
                "reasons": reasons,
            }
        )
    return {
        "manifest_version": manifest["manifest_version"],
        "cases": cases,
        "summary": {
            "executed": len(cases),
            "passed": counts["pass"],
            "failed": counts["fail"],
            "not_asserted": counts["not-asserted"],
            "model_entries_not_executed": ignored_model,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("regression_manifest.json"),
    )
    args = parser.parse_args(argv)
    try:
        report = run_manifest(args.manifest)
    except ManifestError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
