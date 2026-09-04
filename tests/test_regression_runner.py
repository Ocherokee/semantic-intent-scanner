import copy
import json
from pathlib import Path

import pytest

from evaluation.run_regressions import ManifestError, load_manifest, main, run_manifest


ROOT = Path(__file__).parent.parent
MANIFEST = ROOT / "evaluation" / "regression_manifest.json"


def _write_manifest(tmp_path, entries):
    path = tmp_path / "regression_manifest.json"
    path.write_text(json.dumps({"manifest_version": "0.1", "entries": entries}), encoding="utf-8")
    return path


def test_checked_in_manifest_runs_only_nine_deterministic_cases():
    report = run_manifest(MANIFEST)
    assert report["summary"] == {
        "executed": 9,
        "passed": 9,
        "failed": 0,
        "not_asserted": 0,
        "model_entries_not_executed": 9,
    }
    assert [case["id"] for case in report["cases"]] == sorted(case["id"] for case in report["cases"])


def test_model_entry_is_not_executed_even_with_missing_fixture(tmp_path):
    entry = {
        "id": "model-only",
        "analyzer": "semantic",
        "fixture": "missing",
        "invocation": {},
        "evaluation": {"intended_detector": "model"},
    }
    assert run_manifest(_write_manifest(tmp_path, [entry]))["summary"]["model_entries_not_executed"] == 1


@pytest.mark.parametrize("assertion, recorded, actual, status", [
    ("exact", "low", "low", "pass"),
    ("exact", "medium", "low", "fail"),
    ("floor", "medium", "high", "pass"),
    ("floor", "high", "medium", "fail"),
    ("none", "critical", "low", "not-asserted"),
])
def test_assertion_modes(monkeypatch, tmp_path, assertion, recorded, actual, status):
    fixture = tmp_path / "fixture.json"
    fixture.write_text("{}", encoding="utf-8")
    entry = {
        "id": "case",
        "analyzer": "mcp",
        "fixture": "fixture.json",
        "invocation": {},
        "evaluation": {"intended_detector": "deterministic"},
        "regression": {"deterministic": {
            "observed_risk": recorded,
            "test_assertion": assertion,
        }},
    }
    monkeypatch.setattr("evaluation.run_regressions._execute", lambda *_: {"overall_risk": actual, "findings": []})
    report = run_manifest(_write_manifest(tmp_path, [entry]))
    assert report["cases"][0]["status"] == status


def test_recorded_finding_types_remain_present_while_extra_types_are_allowed(monkeypatch, tmp_path):
    entry = copy.deepcopy(load_manifest(MANIFEST)["entries"][0])
    entry["fixture"] = "unused"
    monkeypatch.setattr("evaluation.run_regressions._execute", lambda *_: {
        "overall_risk": "low",
        "findings": [{"finding_type": "extra"}],
    })
    report = run_manifest(_write_manifest(tmp_path, [entry]))
    assert report["cases"][0]["status"] == "fail"
    assert report["cases"][0]["reasons"] == ["missing finding types: unverified_package_provenance"]


@pytest.mark.parametrize("mutation", [
    lambda data: data.pop("manifest_version"),
    lambda data: data.update(entries={}),
])
def test_malformed_manifest_fails_clearly(tmp_path, mutation):
    data = {"manifest_version": "0.1", "entries": []}
    mutation(data)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_cli_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr("evaluation.run_regressions.run_manifest", lambda _path: {
        "summary": {"failed": 1}, "cases": []
    })
    assert main([str(MANIFEST)]) == 1
    capsys.readouterr()
    monkeypatch.setattr("evaluation.run_regressions.run_manifest", lambda _path: (_ for _ in ()).throw(ManifestError("bad")))
    assert main([str(MANIFEST)]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "bad"}
