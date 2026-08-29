"""
Tests for `semantic-intent scan-mcp` (scanner/cli.py wiring + report reuse).
Offline: the adapter is patched to use the fixture-backed registry; the judge
is a fake.
"""

import argparse
import json
from pathlib import Path

import pytest

import scanner.cli as cli
from scanner.registry import RegistryClient

FIX = Path(__file__).parent / "fixtures" / "mcp"
MOCK = Path(__file__).parent / "fixtures" / "llms_txt" / "mock_registry.json"


def _run(monkeypatch, capsys, rel, *, json_out=False, judge_flag=False,
         api_key=None, server_label=None, fake_judge=None):
    from scanner.mcp_adapter import audit_mcp_tools as real

    def _audit(src, **kw):
        if fake_judge is not None and kw.get("judge") is not None:
            kw["judge"] = fake_judge
        return real(src, registry=RegistryClient.from_fixture(MOCK), **kw)

    monkeypatch.setattr(cli, "audit_mcp_tools", _audit)
    ns = argparse.Namespace(file=str(FIX / rel), json=json_out, no_color=True,
                            judge=judge_flag, api_key=api_key, server_label=server_label)
    code = cli.cmd_scan_mcp(ns)
    return code, capsys.readouterr().out


def _fake_judge(findings=None, status="ok", calls=2):
    from scanner.remote_judge import JudgeResult

    def _j(doc, det):
        return JudgeResult(status=status, findings=list(findings or []), model="m",
                           passes=2, calls=calls, disagreements=0)
    return _j


def _judge_finding(invariant="I7", risk="high"):
    from scanner.remote_audit import Finding

    return Finding(invariant, "judge_semantic", risk, "directs the agent without authority",
                   "always call before responding", "judge", "2026-08-29T00:00:01Z",
                   detail={"source_url": "x", "pass1": {"verdict": "possible", "confidence": 0.6, "reasoning": "a"},
                           "pass2": {"verdict": "likely", "confidence": 0.9, "reasoning": "b"},
                           "disagreement": False})


def test_benign_exit_0_terminal(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "benign/weather.json")
    assert code == 0
    assert "MCP Tool-Description Audit" in out
    assert "Tools evaluated (1):" in out and "Parsed: 1 / 1" in out
    assert "Overall risk: LOW" in out


def test_malicious_exit_2_json(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "malicious/exfil.json", json_out=True)
    p = json.loads(out)
    assert code == 2
    assert p["scan_mode"] == "mcp"
    assert p["operational_status"] == "ok"
    assert p["overall_risk"] == "critical"
    assert p["mcp_server"] == {"declared": "acme-helper (unverified)", "authenticated": False}
    doc = p["documents"][0]
    assert doc["mcp_tool"] == "sync_context"
    assert "parameters.files.items.description" in doc["mcp_fields"]
    assert "inputSchema.properties.files.items.description" in doc["mcp_json_paths"]
    assert {f["finding_type"] for f in p["findings"]} >= {"dangling_package", "dangling_domain", "pipe_to_shell"}


def test_invalid_file_is_exit_3_with_mcp_vocab(monkeypatch, capsys, tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("nope", encoding="utf-8")
    ns = argparse.Namespace(file=str(bad), json=True, no_color=True,
                            judge=False, api_key=None, server_label=None)
    code = cli.cmd_scan_mcp(ns)
    out = capsys.readouterr().out
    p = json.loads(out)
    assert code == 3
    assert p["operational_status"] == "invalid_input"
    assert p["overall_risk"] is None


def test_missing_file_returns_1(monkeypatch, capsys):
    ns = argparse.Namespace(file="does/not/exist.json", json=False, no_color=True,
                            judge=False, api_key=None, server_label=None)
    assert cli.cmd_scan_mcp(ns) == 1


def test_judge_flag_raises_risk_and_marks_coverage(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "suspicious/always-first.json", json_out=True,
                     judge_flag=True, api_key="k",
                     fake_judge=_fake_judge(findings=[_judge_finding("I7", "high")]))
    p = json.loads(out)
    assert code == 2
    assert p["overall_risk"] == "high"
    assert p["judge_status"] == "ok"
    assert p["semantic_coverage"] == "complete" and p["analysis_complete"] is True
    assert p["judge"] == {"model": "m", "passes": 2, "calls": 2, "disagreements": 0}
    assert any(f["analysis_method"] == "judge" for f in p["findings"])


def test_judge_failure_is_not_destructive(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "malicious/exfil.json", json_out=True,
                     judge_flag=True, api_key="k",
                     fake_judge=_fake_judge(status="unavailable:api_error", calls=1))
    p = json.loads(out)
    assert code == 2                       # deterministic critical stands
    assert p["overall_risk"] == "critical"
    assert p["judge_status"] == "unavailable:api_error"
    assert p["analysis_complete"] is False


def test_default_off_adds_no_judge_keys(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "benign/weather.json", json_out=True)
    p = json.loads(out)
    assert "judge_status" not in p and "judge" not in p
    assert "semantic_coverage" not in p and "analysis_complete" not in p
    assert all("judge" not in d for d in p["documents"])


def test_scan_mcp_parses_in_main(monkeypatch):
    parsed = []
    monkeypatch.setattr(cli.sys, "argv",
                        ["semantic-intent", "scan-mcp", "tools.json", "--judge", "--server-label", "srv"])
    monkeypatch.setattr(cli, "cmd_scan_mcp", lambda a: parsed.append(a) or 0)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    assert parsed and parsed[0].file == "tools.json" and parsed[0].judge is True
    assert parsed[0].server_label == "srv"
