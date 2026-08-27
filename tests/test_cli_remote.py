"""
Tests for `semantic-intent scan-remote` (scanner/cli.py + report.py remote
renderers). Fully offline: the llms.txt adapter is patched to use a fake
guarded-fetch and the fixture-backed registry — no network, no API key.
"""

import argparse
import json
from pathlib import Path

import pytest

import scanner.cli as cli
from scanner.registry import RegistryClient
from scanner.remote_fetch import FetchOutcome

FIX = Path(__file__).parent / "fixtures" / "llms_txt"
MOCK = FIX / "mock_registry.json"


# ---------------------------------------------------------------------------
# fake fetch builders
# ---------------------------------------------------------------------------

def _served(url, body, **kw):
    return FetchOutcome(
        requested_url=url,
        final_url=kw.get("final_url", url),
        status=200,
        content_type="text/markdown",
        body=body,
        sha256=kw.get("sha256", "a" * 64),
        fetched_at="2026-08-27T00:00:00Z",
        redirect_chain=kw.get("redirect_chain", []),
        cross_origin_redirect=kw.get("cross_origin_redirect", False),
        truncated=kw.get("truncated", False),
    )


def _fetch_fixture(fixture_rel, path="llms.txt"):
    body = (FIX / fixture_rel).read_bytes()

    def _fetch(url):
        if url.rstrip("/").endswith("/" + path):
            return _served(url, body)
        return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")

    return _fetch


def _fetch_all_404(url):
    return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")


def _fetch_all_blocked(url):
    return FetchOutcome(
        url, None, 0, None, b"", None, "2026-08-27T00:00:00Z",
        blocked_reason="resolves to 10.0.0.1: private address",
        error="blocked: resolves to 10.0.0.1: private address",
    )


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

def _run(monkeypatch, capsys, fetch, url="https://example.com", json_out=False):
    from scanner.llms_txt import audit_llms_txt as real

    monkeypatch.setattr(
        cli, "audit_llms_txt",
        lambda u: real(u, registry=RegistryClient.from_fixture(MOCK), fetch=fetch),
    )
    ns = argparse.Namespace(url=url, json=json_out, no_color=True)
    code = cli.cmd_scan_remote(ns)
    return code, capsys.readouterr().out


# ---------------------------------------------------------------------------
# A / B / C / D — risk tiers and exit codes
# ---------------------------------------------------------------------------

def test_A_benign_target_low_exit_0(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _fetch_fixture("benign/first-party-sdk-llms.txt"),
                     url="https://sdk.example.com")
    assert code == 0
    assert "Overall risk: LOW" in out
    assert "OPERATIONAL FAILURE" not in out


def test_B_malicious_target_critical_exit_2(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys,
                     _fetch_fixture("malicious/onboarding-llms-full.txt", path="llms-full.txt"),
                     url="https://acme.example")
    assert code == 2
    assert "Overall risk: CRITICAL" in out
    assert "dangling_package" in out and "pipe_to_shell" in out


def test_C_medium_target_exit_1(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _fetch_fixture("suspicious/agent-tooling-llms.txt"),
                     url="https://aitools.example")
    assert code == 1
    assert "Overall risk: MEDIUM" in out


def test_D_one_path_404_other_succeeds_is_scanned(monkeypatch, capsys):
    # only llms.txt served; llms-full.txt 404 -> still a real scan, not a failure
    code, out = _run(monkeypatch, capsys, _fetch_fixture("benign/docs-site-llms.txt"),
                     url="https://docs.example.com", json_out=True)
    payload = json.loads(out)
    assert payload["operational_status"] == "ok"
    assert payload["documents_retrieved"] == 1
    assert payload["documents_attempted"] == 2
    assert payload["exit_code"] == 0
    assert code == 0
    assert len(payload["findings"]) >= 1


# ---------------------------------------------------------------------------
# E / F — operational failures (never "low risk")
# ---------------------------------------------------------------------------

def test_E_no_document_retrieved_is_operational_failure(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _fetch_all_404, json_out=True)
    payload = json.loads(out)
    assert code == 3
    assert payload["operational_status"] == "not_found"
    assert payload["overall_risk"] is None          # NOT "low"
    assert payload["exit_code"] == 3


def test_E_terminal_says_not_low_risk(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _fetch_all_404)
    assert code == 3
    assert "OPERATIONAL FAILURE" in out
    assert "NOT a low-risk result" in out
    assert "Overall risk:" not in out


def test_F_ssrf_blocked_is_operational_failure_with_reason(monkeypatch, capsys):
    code, term = _run(monkeypatch, capsys, _fetch_all_blocked)
    assert code == 3
    assert "BLOCKED" in term and "private address" in term
    assert "OPERATIONAL FAILURE" in term

    code_j, out = _run(monkeypatch, capsys, _fetch_all_blocked, json_out=True)
    payload = json.loads(out)
    assert payload["operational_status"] == "fetch_blocked"
    assert payload["overall_risk"] is None
    assert any("private address" in (d["blocked_reason"] or "") for d in payload["documents"])


# ---------------------------------------------------------------------------
# G / H — redirect and truncation surfacing
# ---------------------------------------------------------------------------

def test_G_cross_origin_redirect_surfaced(monkeypatch, capsys):
    chain = [
        {"url": "https://example.com/llms.txt", "status": 302},
        {"url": "https://cdn.other.example/llms.txt", "status": 200},
    ]

    def fetch(url):
        if url.endswith("/llms.txt"):
            return _served(url, b"# docs\npip install requests\n",
                           final_url="https://cdn.other.example/llms.txt",
                           cross_origin_redirect=True, redirect_chain=chain)
        return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")

    code, term = _run(monkeypatch, capsys, fetch)
    assert "[cross-origin redirect]" in term
    assert "cross-origin redirect followed:" in term

    _, out = _run(monkeypatch, capsys, fetch, json_out=True)
    payload = json.loads(out)
    served = [d for d in payload["documents"] if d["status"] == 200][0]
    assert served["cross_origin_redirect"] is True
    assert served["redirect_chain"] == chain
    assert any(f["finding_type"] == "cross_origin_instruction" for f in payload["findings"])


def test_H_truncated_document_surfaced(monkeypatch, capsys):
    def fetch(url):
        if url.endswith("/llms.txt"):
            return _served(url, b"# docs\npip install requests\n", truncated=True)
        return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")

    from scanner.remote_fetch import MAX_BODY_BYTES
    kb = MAX_BODY_BYTES // 1024

    code, term = _run(monkeypatch, capsys, fetch)
    assert f"[truncated @ {kb} KB]" in term
    assert f"truncated at the {kb} KB body limit" in term

    _, out = _run(monkeypatch, capsys, fetch, json_out=True)
    payload = json.loads(out)
    served = [d for d in payload["documents"] if d["status"] == 200][0]
    assert served["truncated"] is True


# ---------------------------------------------------------------------------
# I — JSON schema
# ---------------------------------------------------------------------------

def test_I_json_schema_has_required_metadata_and_full_findings(monkeypatch, capsys):
    _, out = _run(monkeypatch, capsys,
                  _fetch_fixture("malicious/onboarding-llms-full.txt", path="llms-full.txt"),
                  url="https://acme.example", json_out=True)
    p = json.loads(out)

    for key in ("scanner", "version", "scan_mode", "target", "timestamp",
                "operational_status", "exit_code", "overall_risk",
                "documents_attempted", "documents_retrieved", "documents",
                "finding_count", "findings", "disclaimer"):
        assert key in p, f"missing top-level key {key}"
    assert p["scan_mode"] == "remote"
    assert p["target"] == "https://acme.example"

    doc = [d for d in p["documents"] if d["status"] == 200][0]
    for key in ("requested_url", "final_url", "status", "fetched_at", "sha256",
                "content_type", "redirect_chain", "cross_origin_redirect",
                "truncated", "error", "blocked_reason"):
        assert key in doc, f"missing document key {key}"

    assert p["findings"], "expected findings for the malicious fixture"
    f = p["findings"][0]
    for key in ("invariant_id", "finding_type", "risk", "summary", "evidence",
                "analysis_method", "observed_at", "provenance_state", "detail"):
        assert key in f, f"missing finding key {key}"
    # external-state evidence is not collapsed into a generic flag
    methods = {f["analysis_method"] for f in p["findings"]}
    assert methods <= {"rule_based", "external_state", "fixture"}
    assert "fixture" in methods  # registry/DNS findings kept their method


# ---------------------------------------------------------------------------
# J — no Anthropic API key needed
# ---------------------------------------------------------------------------

def test_J_works_without_anthropic_api_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code, out = _run(monkeypatch, capsys, _fetch_fixture("benign/first-party-sdk-llms.txt"),
                     url="https://sdk.example.com")
    assert code == 0
    assert "Remote Content Audit" in out


# ---------------------------------------------------------------------------
# backward compatibility — `scan` subcommand still parses
# ---------------------------------------------------------------------------

def test_scan_and_scan_remote_both_parse(monkeypatch):
    parsed = []
    monkeypatch.setattr(cli.sys, "argv", ["semantic-intent", "scan-remote", "https://example.com", "--json"])
    monkeypatch.setattr(cli, "cmd_scan_remote", lambda a: parsed.append(("remote", a)) or 0)
    monkeypatch.setattr(cli, "cmd_scan", lambda a: parsed.append(("scan", a)) or 0)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    assert parsed and parsed[0][0] == "remote"
    assert parsed[0][1].url == "https://example.com" and parsed[0][1].json is True

    parsed.clear()
    monkeypatch.setattr(cli.sys, "argv", ["semantic-intent", "scan", "./SKILL.md", "--no-color"])
    with pytest.raises(SystemExit):
        cli.main()
    assert parsed and parsed[0][0] == "scan"
    assert parsed[0][1].path == "./SKILL.md"
