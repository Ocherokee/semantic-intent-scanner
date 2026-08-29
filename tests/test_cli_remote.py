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

def _run(monkeypatch, capsys, fetch, url="https://example.com", json_out=False,
         judge_flag=False, api_key=None, fake_judge=None):
    from scanner.llms_txt import audit_llms_txt as real

    def _audit(u, **kw):
        if fake_judge is not None and kw.get("judge") is not None:
            kw["judge"] = fake_judge
        return real(u, registry=RegistryClient.from_fixture(MOCK), fetch=fetch, **kw)

    monkeypatch.setattr(cli, "audit_llms_txt", _audit)
    ns = argparse.Namespace(url=url, json=json_out, no_color=True,
                            judge=judge_flag, api_key=api_key)
    code = cli.cmd_scan_remote(ns)
    return code, capsys.readouterr().out


# ---------------------------------------------------------------------------
# fake judge — canned JudgeResults per document
# ---------------------------------------------------------------------------

def _judge_finding(invariant="I7", risk="high", ftype="judge_semantic"):
    from scanner.remote_audit import Finding
    return Finding(
        invariant_id=invariant, finding_type=ftype, risk=risk,
        summary="narrates an unestablished vendor relationship", evidence="official renewal",
        analysis_method="judge", observed_at="2026-08-28T00:00:01Z",
        detail={"source_url": "https://x/llms.txt", "source_sha256": "s", "judge_model": "m",
                "pass1": {"verdict": "possible", "confidence": 0.6, "reasoning": "a"},
                "pass2": {"verdict": "likely", "confidence": 0.9, "reasoning": "b"},
                "disagreement": ftype == "judge_pass_disagreement"},
    )


def make_judge(per_url=None, default=None):
    """
    Build a fake judge callable `(doc, det) -> JudgeResult`. `judge_document`
    never raises, so neither does this — a failed pass is a JudgeResult with an
    `unavailable:*` status. `per_url` keys on final_url / origin_url.
    """
    from scanner.remote_judge import JudgeResult

    per_url = per_url or {}
    fallback = default or JudgeResult(status="ok", findings=[], model="m",
                                      passes=2, calls=2, disagreements=0)

    def _judge(doc, det):
        return per_url.get(doc.final_url, per_url.get(doc.origin_url, fallback))

    return _judge


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
    assert methods <= {"rule_based", "external_state", "fixture", "judge"}
    assert "fixture" in methods  # registry/DNS findings kept their method
    # no --judge here -> no judge keys at all
    assert "judge_status" not in p and "judge" not in p


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


# ---------------------------------------------------------------------------
# --judge (v0.4 PR3) — fake judge, fully offline
# ---------------------------------------------------------------------------

def _fetch_both(body_llms, body_full):
    def _fetch(url):
        if url.endswith("/llms.txt"):
            return _served("https://acme.example/llms.txt", body_llms)
        if url.endswith("/llms-full.txt"):
            return _served("https://acme.example/llms-full.txt", body_full)
        return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")
    return _fetch


def test_judge_finding_raises_overall_risk_and_exit(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult
    jr = JudgeResult(status="ok", findings=[_judge_finding("I7", "high")], model="m",
                     passes=2, calls=2, disagreements=0)
    code, out = _run(monkeypatch, capsys, _fetch_fixture("benign/first-party-sdk-llms.txt"),
                     url="https://sdk.example.com", json_out=True,
                     judge_flag=True, api_key="k", fake_judge=make_judge(default=jr))
    p = json.loads(out)
    assert p["judge_status"] == "ok"
    assert p["semantic_coverage"] == "complete" and p["analysis_complete"] is True
    assert p["overall_risk"] == "high"          # deterministic was low
    assert p["exit_code"] == 2 and code == 2
    assert any(f["analysis_method"] == "judge" for f in p["findings"])
    assert p["judge"] == {"model": "m", "passes": 2, "calls": 2, "disagreements": 0}
    assert "WARNING" not in out


def test_judge_never_lowers_a_deterministic_critical(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult
    jr = JudgeResult(status="ok", findings=[], model="m", passes=2, calls=2, disagreements=0)
    code, out = _run(monkeypatch, capsys,
                     _fetch_fixture("malicious/onboarding-llms-full.txt", path="llms-full.txt"),
                     url="https://acme.example", json_out=True,
                     judge_flag=True, api_key="k", fake_judge=make_judge(default=jr))
    p = json.loads(out)
    assert p["overall_risk"] == "critical" and p["exit_code"] == 2 and code == 2
    assert p["judge_status"] == "ok"


def test_partial_judge_coverage_across_documents(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult
    ok = JudgeResult(status="ok", findings=[_judge_finding("I7", "medium")], model="m",
                     passes=2, calls=2, disagreements=0)
    failed = JudgeResult(status="unavailable:api_error", findings=[], model="m",
                         passes=2, calls=1, disagreements=0)
    per = {"https://acme.example/llms.txt": ok, "https://acme.example/llms-full.txt": failed}
    code, out = _run(monkeypatch, capsys,
                     _fetch_both(b"# a\npip install requests\n", b"# b\nnpm install chalk\n"),
                     url="https://acme.example", json_out=True,
                     judge_flag=True, api_key="k", fake_judge=make_judge(per_url=per))
    p = json.loads(out)
    assert p["judge_status"] == "partial"
    assert p["semantic_coverage"] == "partial" and p["analysis_complete"] is False
    assert p["judge"]["calls"] == 3  # 2 + 1
    doc_status = {d["requested_url"]: d["judge"]["status"] for d in p["documents"] if d["judge"]}
    assert doc_status["https://acme.example/llms.txt"] == "ok"
    assert doc_status["https://acme.example/llms-full.txt"] == "unavailable:api_error"
    assert any(f["analysis_method"] == "judge" for f in p["findings"])  # the OK doc's finding survived
    assert code != 3  # judge failure is not an operational failure

    _, term = _run(monkeypatch, capsys,
                   _fetch_both(b"# a\npip install requests\n", b"# b\nnpm install chalk\n"),
                   url="https://acme.example", judge_flag=True, api_key="k",
                   fake_judge=make_judge(per_url=per))
    assert "WARNING: --judge was requested but the semantic analysis did not fully complete" in term


def test_all_documents_judge_fail_is_not_exit_3(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult
    failed = JudgeResult(status="unavailable:api_error", findings=[], model="m",
                         passes=2, calls=1, disagreements=0)
    code, out = _run(monkeypatch, capsys, _fetch_fixture("suspicious/agent-tooling-llms.txt"),
                     url="https://aitools.example", json_out=True,
                     judge_flag=True, api_key="k", fake_judge=make_judge(default=failed))
    p = json.loads(out)
    assert p["judge_status"] == "unavailable:api_error"
    assert p["semantic_coverage"] == "incomplete" and p["analysis_complete"] is False
    assert p["operational_status"] == "ok"
    assert p["overall_risk"] == "medium" and p["exit_code"] == 1 and code == 1  # deterministic stands


def test_judge_pass_disagreement_finding_surfaced(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult
    jr = JudgeResult(status="ok", findings=[_judge_finding("I8", "high", "judge_pass_disagreement")],
                     model="m", passes=2, calls=2, disagreements=1)
    code, term = _run(monkeypatch, capsys, _fetch_fixture("benign/first-party-sdk-llms.txt"),
                      url="https://sdk.example.com", judge_flag=True, api_key="k",
                      fake_judge=make_judge(default=jr))
    assert "judge_pass_disagreement" in term
    assert "disagreement" in term.lower()
    assert "Semantic judge pass: OK" in term


def test_judge_without_api_key_is_unavailable_not_destructive(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # no fake_judge -> the REAL judge_document runs, finds no key
    code, out = _run(monkeypatch, capsys, _fetch_fixture("suspicious/agent-tooling-llms.txt"),
                     url="https://aitools.example", json_out=True, judge_flag=True)
    p = json.loads(out)
    assert p["judge_status"] == "unavailable:no_api_key"
    assert p["analysis_complete"] is False
    assert p["overall_risk"] == "medium" and p["exit_code"] == 1 and code == 1


def test_judge_default_off_leaves_result_and_report_unchanged(monkeypatch, capsys):
    # --judge absent: no judge_* keys anywhere, byte-identical to PR2
    code, out = _run(monkeypatch, capsys, _fetch_fixture("suspicious/agent-tooling-llms.txt"),
                     url="https://aitools.example", json_out=True)
    p = json.loads(out)
    assert "judge_status" not in p and "judge" not in p
    assert "semantic_coverage" not in p and "analysis_complete" not in p
    assert all("judge" not in d for d in p["documents"])
    assert "LLM judge" not in out or "no LLM judge" in out


def _fetch_findingless(url):
    # a served document with no install commands and no referenced domains ->
    # the deterministic lane produces zero findings
    if url.endswith("/llms.txt"):
        return _served("https://plain.example/llms.txt", b"# Plain docs\n\nJust prose, nothing to install.\n")
    return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")


def test_no_findings_sentence_is_the_pinned_wording_without_judge(monkeypatch, capsys):
    code, term = _run(monkeypatch, capsys, _fetch_findingless, url="https://plain.example")
    assert "No rule-based or registry/DNS findings." in term
    assert "No findings from any lane that ran." not in term


def test_no_findings_sentence_widens_only_when_a_semantic_lane_ran(monkeypatch, capsys):
    from scanner.remote_judge import JudgeResult

    ran = JudgeResult(status="ok", findings=[], model="m", passes=2, calls=2, disagreements=0)
    _, term = _run(monkeypatch, capsys, _fetch_findingless, url="https://plain.example",
                   judge_flag=True, api_key="k", fake_judge=make_judge(default=ran))
    assert "No findings from any lane that ran." in term
    assert "No rule-based or registry/DNS findings." not in term

    # judge requested but unavailable -> keep the deterministic wording; the
    # coverage WARNING explains the judge did not run
    failed = JudgeResult(status="unavailable:api_error", findings=[], model="m",
                         passes=2, calls=1, disagreements=0)
    _, term2 = _run(monkeypatch, capsys, _fetch_findingless, url="https://plain.example",
                    judge_flag=True, api_key="k", fake_judge=make_judge(default=failed))
    assert "No rule-based or registry/DNS findings." in term2
    assert "No findings from any lane that ran." not in term2
    assert "WARNING: --judge was requested" in term2


def test_zero_documents_plus_judge_is_skipped_and_exit_3(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _fetch_all_404, json_out=True,
                     judge_flag=True, api_key="k", fake_judge=make_judge())
    p = json.loads(out)
    assert p["judge_status"] == "skipped:no_documents"
    assert p["semantic_coverage"] == "incomplete" and p["analysis_complete"] is False
    assert p["operational_status"] == "not_found"
    assert p["overall_risk"] is None and p["exit_code"] == 3 and code == 3
