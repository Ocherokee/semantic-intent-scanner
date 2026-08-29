"""
llms.txt / llms-full.txt adapter for the remote-content audit engine.

This is a thin entrypoint: it knows the two conventional paths a site
publishes agent-facing documentation at, fetches them through the
SSRF-hardened fetcher, and hands each served document to the
format-agnostic :func:`scanner.remote_audit.analyze_document`.

Background: sites publish ``/llms.txt`` (and an expanded ``/llms-full.txt``)
to tell AI agents how to use them. A poisoned one can list an install
command for an unregistered package, or reference a domain nobody owns;
an attacker claims the empty slot later and every agent that followed the
file is running attacker code. (Ars Technica, 2026-08-27: 227 such
commands across 120 misconfigured files, some executed inside Fortune 500
networks.)

Nothing here executes a command or installs anything.
"""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

from .registry import RegistryClient
from .remote_audit import (
    Finding,
    RemoteDocument,
    analyze_document,
    findings_as_dicts,
    overall_risk,
)
from .remote_fetch import FetchOutcome, guarded_fetch

CANDIDATE_PATHS = ("llms.txt", "llms-full.txt")

Fetcher = Callable[[str], FetchOutcome]
# (RemoteDocument, deterministic findings) -> a JudgeResult-shaped object with
# .status / .findings / .model / .passes / .calls / .disagreements
Judge = Callable[[RemoteDocument, "list[Finding]"], Any]


def candidate_urls(target: str) -> list[str]:
    """Expand a URL or bare domain into the llms.txt URLs to try."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path.strip("/")
    if path in CANDIDATE_PATHS:
        return [f"https://{host}{port}/{path}"]
    return [f"https://{host}{port}/{p}" for p in CANDIDATE_PATHS]


def audit_llms_txt(
    target: str,
    *,
    registry: RegistryClient | None = None,
    fetch: Fetcher | None = None,
    judge: Judge | None = None,
) -> dict[str, Any]:
    """
    Audit the llms.txt surface for ``target`` (a URL or a bare domain).

    ``fetch(url) -> FetchOutcome`` is injectable for tests; the default is
    the SSRF-hardened :func:`scanner.remote_fetch.guarded_fetch`.

    Returns a dict shaped like ``directory_audit.audit_directory``:
    ``{surface, source, documents[], retrieved, findings[], overall_risk}``.
    ``retrieved`` is the count of candidate documents that were actually
    served (HTTP 200, no error) — a caller uses it to tell "scanned and
    found nothing" apart from "nothing could be fetched".

    ``judge`` (v0.4 PR3): an optional ``(RemoteDocument, deterministic
    findings) -> JudgeResult`` callable. When ``judge is None`` (default) the
    code path and result are **identical** to the deterministic-only scan —
    no ``judge*`` keys are added. When provided, the two-pass semantic pass
    runs over each served document; successful judge findings are merged into
    ``findings`` (append-only), ``overall_risk`` is recomputed over the union,
    and ``judge_status`` / ``judge`` / per-document ``documents[].judge`` are
    added (see docs/v0.4-pr3-judge-scoping.md).
    """
    registry = registry or RegistryClient()
    fetch = fetch or guarded_fetch

    outcomes = [fetch(url) for url in candidate_urls(target)]
    served = [o for o in outcomes if o.ok]
    result: dict[str, Any] = {
        "surface": "llms_txt",
        "source": target,
        "documents": [_document_summary(o) for o in outcomes],
        "retrieved": len(served),
        "findings": [],
        "overall_risk": "low",
    }

    if not served:
        blocked = [o.blocked_reason for o in outcomes if o.blocked_reason]
        result["note"] = (
            "fetch blocked by SSRF guard: " + "; ".join(blocked)
            if blocked
            else "no llms.txt or llms-full.txt served (the common, safe case)"
        )
        if judge is not None:
            result["judge_status"] = "skipped:no_documents"
            result["semantic_coverage"] = "incomplete"
        return result

    det_findings: list[Finding] = []
    per_doc_judge: dict[str, Any] = {}  # requested_url -> JudgeResult
    for outcome in served:
        doc = RemoteDocument.from_fetch_outcome(outcome)
        d = analyze_document(doc, registry)
        det_findings.extend(d)
        if judge is not None:
            per_doc_judge[outcome.requested_url] = judge(doc, d)

    all_findings = list(det_findings)
    if judge is not None:
        for jr in per_doc_judge.values():
            if getattr(jr, "status", None) == "ok":
                all_findings.extend(jr.findings)
        _attach_judge(result, per_doc_judge)

    result["findings"] = findings_as_dicts(all_findings)
    result["overall_risk"] = overall_risk(all_findings)
    return result


def _rollup_judge_status(judge_results: list[Any]) -> str:
    statuses = [getattr(jr, "status", "unavailable:api_error") for jr in judge_results]
    if not statuses:
        return "ok"
    if all(s == "ok" for s in statuses):
        return "ok"
    if any(s == "ok" for s in statuses):
        return "partial"
    distinct = set(statuses)
    return distinct.pop() if len(distinct) == 1 else "partial"


def _coverage_for(judge_status: str) -> str:
    """Coarse 'did the requested semantic analysis complete?' signal, easy for
    CI to gate on. Separate from judge_status (which carries the reason)."""
    if judge_status == "ok":
        return "complete"
    if judge_status == "partial":
        return "partial"
    return "incomplete"  # unavailable:* or skipped:*


def _attach_judge(result: dict[str, Any], per_doc_judge: dict[str, Any]) -> None:
    jrs = list(per_doc_judge.values())
    result["judge_status"] = _rollup_judge_status(jrs)
    result["semantic_coverage"] = _coverage_for(result["judge_status"])
    model = next((getattr(jr, "model", None) for jr in jrs if getattr(jr, "model", None)), None)
    result["judge"] = {
        "model": model,
        "passes": 2,
        "calls": sum(int(getattr(jr, "calls", 0) or 0) for jr in jrs),
        "disagreements": sum(int(getattr(jr, "disagreements", 0) or 0) for jr in jrs),
    }
    for dsumm in result["documents"]:
        jr = per_doc_judge.get(dsumm["requested_url"])
        if dsumm["status"] == 200 and jr is not None:
            dsumm["judge"] = {
                "status": getattr(jr, "status", None),
                "findings": len(getattr(jr, "findings", []) or []),
                "calls": int(getattr(jr, "calls", 0) or 0),
                "disagreements": int(getattr(jr, "disagreements", 0) or 0),
            }
        else:
            dsumm["judge"] = None


def _document_summary(o: FetchOutcome) -> dict:
    return {
        "requested_url": o.requested_url,
        "final_url": o.final_url,
        "status": o.status,
        "content_type": o.content_type,
        "sha256": o.sha256,
        "fetched_at": o.fetched_at,
        "bytes": len(o.body),
        "redirect_chain": o.redirect_chain,
        "cross_origin_redirect": o.cross_origin_redirect,
        "truncated": o.truncated,
        "error": o.error,
        "blocked_reason": o.blocked_reason,
    }


if __name__ == "__main__":  # pragma: no cover - manual poke, not the CLI
    import json
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m scanner.llms_txt <url-or-domain>", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(audit_llms_txt(sys.argv[1]), indent=2))
