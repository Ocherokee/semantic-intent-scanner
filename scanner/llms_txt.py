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
from .remote_audit import RemoteDocument, analyze_document, findings_as_dicts, overall_risk
from .remote_fetch import FetchOutcome, guarded_fetch

CANDIDATE_PATHS = ("llms.txt", "llms-full.txt")

Fetcher = Callable[[str], FetchOutcome]


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
) -> dict[str, Any]:
    """
    Audit the llms.txt surface for ``target`` (a URL or a bare domain).

    ``fetch(url) -> FetchOutcome`` is injectable for tests; the default is
    the SSRF-hardened :func:`scanner.remote_fetch.guarded_fetch`.

    Returns a dict shaped like ``directory_audit.audit_directory``:
    ``{surface, source, documents[], findings[], overall_risk}``.
    """
    registry = registry or RegistryClient()
    fetch = fetch or guarded_fetch

    outcomes = [fetch(url) for url in candidate_urls(target)]
    result: dict[str, Any] = {
        "surface": "llms_txt",
        "source": target,
        "documents": [_document_summary(o) for o in outcomes],
        "findings": [],
        "overall_risk": "low",
    }

    served = [o for o in outcomes if o.ok]
    if not served:
        blocked = [o.blocked_reason for o in outcomes if o.blocked_reason]
        result["note"] = (
            "fetch blocked by SSRF guard: " + "; ".join(blocked)
            if blocked
            else "no llms.txt or llms-full.txt served (the common, safe case)"
        )
        return result

    findings = []
    for outcome in served:
        findings.extend(analyze_document(RemoteDocument.from_fetch_outcome(outcome), registry))

    result["findings"] = findings_as_dicts(findings)
    result["overall_risk"] = overall_risk(findings)
    return result


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
