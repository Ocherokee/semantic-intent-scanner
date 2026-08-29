"""
Shared helpers for the remote-content audit surfaces.

Both ``scanner.llms_txt`` (retrieved HTTP documents) and
``scanner.mcp_adapter`` (MCP tool definitions from a file) run the same
deterministic + optional two-pass-judge pipeline and roll the per-document
:class:`scanner.remote_judge.JudgeResult` objects up into the result dict in
exactly the same way. That roll-up logic lives here so neither adapter has to
import the other.

Nothing here fetches, executes, or trusts anything.
"""

from __future__ import annotations

from typing import Any


def rollup_judge_status(judge_results: list[Any]) -> str:
    """
    Collapse per-document judge statuses into one:

      * every document judged ok          -> ``"ok"``
      * some ok, some not                  -> ``"partial"``
      * none ok, all failed the same way   -> that ``"unavailable:<reason>"``
      * none ok, mixed failure reasons     -> ``"partial"``
    """
    statuses = [getattr(jr, "status", "unavailable:api_error") for jr in judge_results]
    if not statuses:
        return "ok"
    if all(s == "ok" for s in statuses):
        return "ok"
    if any(s == "ok" for s in statuses):
        return "partial"
    distinct = set(statuses)
    return distinct.pop() if len(distinct) == 1 else "partial"


def coverage_for(judge_status: str) -> str:
    """Coarse 'did the requested semantic analysis complete?' signal, easy for
    CI to gate on. Separate from judge_status (which carries the reason)."""
    if judge_status == "ok":
        return "complete"
    if judge_status == "partial":
        return "partial"
    return "incomplete"  # unavailable:* or skipped:*


def attach_judge(result: dict[str, Any], per_doc_judge: dict[str, Any]) -> None:
    """
    Mutate ``result`` in place with the judge roll-up:

      * ``result["judge_status"]`` / ``result["semantic_coverage"]``
      * ``result["judge"]`` = ``{model, passes, calls, disagreements}`` (summed
        over documents; ``calls`` is the *actual* API-call count)
      * ``documents[].judge`` = ``{status, findings, calls, disagreements}`` or
        ``None`` for a document that was not judged

    ``per_doc_judge`` is keyed by the same string that appears as each
    document summary's ``requested_url``.
    """
    jrs = list(per_doc_judge.values())
    result["judge_status"] = rollup_judge_status(jrs)
    result["semantic_coverage"] = coverage_for(result["judge_status"])
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
