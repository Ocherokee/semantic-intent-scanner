"""
Report generator for the Semantic Intent Scanner.
Produces both markdown (terminal) and JSON output from evaluation results.
"""

import json
from datetime import datetime, timezone
from typing import Any

from .invariants import INVARIANT_MAP
from .remote_fetch import MAX_BODY_BYTES

# Scanner version emitted in JSON output as "version". Kept in step with the
# package version in pyproject.toml by hand.
SCANNER_VERSION = "1.0.0"

# KiB form of the guarded-fetch body cap, for display in the remote report.
_BODY_LIMIT_KB = MAX_BODY_BYTES // 1024

# ---------------------------------------------------------------------------
# Risk display
# ---------------------------------------------------------------------------

RISK_COLORS = {
    "low": "\033[32m",       # green
    "medium": "\033[33m",    # yellow
    "high": "\033[91m",      # bright red
    "critical": "\033[41m",  # red background
    "parse_error": "\033[35m",  # magenta
}
RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RESET = "\033[0m"
BOLD = "\033[1m"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _risk_label(risk: str, colorize: bool = True) -> str:
    if not colorize:
        return risk.upper()
    color = RISK_COLORS.get(risk, "")
    return f"{color}{BOLD}{risk.upper()}{RESET}"


# ---------------------------------------------------------------------------
# Markdown report (terminal)
# ---------------------------------------------------------------------------

def render_terminal_report(
    results: dict[str, Any],
    skill_path: str,
    colorize: bool = True,
) -> str:
    lines = []
    risk = results.get("overall_risk", "unknown")
    violations = results.get("violations", [])
    chunk_count = results.get("chunk_count", 0)

    lines.append("")
    lines.append(f"{BOLD}Semantic Intent Scanner{RESET}" if colorize else "Semantic Intent Scanner")
    lines.append(f"File: {skill_path}")
    lines.append(f"Chunks evaluated: {chunk_count}")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")
    lines.append(f"Risk: {_risk_label(risk, colorize)}")
    lines.append("")

    if not violations:
        lines.append("No invariant violations detected.")
        lines.append("")
        lines.append(
            "Note: A clean scan does not certify this skill is safe. "
            "It indicates no known semantic threat patterns were detected."
        )
    else:
        lines.append(f"Invariant violations ({len(violations)} found):")
        lines.append("")
        for v in violations:
            inv_id = v.get("invariant_id", "?")
            inv = INVARIANT_MAP.get(inv_id, {})
            inv_name = inv.get("name", "Unknown")
            verdict = v.get("verdict", "?")
            confidence = v.get("confidence", 0.0)
            flagged = v.get("flagged_text")
            reasoning = v.get("reasoning", "")

            verdict_str = f"[{verdict}]" if not colorize else (
                f"\033[91m[{verdict}]{RESET}" if verdict == "likely"
                else f"\033[33m[{verdict}]{RESET}"
            )

            lines.append(f"  {inv_id}: {inv_name} — {verdict_str} (confidence: {confidence:.0%})")
            if flagged:
                lines.append(f"     Flagged:   \"{flagged}\"")
            if reasoning:
                lines.append(f"     Reason:    {reasoning}")
            mechanisms = v.get("mechanism_failure", [])
            bridge = v.get("mechanism_bridge", "")
            if mechanisms:
                lines.append(f"     Mechanism: {', '.join(mechanisms)}")
            if bridge:
                lines.append(f"     Why:       {bridge}")
            lines.append("")

    lines.append("")
    lines.append("─" * 60)
    lines.append(
        "This scanner evaluates semantic intent against invariant constraints. "
        "It does not replace human review for high-risk or production deployments."
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def render_json_report(
    results: dict[str, Any],
    skill_path: str,
) -> str:
    report = {
        "scanner": "semantic-intent-scanner",
        "version": SCANNER_VERSION,
        "timestamp": _utc_now(),
        "file": skill_path,
        "overall_risk": results.get("overall_risk"),
        "violation_count": len(results.get("violations", [])),
        "violations": results.get("violations", []),
        "chunks_evaluated": results.get("chunk_count", 0),
        "disclaimer": (
            "A clean scan does not certify this skill is safe. "
            "This tool evaluates semantic intent against invariant constraints "
            "and does not replace human review."
        ),
    }
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# Directory audit report
# ---------------------------------------------------------------------------

def render_directory_report(
    dir_results: dict[str, Any],
    semantic_results: dict[str, Any] | None,
    colorize: bool = True,
) -> str:
    lines = []
    dir_risk = dir_results.get("overall_directory_risk", "low")
    suspicious_files = dir_results.get("suspicious_files", [])
    config_findings = dir_results.get("config_findings", [])

    lines.append("")
    lines.append(f"{BOLD}Semantic Intent Scanner — Directory Audit{RESET}" if colorize else "Semantic Intent Scanner — Directory Audit")
    lines.append(f"Directory: {dir_results.get('directory', '?')}")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")
    lines.append(f"Directory Risk: {_risk_label(dir_risk, colorize)}")
    lines.append("")

    # Suspicious files
    if suspicious_files:
        lines.append(f"Suspicious files found ({len(suspicious_files)}):")
        lines.append("")
        for f in suspicious_files:
            risk = f.get("risk", "medium")
            risk_str = _risk_label(risk, colorize)
            lines.append(f"  {f.get('path', '?')} — {risk_str}")
            lines.append(f"     Type:   {f.get('type', '?')}")
            lines.append(f"     Reason: {f.get('reason', '')}")
            patterns = f.get("dangerous_patterns", [])
            if patterns:
                categories = list({p["category"] for p in patterns})
                lines.append(f"     Patterns detected: {', '.join(categories)}")
            lines.append("")
    else:
        lines.append("No suspicious files detected in skill directory.")
        lines.append("")

    # Config findings
    if config_findings:
        lines.append(f"Config file findings ({len(config_findings)}):")
        lines.append("")
        for c in config_findings:
            risk = c.get("risk", "low")
            risk_str = _risk_label(risk, colorize)
            lines.append(f"  {c.get('path', '?')} — {risk_str}")
            lines.append(f"     {c.get('reason', '')}")
            dangerous = c.get("dangerous_settings", [])
            if dangerous:
                lines.append(f"     Dangerous settings: {', '.join(dangerous)}")
            lines.append("")

    # Semantic evaluation summary if present
    if semantic_results:
        sem_risk = semantic_results.get("overall_risk", "low")
        violations = semantic_results.get("violations", [])
        lines.append("─" * 60)
        lines.append("")
        lines.append(f"Semantic Evaluation (SKILL.md): {_risk_label(sem_risk, colorize)}")
        if violations:
            lines.append(f"{len(violations)} invariant violation(s) detected — run file scan for details.")
        else:
            lines.append("No invariant violations detected in instruction file.")
        lines.append("")

    lines.append("─" * 60)
    lines.append(
        "Directory audit checks non-instruction attack surfaces: test files, "
        "config files, and bundled executables. It does not replace semantic "
        "evaluation of instruction content."
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remote content audit report  (v0.4 `scan-remote`)
# ---------------------------------------------------------------------------

_REMOTE_FOOTER = (
    "This scan performs rule-based + external-state (registry / DNS) analysis "
    "only. The semantic judge pass over retrieved content is not part of this "
    "scan. A low result means no rule-based or registry/DNS finding - not a "
    "safety guarantee. Registry existence is never treated as legitimacy."
)
_REMOTE_FOOTER_JUDGE = (
    "This scan performs rule-based + external-state (registry / DNS) analysis "
    "and a two-pass LLM judge over the retrieved content. A low result is not "
    "a safety guarantee; the judge may miss manipulation and a judge failure "
    "leaves only the deterministic result. Registry existence is never treated "
    "as legitimacy; retrieved content is evaluated as untrusted evidence, "
    "never followed as instruction."
)
_MCP_FOOTER = (
    "This scan reads MCP tool definitions from a file and evaluates every "
    "description field against the invariant set (rule-based + external-state, "
    "plus the two-pass judge with --judge). No MCP server is contacted and no "
    "tool is invoked. A tool description is untrusted external content, never "
    "authoritative instruction; a low result is not a safety guarantee."
)


def _remote_footer(results: dict[str, Any]) -> str:
    if results.get("surface") == "mcp":
        return _MCP_FOOTER
    return _REMOTE_FOOTER_JUDGE if results.get("judge_status") not in (None, "skipped:no_documents") else _REMOTE_FOOTER

_OPERATIONAL_MESSAGES = {
    "fetch_blocked": "Every candidate document was refused by the fetch guard.",
    "not_found": "No candidate document was served (all returned 404 / not found).",
    "fetch_failed": "Every candidate fetch failed.",
    "invalid_input": "The input is not valid JSON or not a recognised tools/list shape.",
    "no_tools": "The input parsed, but no tool definitions were found to evaluate.",
}


def remote_operational_status(results: dict[str, Any]) -> str:
    """
    Classify an ``audit_llms_txt`` / ``audit_mcp_tools`` result.

    "ok"            -> at least one document / tool was analysed
    "fetch_blocked" -> (llms.txt) nothing retrieved; an attempt hit the SSRF guard
    "not_found"     -> (llms.txt) nothing retrieved; every attempt 404 / not served
    "fetch_failed"  -> (llms.txt) nothing retrieved; some other fetch error
    "invalid_input" -> (mcp) the file is not valid JSON / not a tools/list shape
    "no_tools"      -> (mcp) the file parsed but held no tool definitions

    The exit code is the same in every non-"ok" case (3, "nothing analysed");
    only the vocabulary differs so an MCP failure does not report HTTP words.
    """
    if results.get("retrieved", 0) > 0:
        return "ok"
    if results.get("surface") == "mcp":
        return "invalid_input" if results.get("parse_error") else "no_tools"
    docs = results.get("documents", [])
    if any(d.get("blocked_reason") for d in docs):
        return "fetch_blocked"
    if docs and all(d.get("status") == 404 for d in docs):
        return "not_found"
    return "fetch_failed"


def remote_exit_code(results: dict[str, Any]) -> int:
    """
    0 low / 1 medium / 2 high|critical - the existing risk convention.
    3 = nothing could be scanned (every fetch failed / was blocked / not found).
    A failed scan is never reported as exit 0 / low risk.
    """
    if remote_operational_status(results) != "ok":
        return 3
    return {"low": 0, "medium": 1, "high": 2, "critical": 2}.get(
        results.get("overall_risk", "low"), 0
    )


def _remote_doc_line(d: dict[str, Any]) -> str:
    url = d.get("requested_url", "?")
    if d.get("blocked_reason"):
        return f"{url}  BLOCKED - {d['blocked_reason']}"
    status = d.get("status")
    if status == 200:
        sha = (d.get("sha256") or "")[:12]
        flags = ""
        if d.get("cross_origin_redirect"):
            flags += "  [cross-origin redirect]"
        if d.get("truncated"):
            flags += f"  [truncated @ {_BODY_LIMIT_KB} KB]"
        return f"{url}  200  sha256:{sha}...  {d.get('fetched_at', '?')}{flags}"
    if status:
        return f"{url}  {status}  (not served)"
    label = "MALFORMED" if d.get("kind") == "mcp_tool" else "FETCH FAILED"
    return f"{url}  {label} - {d.get('error') or 'unknown error'}"


def _remote_finding_block(f: dict[str, Any], colorize: bool) -> list[str]:
    out = [
        f"  [{_risk_label(f.get('risk', '?'), colorize)}] "
        f"{f.get('invariant_id', '?')}  {f.get('finding_type', '?')}",
        f"     Summary:    {f.get('summary', '')}",
    ]
    if f.get("evidence"):
        out.append(f"     Evidence:   {f['evidence']}")
    meta = f"Method: {f.get('analysis_method', '?')}"
    if f.get("provenance_state"):
        meta += f"   Provenance: {f['provenance_state']}"
    if f.get("observed_at"):
        meta += f"   Observed: {f['observed_at']}"
    out.append(f"     {meta}")
    detail = f.get("detail") or {}
    if f.get("finding_type") == "judge_pass_disagreement":
        p1 = (detail.get("pass1") or {}).get("verdict", "?")
        p2 = (detail.get("pass2") or {}).get("verdict", "?")
        out.append(f"     Passes:     Pass 1 said {p1}; Pass 2 said {p2} (disagreement -> escalated)")
    if detail.get("source_url"):
        out.append(f"     Source:     {detail['source_url']}")
    out.append("")
    return out


def _remote_judge_lines(results: dict[str, Any], colorize: bool) -> list[str]:
    """The 'Semantic judge pass' block. Empty when --judge was not used."""
    status = results.get("judge_status")
    if status is None:
        return []
    b, r = (BOLD, RESET) if colorize else ("", "")
    coverage = results.get("semantic_coverage", "incomplete")
    j = results.get("judge") or {}

    def _warn() -> list[str]:
        if coverage == "complete":
            return []
        reason = status if status != "partial" else "partial coverage across the retrieved documents"
        return [
            "",
            f"{b}WARNING: --judge was requested but the semantic analysis did not fully complete{r}",
            f"         (judge_status: {status}; semantic_coverage: {coverage}).",
            "         The deterministic risk and exit code below are unaffected;"
            " only the semantic pass is incomplete.",
        ]

    if status.startswith("skipped"):
        return ["", f"{b}Semantic judge pass:{r} SKIPPED (no document to evaluate)"] + _warn()

    label = {"ok": "OK", "partial": "PARTIAL"}.get(status, "UNAVAILABLE")
    detail = ""
    if status not in ("ok", "partial"):
        detail = f" ({status.split(':', 1)[-1]})"
    head = (
        f"{b}Semantic judge pass:{r} {label}{detail}"
        f"  (model {j.get('model', '?')}, {j.get('passes', 2)} passes, "
        f"{j.get('calls', 0)} API call(s), {j.get('disagreements', 0)} disagreement(s))"
    )
    lines = ["", head]
    for d in results.get("documents", []):
        dj = d.get("judge")
        if d.get("status") == 200 and dj:
            st = dj.get("status", "?")
            mark = "OK" if st == "ok" else f"UNAVAILABLE ({st.split(':', 1)[-1]})"
            lines.append(f"  {d.get('requested_url', '?')}   judged: {mark}")
    return lines + _warn()


def _remote_notes(docs: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for d in docs:
        ref = d.get("final_url") or d.get("requested_url", "?")
        if d.get("truncated"):
            notes.append(
                f"{ref} was truncated at the {_BODY_LIMIT_KB} KB body limit; "
                "findings from it may be incomplete."
            )
        if d.get("cross_origin_redirect"):
            chain = " -> ".join(h.get("url", "?") for h in d.get("redirect_chain", []))
            notes.append(f"cross-origin redirect followed: {chain or ref}")
    return notes


def render_remote_report(
    results: dict[str, Any],
    target: str,
    colorize: bool = True,
) -> str:
    b, r = (BOLD, RESET) if colorize else ("", "")
    docs = results.get("documents", [])
    findings = results.get("findings", [])
    status = remote_operational_status(results)

    is_mcp = results.get("surface") == "mcp"
    title = "MCP Tool-Description Audit" if is_mcp else "Remote Content Audit"
    mode_kind = "mcp" if is_mcp else "remote"
    attempted_label = "Tools evaluated" if is_mcp else "Documents attempted"
    retrieved_label = "Parsed" if is_mcp else "Retrieved"
    subject = "tool" if is_mcp else "document"

    mode = "rule-based + external-state (registry / DNS)"
    if results.get("judge_status") is not None:
        mode += " + two-pass LLM judge over " + ("tool descriptions" if is_mcp else "retrieved content")
    else:
        mode += "; no LLM judge"
    lines = [
        "",
        f"{b}Semantic Intent Scanner - {title}{r}",
        f"Target: {target}",
        f"Timestamp: {_utc_now()}",
        f"Mode: {mode_kind} - {mode}",
        "",
        f"{attempted_label} ({len(docs)}):",
    ]
    lines += [f"  {_remote_doc_line(d)}" for d in docs]
    lines += ["", f"{retrieved_label}: {results.get('retrieved', 0)} / {len(docs)}"]

    if status != "ok":
        header = "OPERATIONAL FAILURE"
        lines += [
            "",
            f"{b}{header}{r}" if colorize else header,
            f"Nothing was scanned. {_OPERATIONAL_MESSAGES.get(status, '')}".rstrip(),
            "This is NOT a low-risk result - exit code 3.",
            "",
            "-" * 60,
            _remote_footer(results),
            "",
        ]
        return "\n".join(lines)

    lines += _remote_judge_lines(results, colorize)

    lines += ["", f"Overall risk: {_risk_label(results.get('overall_risk', 'low'), colorize)}", ""]

    if not findings:
        # The deterministic wording is the pinned default. Only widen it when a
        # semantic lane actually ran (ok / partial) — a requested-but-unavailable
        # judge keeps the deterministic sentence and lets the coverage WARNING
        # explain that the judge did not run.
        if results.get("judge_status") in ("ok", "partial"):
            lines.append("No findings from any lane that ran.")
        else:
            lines.append("No rule-based or registry/DNS findings.")
    else:
        ordered = sorted(findings, key=lambda f: -RISK_RANK.get(f.get("risk", "low"), 0))
        lines.append(f"Findings ({len(findings)}), worst first:")
        lines.append("")
        for f in ordered:
            lines += _remote_finding_block(f, colorize)

    notes = _remote_notes(docs)
    if notes:
        lines.append("")
        lines.append("Notes:")
        lines += [f"  - {n}" for n in notes]

    lines += ["", "-" * 60, _remote_footer(results), ""]
    return "\n".join(lines)


def _remote_doc_json(d: dict[str, Any]) -> dict[str, Any]:
    out = {
        "requested_url": d.get("requested_url"),
        "final_url": d.get("final_url"),
        "status": d.get("status"),
        "fetched_at": d.get("fetched_at"),
        "sha256": d.get("sha256"),
        "content_type": d.get("content_type"),
        "bytes": d.get("bytes"),
        "redirect_chain": d.get("redirect_chain", []),
        "cross_origin_redirect": d.get("cross_origin_redirect", False),
        "truncated": d.get("truncated", False),
        "error": d.get("error"),
        "blocked_reason": d.get("blocked_reason"),
    }
    if d.get("kind") == "mcp_tool":
        out["mcp_tool"] = d.get("mcp_tool")
        out["mcp_fields"] = d.get("mcp_fields", [])
        out["mcp_json_paths"] = d.get("mcp_json_paths", [])
    if "judge" in d:
        out["judge"] = d["judge"]   # {status, findings, calls, disagreements} | None
    return out


def render_remote_json_report(results: dict[str, Any], target: str) -> str:
    status = remote_operational_status(results)
    scanned = status == "ok"
    docs = results.get("documents", [])
    is_mcp = results.get("surface") == "mcp"
    report = {
        "scanner": "semantic-intent-scanner",
        "version": SCANNER_VERSION,
        "scan_mode": "mcp" if is_mcp else "remote",
        "target": target,
        "timestamp": _utc_now(),
        "operational_status": status,
        "exit_code": remote_exit_code(results),
        "overall_risk": results.get("overall_risk") if scanned else None,
        "documents_attempted": len(docs),
        "documents_retrieved": results.get("retrieved", 0),
        "documents": [_remote_doc_json(d) for d in docs],
        "finding_count": len(results.get("findings", [])),
        "findings": results.get("findings", []),
        "disclaimer": _remote_footer(results),
    }
    if is_mcp:
        report["mcp_server"] = results.get("mcp_server", {"declared": None, "authenticated": False})
    if results.get("judge_status") is not None:
        report["judge_status"] = results["judge_status"]
        report["semantic_coverage"] = results.get("semantic_coverage", "incomplete")
        report["analysis_complete"] = report["semantic_coverage"] == "complete"
        if "judge" in results:
            report["judge"] = results["judge"]
    return json.dumps(report, indent=2)
