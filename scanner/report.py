"""
Report generator for the Semantic Intent Scanner.
Produces both markdown (terminal) and JSON output from evaluation results.
"""

import json
from datetime import datetime, timezone
from typing import Any

from .invariants import INVARIANT_MAP

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
RESET = "\033[0m"
BOLD = "\033[1m"


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
        "version": "0.3.0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
