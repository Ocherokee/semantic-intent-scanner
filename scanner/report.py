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
        "version": "0.1.0",
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
