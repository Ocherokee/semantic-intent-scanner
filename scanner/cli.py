#!/usr/bin/env python3
"""
semantic-intent-scanner CLI

Usage:
    semantic-intent scan <path>            Scan a SKILL.md file
    semantic-intent scan <path> --json     Output JSON report
    semantic-intent scan <path> --no-color Plain text output
"""

import argparse
import sys
from pathlib import Path

from .evaluator import evaluate_skill
from .report import render_json_report, render_terminal_report


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    if not path.is_file():
        print(f"Error: not a file: {path}", file=sys.stderr)
        return 1

    skill_text = path.read_text(encoding="utf-8")

    if not skill_text.strip():
        print(f"Error: file is empty: {path}", file=sys.stderr)
        return 1

    print(f"Scanning {path}...", file=sys.stderr)

    results = evaluate_skill(skill_text, api_key=args.api_key)

    if args.json:
        print(render_json_report(results, str(path)))
    else:
        print(render_terminal_report(
            results,
            str(path),
            colorize=not args.no_color,
        ))

    # Exit code reflects risk level for use in CI/CD pipelines
    risk = results.get("overall_risk", "low")
    if risk in ("critical", "high"):
        return 2
    if risk == "medium":
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="semantic-intent",
        description="Semantic Intent Scanner — evaluates SKILL.md files against invariant constraints",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a SKILL.md file")
    scan_parser.add_argument("path", help="Path to SKILL.md file")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON report")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    scan_parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))


if __name__ == "__main__":
    main()
