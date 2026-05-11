#!/usr/bin/env python3
"""
semantic-intent-scanner CLI

Usage:
    semantic-intent scan <path>            Scan a SKILL.md file
    semantic-intent scan <path> --dir      Scan entire skill directory
    semantic-intent scan <path> --json     Output JSON report
    semantic-intent scan <path> --no-color Plain text output
"""

import argparse
import json
import sys
from pathlib import Path

from .directory_audit import audit_directory
from .evaluator import evaluate_skill
from .report import render_directory_report, render_json_report, render_terminal_report


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)

    if not path.exists():
        print(f"Error: path not found: {path}", file=sys.stderr)
        return 1

    if args.dir or path.is_dir():
        return cmd_scan_directory(path, args)

    return cmd_scan_file(path, args)


def cmd_scan_file(path: Path, args: argparse.Namespace) -> int:
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

    risk = results.get("overall_risk", "low")
    if risk in ("critical", "high"):
        return 2
    if risk == "medium":
        return 1
    return 0


def cmd_scan_directory(path: Path, args: argparse.Namespace) -> int:
    print(f"Auditing directory {path}...", file=sys.stderr)

    dir_results = audit_directory(path)

    semantic_results = None
    skill_md = path / "SKILL.md"
    if not skill_md.exists():
        for name in ["skill.md", "Skill.md", "README.md"]:
            candidate = path / name
            if candidate.exists():
                skill_md = candidate
                break

    if skill_md and skill_md.exists():
        print(f"Found {skill_md.name} — running semantic evaluation...", file=sys.stderr)
        skill_text = skill_md.read_text(encoding="utf-8")
        if skill_text.strip():
            semantic_results = evaluate_skill(skill_text, api_key=args.api_key)

    if args.json:
        combined = {
            "directory_audit": dir_results,
            "semantic_evaluation": semantic_results,
        }
        print(json.dumps(combined, indent=2))
    else:
        print(render_directory_report(
            dir_results,
            semantic_results,
            colorize=not args.no_color,
        ))

    dir_risk = dir_results.get("overall_directory_risk", "low")
    sem_risk = semantic_results.get("overall_risk", "low") if semantic_results else "low"

    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    worst = max(risk_order.get(dir_risk, 0), risk_order.get(sem_risk, 0))

    if worst >= 2:
        return 2
    if worst == 1:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="semantic-intent",
        description="Semantic Intent Scanner — evaluates AI agent skill files against invariant constraints",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a SKILL.md file or skill directory")
    scan_parser.add_argument("path", help="Path to SKILL.md file or skill directory")
    scan_parser.add_argument("--dir", action="store_true", help="Scan entire directory")
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
