#!/usr/bin/env python3
"""
semantic-intent-scanner CLI

Usage:
    semantic-intent scan <path>            Scan a SKILL.md file
    semantic-intent scan <path> --dir      Scan entire skill directory
    semantic-intent scan <path> --json     Output JSON report
    semantic-intent scan <path> --no-color Plain text output

    semantic-intent scan-remote <url>          Scan a site's llms.txt / llms-full.txt
    semantic-intent scan-remote <url> --json   Output JSON report

    semantic-intent inventory <url>            Inventory public agent-readable surfaces as JSON
    semantic-intent inventory-diff <previous.json> <current.json>
                                                Compare two inventory artifacts offline
    semantic-intent trust-analyze <inventory.json>
                                                Analyze structural authority crossings offline
    semantic-intent audit [explicit input flags]
                                                Run selected analyzers into one finding stream
"""

import argparse
import json
import sys
from pathlib import Path

from .composite_audit import (
    composite_exit_code,
    directory_adapter,
    mcp_adapter as composite_mcp_adapter,
    remote_adapter as composite_remote_adapter,
    run_composite,
    semantic_adapter,
    serialize_composite_audit,
    trust_adapter,
)
from .directory_audit import audit_directory
from .evaluator import evaluate_skill
from .inventory_diff import compare_inventories, serialize_change_set
from .llms_txt import audit_llms_txt
from .mcp_adapter import audit_mcp_tools
from .report import (
    remote_exit_code,
    render_directory_report,
    render_json_report,
    render_remote_json_report,
    render_remote_report,
    render_terminal_report,
)
from .resource_limits import MAX_LOCAL_ARTIFACT_BYTES
from .surface_inventory import InventoryError, discover_inventory, serialize_inventory
from .trust_analysis import analyze_trust_boundaries, serialize_trust_findings

MAX_PUBLIC_ERROR_LENGTH = 240

def _read_bounded_text(path: Path) -> str:
    if path.stat().st_size > MAX_LOCAL_ARTIFACT_BYTES:
        raise ValueError(f"input exceeds {MAX_LOCAL_ARTIFACT_BYTES} byte limit")
    return path.read_text(encoding="utf-8")


def _public_error(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        reason = "input cannot be read"
    elif isinstance(exc, UnicodeError):
        reason = "input is not valid UTF-8 text"
    elif isinstance(exc, json.JSONDecodeError):
        reason = f"input is not valid JSON at line {exc.lineno}, column {exc.colno}"
    else:
        reason = " ".join(str(exc).split())
    if len(reason) > MAX_PUBLIC_ERROR_LENGTH:
        reason = reason[: MAX_PUBLIC_ERROR_LENGTH - 3] + "..."
    return reason


def _print_public_error(exc: BaseException) -> None:
    print(f"Error: {_public_error(exc)}", file=sys.stderr)


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

    try:
        skill_text = _read_bounded_text(path)
    except (OSError, UnicodeError, ValueError) as exc:
        _print_public_error(exc)
        return 1

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
        try:
            skill_text = _read_bounded_text(skill_md)
        except (OSError, UnicodeError, ValueError) as exc:
            _print_public_error(exc)
            return 1
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


def cmd_scan_remote(args: argparse.Namespace) -> int:
    """
    Scan a site's agent-facing remote documents (llms.txt / llms-full.txt).

    Rule-based + external-state (registry / DNS) analysis by default. `--judge`
    adds a two-pass LLM evaluation of the retrieved content as untrusted
    evidence (v0.4 PR3) — it never follows an instruction found in that
    content, and a judge failure leaves the deterministic result intact.
    No command is executed and no package is installed either way. The fetch
    goes through the SSRF-hardened guarded path — HTTPS only, private/blocked
    address space refused, every redirect re-validated, no bypass flag.
    """
    url = args.url
    use_judge = getattr(args, "judge", False)

    print(f"Fetching supported remote documents for {url} …", file=sys.stderr)
    print(
        "(guarded fetch: HTTPS-only, SSRF-blocked, decompression-capped; "
        "no execution, no install"
        + ("; retrieved content evaluated as untrusted evidence)" if use_judge else "; no LLM judge)"),
        file=sys.stderr,
    )

    judge_cb = None
    if use_judge:
        from .remote_judge import judge_document

        judge_cb = lambda doc, det: judge_document(doc, det, api_key=args.api_key)  # noqa: E731

    results = audit_llms_txt(url, judge=judge_cb)  # live RegistryClient + guarded_fetch defaults

    if args.json:
        print(render_remote_json_report(results, url))
    else:
        print(render_remote_report(results, url, colorize=not args.no_color))

    return remote_exit_code(results)


def cmd_scan_mcp(args: argparse.Namespace) -> int:
    """
    Scan MCP tool definitions from a captured ``tools/list`` JSON file.

    Every tool ``description`` (and every nested ``description`` in an
    ``inputSchema``) is evaluated against the invariant set as untrusted
    external content. `--judge` adds the two-pass LLM judge over each tool's
    combined text. No MCP server is contacted, no transport is opened, no tool
    is invoked. A judge failure leaves the deterministic result intact.
    """
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    use_judge = getattr(args, "judge", False)
    print(f"Reading MCP tool definitions from {path} …", file=sys.stderr)
    print(
        "(offline: no MCP server contacted, no tool invoked, no transport opened"
        + ("; tool descriptions evaluated as untrusted evidence)" if use_judge else "; no LLM judge)"),
        file=sys.stderr,
    )

    judge_cb = None
    if use_judge:
        from .remote_judge import judge_document

        judge_cb = lambda doc, det: judge_document(doc, det, api_key=args.api_key)  # noqa: E731

    results = audit_mcp_tools(str(path), judge=judge_cb, server_label=args.server_label)

    if args.json:
        print(render_remote_json_report(results, str(path)))
    else:
        print(render_remote_report(results, str(path), colorize=not args.no_color))

    return remote_exit_code(results)


def cmd_inventory(args: argparse.Namespace) -> int:
    """Emit a bounded factual inventory; no detector or risk lane is invoked."""
    print(
        f"Inventorying public agent-readable surfaces for {args.url} …\n"
        "(bounded guarded retrieval; no crawling, execution, judge, or risk analysis)",
        file=sys.stderr,
    )
    try:
        inventory = discover_inventory(args.url)
    except InventoryError as exc:
        _print_public_error(exc)
        return 3
    print(serialize_inventory(inventory))
    return 0


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def cmd_inventory_diff(args: argparse.Namespace) -> int:
    """Compare two local inventory artifacts without discovery or analysis."""
    previous_path = Path(args.previous)
    current_path = Path(args.current)
    try:
        previous = json.loads(
            _read_bounded_text(previous_path),
            parse_constant=_reject_nonfinite_json,
        )
        current = json.loads(
            _read_bounded_text(current_path),
            parse_constant=_reject_nonfinite_json,
        )
        change_set = compare_inventories(previous, current)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _print_public_error(exc)
        return 3
    print(serialize_change_set(change_set))
    return 0


def cmd_trust_analyze(args: argparse.Namespace) -> int:
    """Analyze one local inventory without retrieval, execution, or judgment."""
    inventory_path = Path(args.inventory)
    try:
        inventory = json.loads(
            _read_bounded_text(inventory_path),
            parse_constant=_reject_nonfinite_json,
        )
        findings = analyze_trust_boundaries(inventory)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _print_public_error(exc)
        return 3
    print(serialize_trust_findings(findings))
    return 0


def _numbered_id(base: str, index: int) -> str:
    return base if index == 0 else f"{base}:{index + 1}"


def cmd_audit(args: argparse.Namespace) -> int:
    """Run only explicitly selected existing analyzers into a v0.9 artifact."""
    adapters = []
    if args.judge and not (args.remote or args.mcp):
        print("Error: --judge requires at least one --remote or --mcp input", file=sys.stderr)
        return 3
    if args.server_label is not None and not args.mcp:
        print("Error: --server-label requires at least one --mcp input", file=sys.stderr)
        return 3
    judge_cb = None
    if args.judge:
        from .remote_judge import judge_document

        judge_cb = lambda doc, det: judge_document(  # noqa: E731
            doc, det, api_key=args.api_key,
        )

    for index, value in enumerate(args.directory or []):
        adapters.append(directory_adapter(_numbered_id("directory", index), value))
    for index, value in enumerate(args.skill or []):
        adapters.append(semantic_adapter(
            _numbered_id("semantic", index), value, api_key=args.api_key,
        ))
    for index, value in enumerate(args.remote or []):
        adapters.append(composite_remote_adapter(
            _numbered_id("remote", index), value, judge=judge_cb,
        ))
    for index, value in enumerate(args.mcp or []):
        adapters.append(composite_mcp_adapter(
            _numbered_id("mcp", index), value, judge=judge_cb,
            server_label=args.server_label,
        ))
    for index, value in enumerate(args.trust_inventory or []):
        adapters.append(trust_adapter(_numbered_id("trust", index), value))

    if not adapters:
        print("Error: audit requires at least one explicit analyzer input", file=sys.stderr)
        return 3
    artifact = run_composite(adapters)
    print(serialize_composite_audit(artifact))
    return composite_exit_code(artifact)


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

    remote_parser = subparsers.add_parser(
        "scan-remote",
        help="Scan a site's remote agent-facing documents (llms.txt / llms-full.txt)",
    )
    remote_parser.add_argument("url", help="Site or base URL, e.g. https://example.com")
    remote_parser.add_argument("--json", action="store_true", help="Output JSON report")
    remote_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    remote_parser.add_argument(
        "--judge",
        action="store_true",
        help="Also run the two-pass LLM judge over retrieved content (needs an API key)",
    )
    remote_parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key for --judge (defaults to ANTHROPIC_API_KEY env var)",
    )

    mcp_parser = subparsers.add_parser(
        "scan-mcp",
        help="Scan MCP tool descriptions from a captured tools/list JSON file",
    )
    mcp_parser.add_argument("file", help="Path to a tools/list JSON file (offline; no server is contacted)")
    mcp_parser.add_argument("--json", action="store_true", help="Output JSON report")
    mcp_parser.add_argument("--no-color", action="store_true", help="Disable color output")
    mcp_parser.add_argument(
        "--judge",
        action="store_true",
        help="Also run the two-pass LLM judge over each tool's description text (needs an API key)",
    )
    mcp_parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key for --judge (defaults to ANTHROPIC_API_KEY env var)",
    )
    mcp_parser.add_argument(
        "--server-label",
        default=None,
        help="Name of the MCP server the file came from (provenance only; not authenticated)",
    )

    inventory_parser = subparsers.add_parser(
        "inventory",
        help="Inventory bounded public agent-readable surfaces (JSON; no risk analysis)",
    )
    inventory_parser.add_argument("url", help="Site or base URL, e.g. https://example.com")

    diff_parser = subparsers.add_parser(
        "inventory-diff",
        help="Compare two inventory JSON artifacts (offline; no risk analysis)",
    )
    diff_parser.add_argument("previous", help="Path to the previous inventory JSON artifact")
    diff_parser.add_argument("current", help="Path to the current inventory JSON artifact")

    trust_parser = subparsers.add_parser(
        "trust-analyze",
        help="Analyze structural authority crossings in an inventory artifact (offline)",
    )
    trust_parser.add_argument("inventory", help="Path to an inventory JSON artifact")

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run explicitly selected analyzers into one canonical finding stream",
    )
    audit_parser.add_argument(
        "--directory", action="append",
        help="Audit one local directory (repeatable; offline directory analyzer)",
    )
    audit_parser.add_argument(
        "--skill", action="append",
        help="Evaluate one local skill file (repeatable; existing model-backed analyzer)",
    )
    audit_parser.add_argument(
        "--remote", action="append",
        help="Audit one HTTPS remote target (repeatable; existing guarded-fetch path)",
    )
    audit_parser.add_argument(
        "--mcp", action="append",
        help="Audit one captured MCP tools/list JSON file (repeatable; no MCP transport)",
    )
    audit_parser.add_argument(
        "--trust-inventory", action="append",
        help="Analyze one saved inventory artifact (repeatable; offline)",
    )
    audit_parser.add_argument(
        "--judge", action="store_true",
        help="Use the existing optional judge for selected remote/MCP analyzers",
    )
    audit_parser.add_argument(
        "--api-key", default=None,
        help="Anthropic API key for --skill or --judge (defaults to environment)",
    )
    audit_parser.add_argument(
        "--server-label", default=None,
        help="MCP provenance label applied to explicitly selected captured files",
    )

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    if args.command == "scan-remote":
        sys.exit(cmd_scan_remote(args))
    if args.command == "scan-mcp":
        sys.exit(cmd_scan_mcp(args))
    if args.command == "inventory":
        sys.exit(cmd_inventory(args))
    if args.command == "inventory-diff":
        sys.exit(cmd_inventory_diff(args))
    if args.command == "trust-analyze":
        sys.exit(cmd_trust_analyze(args))
    if args.command == "audit":
        sys.exit(cmd_audit(args))


if __name__ == "__main__":
    main()
