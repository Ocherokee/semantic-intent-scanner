"""Opt-in static conditional-execution inspection. Never imports analyzed code.

This intentionally bounded analyzer provides *signals*, not proof of malware.
It does not affect any existing scanner command, report, or finding contract.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_SOURCE_BYTES = 512 * 1024
MAX_NODES = 15000
MAX_LIFECYCLE_BYTES = 128 * 1024

_TIME = re.compile(r"\b(datetime|date|time|timestamp|utcnow|now|today|strftime|strptime|sleep|setTimeout|setInterval)\b", re.I)
_ANTI = re.compile(r"\b(debugger|debugger_present|is_debugger|ptrace|sys\.gettrace|virtualbox|vmware|sandbox|analysis_tool|security_process|antivirus)\b", re.I)
_CREDENTIAL = re.compile(r"(?<![^\W_])credentials?(?![^\W_])|\b(secret|token|password|api_key|access_key|private_key|\.aws|\.ssh)\b", re.I)
_OUTBOUND = re.compile(r"\b(requests\.post|httpx\.post|urllib\.request|fetch\s*\(|axios\.post|send|transmit|upload)\b", re.I)
_PROCESS = re.compile(r"\b(subprocess|Popen|os\.system|child_process|spawn\s*\(|exec\s*\(|detached)\b", re.I)
_DYNAMIC = re.compile(r"\b(eval|exec|compile|__import__|importlib|Function)\s*\(", re.I)
_JS_CONDITION = re.compile(r"\bif\s*\(", re.I)

def _javascript_conditions(source: str):
    """Extract braced if conditions with at most 300 condition characters."""
    for match in _JS_CONDITION.finditer(source):
        start = match.end()
        depth = 1
        quote = None
        escaped = False
        for index in range(start, min(len(source), start + 301)):
            char = source[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ("'", '"', "`"):
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    body_start = index + 1
                    while body_start < len(source) and source[body_start].isspace():
                        body_start += 1
                    if index > start and body_start < len(source) and source[body_start] == "{":
                        yield source[start:index], body_start + 1, match.start()
                    break

@dataclass(frozen=True)
class Observation:
    rule: str
    concern: str
    line: int
    evidence: str

def _describe(condition: str, body: str, line: int) -> list[Observation]:
    time = bool(_TIME.search(condition))
    anti = bool(_ANTI.search(condition))
    credentials = bool(_CREDENTIAL.search(body))
    outbound = bool(_OUTBOUND.search(body))
    process = bool(_PROCESS.search(body))
    if time and credentials and outbound:
        return [Observation("CE-05", "high", line, "date/time-gated credential-related outbound behavior")]
    if time and process:
        return [Observation("CE-06", "high", line, "time-gated process execution")]
    if anti and (process or credentials or outbound or _DYNAMIC.search(body)):
        return [Observation("CE-03", "elevated", line, "anti-analysis condition gates sensitive behavior")]
    if anti:
        return [Observation("CE-03", "review", line, "environment-dependent branch; consequence not resolved")]
    if time:
        return [Observation("CE-01", "informational", line, "time-dependent branch; inspect intent in context")]
    return []

def inspect_python(source: str) -> list[Observation]:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("source too large")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError("invalid Python syntax") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_NODES:
        raise ValueError("AST too large")
    findings: list[Observation] = []
    for node in nodes:
        if isinstance(node, (ast.If, ast.While)):
            condition = ast.unparse(node.test)
            body = "\n".join(ast.unparse(item) for item in node.body)
            findings.extend(_describe(condition, body, node.lineno))
        if isinstance(node, ast.Call):
            target = ast.unparse(node.func)
            if _DYNAMIC.search(target + "("):
                findings.append(Observation("CE-UNRESOLVED", "incomplete", node.lineno,
                                            "dynamic execution cannot be statically resolved"))
    return sorted(set(findings), key=lambda f: (f.line, f.rule, f.evidence))

def inspect_npm_manifest(payload: str) -> list[Observation]:
    if len(payload.encode("utf-8")) > MAX_LIFECYCLE_BYTES:
        raise ValueError("manifest too large")
    try:
        manifest = json.loads(payload)
    except ValueError as exc:
        raise ValueError("invalid package JSON") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("scripts", {}), dict):
        raise ValueError("invalid npm scripts")
    findings: list[Observation] = []
    for hook in ("preinstall", "install", "postinstall"):
        script = manifest["scripts"].get(hook)
        if not isinstance(script, str):
            continue
        if _TIME.search(script) and _PROCESS.search(script):
            findings.append(Observation("CE-06", "high", 0,
                                        f"{hook}: delayed/background process behavior"))
        elif _ANTI.search(script) and _PROCESS.search(script):
            findings.append(Observation("CE-03", "elevated", 0,
                                        f"{hook}: analysis-gated process behavior"))
        elif _TIME.search(script):
            findings.append(Observation("CE-02", "informational", 0,
                                        f"{hook}: time-dependent installation hook"))
        if _DYNAMIC.search(script):
            findings.append(Observation("CE-UNRESOLVED", "incomplete", 0,
                                        f"{hook}: dynamic code not statically resolved"))
    return findings

def inspect_javascript(source: str) -> list[Observation]:
    """Conservative heuristic only; NOT a JavaScript parser or dataflow proof."""
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("source too large")
    findings = []
    for condition, body_start, condition_start in _javascript_conditions(source):
        # Bounded snippet is intentionally not represented as a full reachable call graph.
        body = source[body_start:body_start+1200].split("}", 1)[0]
        findings.extend(_describe(condition, body, source.count("\n", 0, condition_start)+1))
    if _DYNAMIC.search(source):
        findings.append(Observation("CE-UNRESOLVED", "incomplete", 0,
                                    "dynamic JavaScript execution not statically resolved"))
    return findings

def unchanged_approved_artifact(artifact: bytes, *, approved_sha256: str,
                                policy_version: str, approved_policy_version: str) -> bool:
    """Reuse a previous review only for exact bytes and matching policy version."""
    return (policy_version == approved_policy_version
            and hashlib.sha256(artifact).hexdigest() == approved_sha256)

def inspect_path(path: str | Path) -> list[Observation]:
    p = Path(path)
    if p.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("source too large")
    data = p.read_text(encoding="utf-8")
    if p.name == "package.json":
        return inspect_npm_manifest(data)
    if p.suffix == ".py":
        return inspect_python(data)
    if p.suffix in (".js", ".mjs", ".cjs"):
        return inspect_javascript(data)
    raise ValueError("unsupported input format")
