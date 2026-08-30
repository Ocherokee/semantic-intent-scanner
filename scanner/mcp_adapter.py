"""
MCP tool-description adapter for the remote-content audit engine.

An MCP server, on connection, returns a ``tools/list`` response: an array of
tool definitions, each ``{name, description, inputSchema}``. An agent loads
every ``description`` string into its context as one of its own trusted
capabilities. A poisoned description can tell the agent when to call a tool,
embed operational instructions, claim authority, ask for credentials, or
redirect activity to an external package / domain -- the I8 surface, named
verbatim in the invariant ("...an MCP tool description...").

This adapter takes a captured ``tools/list`` payload **from a file**,
normalises each semantically-relevant field into a
:class:`scanner.remote_audit.RemoteDocument`, and runs it through the existing
engine -- two roles, two lanes, no text analysed twice:

  * **per-field documents -> deterministic lane.** One ``RemoteDocument`` per
    field (``name``, ``description``, every nested ``description`` in
    ``inputSchema``). ``remote_audit.analyze_document`` runs over these;
    findings carry the exact field path.
  * **one combined per-tool document -> judge lane (optional, --judge).**
    Body = every field joined with labelled separators, so the judge can
    reason across fields ("benign description + malicious parameter
    description"). It receives that tool's per-field deterministic findings as
    the trusted ``<<<FINDINGS>>>`` evidence. It is **never** passed to
    ``analyze_document`` -- that would re-derive the same findings and repeat
    registry / DNS lookups for the same text.

No MCP server is contacted. No transport is opened. No tool is invoked. The
``mcp://`` origin strings are identifiers only and are never dereferenced;
their attacker/user-controlled components are percent-encoded so a tool name
or server label cannot forge or blur a provenance identifier.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from .registry import RegistryClient
from .remote_audit import (
    Finding,
    RemoteDocument,
    analyze_document,
    findings_as_dicts,
    overall_risk,
)
from .remote_common import attach_judge

# (RemoteDocument, deterministic findings) -> a JudgeResult-shaped object.
Judge = Callable[[RemoteDocument, "list[Finding]"], Any]

# Schema keys that are structural containers. They are elided from the
# *friendly* path (``mcp_field``) only, so a nested description reads
# ``parameters.location.description`` rather than
# ``parameters.properties.location.description``. They are always kept in the
# *lossless* path (``mcp_json_path``) -- two locations that would collapse to
# the same friendly path (``properties.foo`` vs ``$defs.foo``) must stay
# distinguishable, and the synthetic ``mcp://`` URI is built from the lossless
# path for exactly that reason.
_PATH_TRANSPARENT = {"properties", "patternProperties", "$defs", "definitions"}
MAX_MCP_INPUT_BYTES = 512 * 1024
MAX_MCP_NESTING_DEPTH = 64
MAX_MCP_DESCRIPTION_FIELDS = 4096


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _enc(part: str) -> str:
    """Percent-encode one component of a synthetic ``mcp://`` URI."""
    return quote(str(part), safe="")


def _mcp_uri(server: str | None, tool: str, field: str) -> str:
    host = _enc(server) if server else "unknown"
    return f"mcp://{host}/tools/{_enc(tool)}#{_enc(field)}"


# ---------------------------------------------------------------------------
# payload parsing  (offline file -> list of tool dicts)
# ---------------------------------------------------------------------------

def _tools_from_payload(payload: Any) -> tuple[list[Any] | None, bool]:
    """
    Return ``(tools, recognised_shape)``.

    Accepts a bare ``[ {...} ]`` array, a ``ListToolsResult``
    ``{"tools": [...]}``, or a JSON-RPC envelope ``{"result": {"tools": [...]}}``.
    ``recognised_shape`` is False when none of those matched (invalid input);
    an empty but well-formed ``tools`` list is ``([], True)`` (no tools).
    """
    if isinstance(payload, list):
        return payload, True
    if isinstance(payload, dict):
        if isinstance(payload.get("tools"), list):
            return payload["tools"], True
        result = payload.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return result["tools"], True
    return None, False


def _server_label(payload: Any, override: str | None) -> str | None:
    if override:
        return override
    containers = [payload]
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        containers.append(payload["result"])
    for c in containers:
        if isinstance(c, dict):
            meta = c.get("_meta")
            if isinstance(meta, dict) and isinstance(meta.get("server"), str) and meta["server"].strip():
                return meta["server"]
    return None


# ---------------------------------------------------------------------------
# field extraction
# ---------------------------------------------------------------------------

def _walk_descriptions(node: Any, friendly: list[str], jsonpath: str,
                       out: list[tuple[str, str, str]], depth: int = 0) -> None:
    """
    Collect every string-valued ``description`` anywhere under ``node``.

    ``inputSchema`` is walked as ordinary untrusted JSON. This locates
    attacker-authored natural language wherever it sits -- under ``properties``,
    ``items``, ``oneOf`` / ``allOf`` / ``anyOf``, ``$defs``, ... -- and is
    **not** schema interpretation: no ``$ref`` is resolved and no type is
    acted on.

    Each hit yields ``(friendly_path, json_path, text)``:

      * ``friendly_path`` -- human-facing, structural containers elided:
        ``parameters.files.items.description``
      * ``json_path`` -- lossless, every container and index kept, so two
        genuinely different locations can never collapse together:
        ``inputSchema.properties.files.items.description``,
        ``inputSchema.$defs.foo.description``,
        ``inputSchema.oneOf[0].properties.foo.description``
    """
    if depth > MAX_MCP_NESTING_DEPTH:
        raise ValueError(f"MCP inputSchema exceeds nesting depth {MAX_MCP_NESTING_DEPTH}")
    if len(out) >= MAX_MCP_DESCRIPTION_FIELDS:
        raise ValueError(f"MCP inputSchema exceeds {MAX_MCP_DESCRIPTION_FIELDS} description fields")
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "description":
                if isinstance(value, str) and value.strip():
                    if len(out) >= MAX_MCP_DESCRIPTION_FIELDS:
                        raise ValueError(
                            f"MCP inputSchema exceeds {MAX_MCP_DESCRIPTION_FIELDS} description fields"
                        )
                    out.append((
                        ".".join(friendly + ["description"]),
                        jsonpath + ".description",
                        value,
                    ))
                continue
            f_child = friendly if key in _PATH_TRANSPARENT else friendly + [str(key)]
            _walk_descriptions(value, f_child, f"{jsonpath}.{key}", out, depth + 1)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_descriptions(item, friendly + [str(i)], f"{jsonpath}[{i}]", out, depth + 1)


def _tool_fields(tool: dict) -> list[tuple[str, str, str]]:
    """``(friendly_path, json_path, text)`` for every semantically-relevant field."""
    fields: list[tuple[str, str, str]] = []
    name = tool.get("name")
    if isinstance(name, str) and name.strip():
        fields.append(("name", "name", name))
    desc = tool.get("description")
    if isinstance(desc, str) and desc.strip():
        fields.append(("description", "description", desc))
    schema = tool.get("inputSchema")
    if isinstance(schema, (dict, list)):
        walked: list[tuple[str, str, str]] = []
        _walk_descriptions(schema, ["parameters"], "inputSchema", walked)
        fields.extend(walked)
    return fields


def _combined_text(fields: list[tuple[str, str, str]]) -> str:
    return "\n\n".join(f"[{friendly}]\n{text}" for friendly, _jsonpath, text in fields)


def _tag(f: Finding, tool: str, friendly: str, json_path: str, server: str | None) -> None:
    """
    Attach MCP provenance to a finding. ``source_url`` (set by
    ``analyze_document``) is the percent-encoded synthetic URI built from the
    lossless ``json_path``; the unescaped originals live here.
    """
    f.detail = {
        **(f.detail or {}),
        "mcp_tool": tool,
        "mcp_field": friendly,        # human-facing, may collide across containers
        "mcp_json_path": json_path,   # lossless structural location
        "mcp_server": {"declared": server, "authenticated": False},
    }


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _empty_result(source: str) -> dict[str, Any]:
    return {
        "surface": "mcp",
        "source": source,
        "documents": [],
        "retrieved": 0,
        "findings": [],
        "overall_risk": "low",
    }


def _bail(result: dict[str, Any], *, parse_error: str | None, note: str,
          judge: Judge | None) -> dict[str, Any]:
    result["parse_error"] = parse_error
    result["note"] = note
    if judge is not None:
        result["judge_status"] = "skipped:no_documents"
        result["semantic_coverage"] = "incomplete"
    return result


def audit_mcp_tools(
    source: str,
    *,
    registry: RegistryClient | None = None,
    judge: Judge | None = None,
    server_label: str | None = None,
) -> dict[str, Any]:
    """
    Audit MCP tool definitions read from the JSON file at ``source``.

    Returns the same result-dict shape as
    :func:`scanner.llms_txt.audit_llms_txt` (``surface`` / ``documents`` /
    ``retrieved`` / ``findings`` / ``overall_risk`` [+ ``judge*`` when a judge
    ran]), so ``report.render_remote_report`` / ``render_remote_json_report``
    and ``remote_exit_code`` consume it directly.

    ``judge`` is an optional ``(RemoteDocument, deterministic findings) ->
    JudgeResult`` callable (``scanner.remote_judge.judge_document``). With no
    judge the result is deterministic-only and needs no API key.
    """
    registry = registry or RegistryClient()
    read_at = _utc_now()
    result = _empty_result(source)

    try:
        raw = Path(source).read_text("utf-8")
    except OSError as exc:
        return _bail(result, parse_error=f"cannot read input: {exc}",
                     note=f"cannot read {source}: {exc}", judge=judge)

    if len(raw.encode("utf-8")) > MAX_MCP_INPUT_BYTES:
        return _bail(result, parse_error=f"input exceeds {MAX_MCP_INPUT_BYTES} byte limit",
                     note="captured MCP input exceeds deterministic byte limit", judge=judge)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _bail(result, parse_error=f"not valid JSON: {exc}",
                     note=f"{source} is not valid JSON: {exc}", judge=judge)

    label = _server_label(payload, server_label)
    result["mcp_server"] = {"declared": label, "authenticated": False}

    tools, recognised = _tools_from_payload(payload)
    if not recognised:
        return _bail(result,
                     parse_error="unrecognised shape: expected a tools array, "
                                 "{\"tools\": [...]}, or a JSON-RPC result",
                     note="input is not a recognised tools/list shape", judge=judge)

    tool_dicts = [t for t in (tools or []) if isinstance(t, dict)]
    if not tool_dicts:
        # well-formed, just nothing to evaluate -> "no_tools", not "invalid_input"
        return _bail(result, parse_error=None,
                     note="the input parsed but contained no tool definitions",
                     judge=judge)

    det_findings: list[Finding] = []
    per_tool_judge: dict[str, Any] = {}
    doc_summaries: list[dict] = []
    parsed = 0
    malformed = 0

    for idx, tool in enumerate(tool_dicts):
        name = tool.get("name")
        if not isinstance(name, str) or not name.strip():
            malformed += 1
            doc_summaries.append({
                "kind": "mcp_tool",
                "requested_url": _mcp_uri(label, f"[{idx}]", "whole"),
                "final_url": None, "status": 0, "content_type": "application/json",
                "sha256": None, "fetched_at": read_at, "bytes": 0,
                "redirect_chain": [], "cross_origin_redirect": False, "truncated": False,
                "error": "tool definition has no usable 'name'", "blocked_reason": None,
                "mcp_tool": None, "mcp_fields": [], "mcp_json_paths": [],
            })
            continue

        try:
            fields = _tool_fields(tool)
        except ValueError as exc:
            malformed += 1
            doc_summaries.append({
                "kind": "mcp_tool", "requested_url": _mcp_uri(label, name, "whole"),
                "final_url": None, "status": 0, "content_type": "application/json",
                "sha256": None, "fetched_at": read_at, "bytes": 0,
                "redirect_chain": [], "cross_origin_redirect": False, "truncated": False,
                "error": str(exc), "blocked_reason": None, "mcp_tool": name,
                "mcp_fields": [], "mcp_json_paths": [],
            })
            continue
        combined = _combined_text(fields)
        combined_uri = _mcp_uri(label, name, "whole")

        tool_det: list[Finding] = []
        for friendly, json_path, text in fields:
            fdoc = RemoteDocument(
                # synthetic origin built from the LOSSLESS path -> two distinct
                # source locations can never collapse to the same URI
                origin_url=_mcp_uri(label, name, json_path),
                final_url=None, body=text, sha256=_sha256(text), fetched_at=read_at,
            )
            for f in analyze_document(fdoc, registry):
                _tag(f, name, friendly, json_path, label)
                tool_det.append(f)
        det_findings.extend(tool_det)

        if judge is not None:
            cdoc = RemoteDocument(
                origin_url=combined_uri, final_url=None, body=combined,
                sha256=_sha256(combined), fetched_at=read_at,
            )
            jr = judge(cdoc, tool_det)
            for f in getattr(jr, "findings", []) or []:
                _tag(f, name, "whole", "whole", label)
            per_tool_judge[combined_uri] = jr

        parsed += 1
        doc_summaries.append({
            "kind": "mcp_tool",
            "requested_url": combined_uri,
            "final_url": None,
            "status": 200,
            "content_type": "application/json",
            "sha256": _sha256(combined),
            "fetched_at": read_at,
            "bytes": len(combined.encode("utf-8")),
            "redirect_chain": [],
            "cross_origin_redirect": False,
            "truncated": False,
            "error": None,
            "blocked_reason": None,
            "mcp_tool": name,
            "mcp_fields": [fr for fr, _jp, _t in fields],
            "mcp_json_paths": [jp for _fr, jp, _t in fields],
        })

    result["documents"] = doc_summaries
    result["retrieved"] = parsed
    if malformed:
        result["note"] = f"{malformed} tool definition(s) skipped (no usable name)"

    all_findings = list(det_findings)
    if judge is not None:
        for jr in per_tool_judge.values():
            if getattr(jr, "status", None) == "ok":
                all_findings.extend(jr.findings)
        attach_judge(result, per_tool_judge)

    result["findings"] = findings_as_dicts(all_findings)
    result["overall_risk"] = overall_risk(all_findings)
    return result


if __name__ == "__main__":  # pragma: no cover - manual poke, not the CLI
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m scanner.mcp_adapter <tools-list.json>", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(audit_mcp_tools(sys.argv[1]), indent=2))
