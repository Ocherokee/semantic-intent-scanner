"""Deterministic, opt-in sanitization of JSON before untrusted disclosure.

This module is NOT wired into scanner reports or external agent responses.
Callers must enforce access control before retrieval and pass a trusted
field allowlist. No credential value should enter logs or model prompts.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"
MAX_BYTES = 512 * 1024
MAX_DEPTH = 32
MAX_NODES = 10_000

# Defense in depth: even an accidentally allowlisted field cannot disclose
# familiar credential names or obvious secret-bearing payloads.
_SECRET_KEY = re.compile(
    r"(?:password|passwd|pwd|secret|private.?key|access.?key|api.?key|"
    r"session.?token|auth(?:orization)?|credential|bearer|client.?secret|"
    r"refresh.?token|security.?token|id.?token|cookie)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/\-]{8,}|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,})\b|"
    r"\b(?:sk-[A-Za-z0-9_-]{20,})\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)",
    re.IGNORECASE,
)


class DisclosureBlocked(ValueError):
    """The input cannot be safely processed; do not release the original."""


def sanitize_json(
    payload: str | bytes | dict | list,
    *,
    allowed_paths: frozenset[tuple[str, ...]],
) -> Any:
    """Return sanitized JSON-compatible data; never modify caller's data.

    allowed_paths is a trusted exact leaf-path allowlist. Use '*' to match an
    array index, e.g. ('items', '*', 'status'). Never build policy from source
    JSON, a retrieved document, or a requester's instructions.

    Every non-allowlisted leaf becomes REDACTED, including unknown fields.
    Both parent containers and list positions are preserved.
    """
    if not isinstance(allowed_paths, frozenset) or not all(
        isinstance(path, tuple) and len(path) > 0
        and all(isinstance(part, str) and part for part in path)
        for path in allowed_paths
    ):
        raise DisclosureBlocked("a trusted field allowlist is required")
    if isinstance(payload, (str, bytes)):
        if len(payload.encode("utf-8") if isinstance(payload, str) else payload) > MAX_BYTES:
            raise DisclosureBlocked("input exceeds size limit")
        try:
            payload = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise DisclosureBlocked("invalid JSON") from exc
    elif not isinstance(payload, (dict, list)):
        raise DisclosureBlocked("expected a JSON object or array")
    if not isinstance(payload, (dict, list)):
        raise DisclosureBlocked("expected a JSON object or array")

    nodes = 0

    def walk(value: Any, path: tuple[str, ...], depth: int, sensitive: bool) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise DisclosureBlocked("JSON exceeds traversal limits")
        if isinstance(value, dict):
            if not all(isinstance(k, str) for k in value):
                raise DisclosureBlocked("invalid object key")
            return {
                k: walk(v, path + (k,), depth + 1, sensitive or bool(_SECRET_KEY.search(k)))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [walk(v, path + ("*",), depth + 1, sensitive) for v in value]
        if not (value is None or isinstance(value, (str, int, float, bool))):
            raise DisclosureBlocked("unsupported JSON value")
        if isinstance(value, float) and not __import__("math").isfinite(value):
            raise DisclosureBlocked("non-finite number")
        if sensitive or path not in allowed_paths:
            return REDACTED
        if isinstance(value, str) and _SECRET_VALUE.search(value):
            return REDACTED
        return value

    try:
        return walk(payload, (), 0, False)
    except RecursionError as exc:
        raise DisclosureBlocked("JSON depth exceeded") from exc


def safe_json_response(
    payload: str | bytes | dict | list,
    *,
    allowed_paths: frozenset[tuple[str, ...]],
) -> str:
    """Serialize only the sanitized result; exceptions must be handled as denial."""
    sanitized = sanitize_json(payload, allowed_paths=allowed_paths)
    return json.dumps(sanitized, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
