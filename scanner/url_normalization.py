"""Authoritative HTTPS resource and origin normalization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


class URLNormalizationError(ValueError):
    """Raised when a URL cannot safely enter a scanner trust boundary."""


def _remove_dot_segments(path: str) -> str:
    """Apply RFC 3986 dot-segment removal without decoding path octets."""
    source = path
    output = ""
    while source:
        if source.startswith("../"):
            source = source[3:]
        elif source.startswith("./"):
            source = source[2:]
        elif source.startswith("/./"):
            source = source[2:]
        elif source == "/.":
            source = "/"
        elif source.startswith("/../"):
            source = source[3:]
            output = output.rsplit("/", 1)[0]
        elif source == "/..":
            source = "/"
            output = output.rsplit("/", 1)[0]
        elif source in {".", ".."}:
            source = ""
        else:
            start = 1 if source.startswith("/") else 0
            slash = source.find("/", start)
            if slash < 0:
                output += source
                source = ""
            else:
                output += source[:slash]
                source = source[slash:]
    return output or "/"


def canonicalize_https_url(url: str) -> str:
    """Canonicalize an absolute public HTTPS resource without decoding its path/query."""
    if not isinstance(url, str) or not url.strip():
        raise URLNormalizationError("resource URL must be a non-empty string")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise URLNormalizationError(f"invalid resource URL: {exc}") from exc
    if parsed.scheme.lower() != "https":
        raise URLNormalizationError("inventory supports HTTPS resources only")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise URLNormalizationError("resource URL requires a hostname and must not contain userinfo")
    host = parsed.hostname.lower()
    if host.endswith(".."):
        raise URLNormalizationError("resource URL hostname has multiple trailing dots")
    host = host.removesuffix(".")
    if not host:
        raise URLNormalizationError("resource URL requires a hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLNormalizationError("resource URL hostname is not valid IDNA") from exc
        labels = host.split(".")
        if any(
            not label or len(label) > 63
            or label.startswith("-") or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ) or len(host) > 253:
            raise URLNormalizationError("resource URL hostname is malformed")
        canonical_host = host
    else:
        canonical_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    netloc = canonical_host if port in (None, 443) else f"{canonical_host}:{port}"
    path = _remove_dot_segments(parsed.path or "/")
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def canonical_https_origin(url: str) -> str:
    canonical = canonicalize_https_url(url)
    parsed = urlsplit(canonical)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def https_origin_key(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(canonicalize_https_url(url))
    return (parsed.scheme, parsed.hostname or "", parsed.port or 443)
