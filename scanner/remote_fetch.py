"""
SSRF-hardened HTTP fetch for the remote-content audit lanes.

Guarantees:
  * HTTPS only. ``http://`` and every other scheme is refused.
  * Userinfo in the URL (``https://user:pass@host/``) is refused.
  * Every hop in a redirect chain is validated the same way as the first
    URL -- scheme, hostname, and *resolved IP addresses*.
  * Blocked address space: loopback, RFC1918 / unique-local, link-local
    (incl. the 169.254.169.254 / fd00:ec2::254 metadata endpoints),
    CGNAT 100.64/10, unspecified, reserved, multicast -- IPv4 and IPv6,
    including IPv4-mapped IPv6.
  * The socket is connected to a *pinned, pre-validated* IP on the URL's
    explicit port (default 443), with the original hostname kept for SNI /
    certificate validation, so a DNS rebind between check and connect
    cannot land us on a private address. Explicit ports are preserved, not
    collapsed to 443, and a port change counts as a cross-origin redirect.
  * No credentials, cookies, or Authorization headers are ever sent, so
    nothing can be forwarded across an origin boundary.
  * Hard connect+read timeout on every hop; total redirects capped.
  * Body size capped on *actual* decompressed bytes, not on the declared
    Content-Length. gzip/deflate is inflated incrementally and inflation
    stops once the cap is exceeded, so a decompression bomb (a few KB that
    expands to gigabytes) is never materialised.

This module returns bytes plus provenance metadata. It never parses,
executes, or interprets the content.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

MAX_BODY_BYTES = 512 * 1024
CONNECT_READ_TIMEOUT = 5.0
MAX_REDIRECTS = 5

# Extra explicit denylist for well-known cloud metadata endpoints. These are
# already covered by the link-local / unique-local checks, but naming them
# makes the intent obvious and survives future refactors of the range logic.
METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}

_STATIC_HEADERS = {
    "User-Agent": "semantic-intent-scanner/0.4 (remote-content audit; +https://github.com/Ocherokee/semantic-intent-scanner)",
    "Accept": "text/plain, text/markdown, text/*;q=0.9, */*;q=0.5",
    "Accept-Encoding": "gzip, deflate",
}

Resolver = Callable[[str], list[str]]          # host -> list of IP strings
Transport = Callable[..., "RawResponse"]        # (method, url, headers, timeout, resolver) -> RawResponse


class RemoteFetchBlocked(Exception):
    """A URL (initial or redirect target) failed the SSRF guard."""


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    location: str | None = None


@dataclass
class FetchOutcome:
    requested_url: str
    final_url: str | None
    status: int
    content_type: str | None
    body: bytes
    sha256: str | None
    fetched_at: str
    redirect_chain: list[dict] = field(default_factory=list)
    cross_origin_redirect: bool = False
    truncated: bool = False
    error: str | None = None
    blocked_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.error is None

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, "replace")


# ---------------------------------------------------------------------------
# Address validation
# ---------------------------------------------------------------------------

def _system_resolver(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)]


def ip_block_reason(ip_str: str) -> str | None:
    """Return a reason string if this IP must not be contacted, else None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"unparseable address {ip_str!r}"
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip_str in METADATA_IPS or str(ip) in METADATA_IPS:
        return "cloud metadata endpoint"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_private:
        return "private address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return "carrier-grade NAT address"
    return None


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def resolve_and_validate(url: str, resolver: Resolver = _system_resolver) -> list[str]:
    """
    Validate ``url`` for fetching and return the list of safe resolved IPs.
    Raises RemoteFetchBlocked on any violation.
    """
    p = urlparse(url)
    if p.scheme != "https":
        raise RemoteFetchBlocked(f"non-https scheme {p.scheme!r}")
    if p.username or p.password:
        raise RemoteFetchBlocked("URL contains userinfo credentials")
    host = p.hostname
    if not host:
        raise RemoteFetchBlocked("URL has no host")

    # Host given as a literal IP: validate directly.
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        reason = ip_block_reason(host)
        if reason:
            raise RemoteFetchBlocked(f"{host}: {reason}")
        return [host]

    try:
        ips = resolver(host)
    except (socket.gaierror, OSError) as exc:
        raise RemoteFetchBlocked(f"{host}: DNS resolution failed ({exc})") from exc
    if not ips:
        raise RemoteFetchBlocked(f"{host}: DNS returned no addresses")
    for ip in ips:
        reason = ip_block_reason(ip)
        if reason:
            raise RemoteFetchBlocked(f"{host} resolves to {ip}: {reason}")
    return ips


# ---------------------------------------------------------------------------
# Default transport: single request, pinned IP, no redirect following
# ---------------------------------------------------------------------------

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to a caller-chosen IP on the URL's port
    but keeps the original hostname for SNI and certificate verification."""

    def __init__(self, host: str, pinned_ip: str, *, port: int = 443, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _default_transport(method: str, url: str, headers: dict[str, str], timeout: float,
                       resolver: Resolver) -> RawResponse:
    safe_ips = resolve_and_validate(url, resolver)
    p = urlparse(url)
    conn = _PinnedHTTPSConnection(p.hostname, safe_ips[0], port=p.port or 443, timeout=timeout)
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    try:
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY_BYTES * 4 + 1)  # generous read; real cap applied after decompression
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return RawResponse(status=resp.status, headers=hdrs, body=raw, location=hdrs.get("location"))
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Streaming decompression with a hard output cap
# ---------------------------------------------------------------------------

# Content-Encoding -> zlib wbits. 15 (zlib-wrapped deflate) is tried first for
# "deflate"; raw deflate (-15) is the fallback, since servers send both.
_WBITS = {"gzip": 31, "x-gzip": 31, "deflate": 15, "x-deflate": 15, "zlib": 15}
_DECOMPRESS_CHUNK = 64 * 1024
_DECOMPRESS_MAX_STEPS = 100_000  # defensive loop bound


_GZIP_MAGIC = b"\x1f\x8b"


def _inflate_capped(body: bytes, wbits: int, want: int) -> tuple[bytearray, bool] | None:
    """
    Inflate `body` with zlib, producing at most `want` output bytes *total*.

    Returns (output, overflowed), or None if the stream does not decode with
    this wbits at all (so the caller can try another). `overflowed` is True if
    the real decompressed representation exceeds `want`, if compressed input
    was left unconsumed, or if a later concatenated gzip member was malformed
    — i.e. the returned bytes are not the complete, clean payload.

    gzip (wbits 31): concatenated members are valid, so member 2..N are
    processed sequentially under the SAME global output and step budget. A
    later member that is present but malformed is surfaced as overflowed
    rather than silently dropped.
    """
    gzip_multi = wbits == 31
    dobj = zlib.decompressobj(wbits=wbits)
    out = bytearray()
    data = body
    produced_any = False

    for _ in range(_DECOMPRESS_MAX_STEPS):
        if len(out) >= want:
            return out, True
        try:
            piece = dobj.decompress(data or b"", _DECOMPRESS_CHUNK)
        except zlib.error:
            # first member never decoded -> not this format (let caller retry);
            # a later member is malformed -> surface, never accept as complete.
            return None if not produced_any else (out, True)
        if piece:
            produced_any = True
            out.extend(piece)
        data = dobj.unconsumed_tail

        if gzip_multi and dobj.eof and dobj.unused_data[:2] == _GZIP_MAGIC:
            # concatenated gzip member — carry the remaining bytes into a fresh
            # decompressor, staying under the same budget.
            data = dobj.unused_data
            dobj = zlib.decompressobj(wbits=wbits)
            continue

        if not piece and not data:
            break

    trailing = dobj.unused_data if (gzip_multi and dobj.eof) else b""
    incomplete_gzip = gzip_multi and not dobj.eof  # last member never terminated
    overflowed = (
        len(out) >= want
        or bool(data)
        or bool(dobj.unconsumed_tail)
        or bool(trailing)
        or incomplete_gzip
    )
    return out, overflowed


def _decompress(body: bytes, encoding: str | None) -> tuple[bytes, bool]:
    """
    Decompress `body` per Content-Encoding. Streaming: inflation stops as soon
    as MAX_BODY_BYTES + 1 output bytes exist, so a decompression bomb cannot
    expand past the cap in memory. The result is then truncated to
    MAX_BODY_BYTES and `truncated` is set when anything was dropped.
    """
    enc = (encoding or "").lower().strip()
    limit = MAX_BODY_BYTES
    want = limit + 1

    if enc in ("", "identity"):
        return body[:limit], len(body) > limit

    wbits = _WBITS.get(enc)
    if wbits is None:
        # unknown (e.g. br) — no stdlib decoder; keep raw, capped, flagged.
        return body[:limit], True

    for attempt in (wbits, -15) if wbits == 15 else (wbits,):
        result = _inflate_capped(body, attempt, want)
        if result is not None:
            out, overflowed = result
            return bytes(out[:limit]), overflowed or len(out) > limit

    # nothing decoded it — hand back the raw bytes, capped and flagged.
    return body[:limit], len(body) > limit


# ---------------------------------------------------------------------------
# Public fetch
# ---------------------------------------------------------------------------

def guarded_fetch(url: str, *, transport: Transport | None = None, resolver: Resolver | None = None,
                  max_redirects: int = MAX_REDIRECTS, timeout: float = CONNECT_READ_TIMEOUT) -> FetchOutcome:
    transport = transport or _default_transport
    resolver = resolver or _system_resolver
    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    chain: list[dict] = []
    current = url

    for hop in range(max_redirects + 1):
        try:
            resolve_and_validate(current, resolver)
        except RemoteFetchBlocked as exc:
            return FetchOutcome(
                requested_url=url, final_url=None, status=0, content_type=None, body=b"",
                sha256=None, fetched_at=fetched_at, redirect_chain=chain,
                cross_origin_redirect=_chain_crossed_origin(url, chain),
                blocked_reason=str(exc), error=f"blocked: {exc}",
            )

        try:
            raw = transport("GET", current, dict(_STATIC_HEADERS), timeout, resolver)
        except RemoteFetchBlocked as exc:
            return FetchOutcome(
                requested_url=url, final_url=None, status=0, content_type=None, body=b"",
                sha256=None, fetched_at=fetched_at, redirect_chain=chain,
                blocked_reason=str(exc), error=f"blocked: {exc}",
            )
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return FetchOutcome(
                requested_url=url, final_url=None, status=0, content_type=None, body=b"",
                sha256=None, fetched_at=fetched_at, redirect_chain=chain, error=str(exc),
            )

        chain.append({"url": current, "status": raw.status})
        headers = {k.lower(): v for k, v in raw.headers.items()}

        if raw.status in (301, 302, 303, 307, 308):
            location = raw.location or headers.get("location")
            if not location:
                return FetchOutcome(url, current, raw.status, headers.get("content-type"),
                                    b"", None, fetched_at, chain, _chain_crossed_origin(url, chain),
                                    error=f"redirect {raw.status} with no Location")
            nxt = urljoin(current, location)
            if hop == max_redirects:
                return FetchOutcome(url, current, raw.status, None, b"", None, fetched_at, chain,
                                    _chain_crossed_origin(url, chain),
                                    error=f"exceeded {max_redirects} redirects")
            current = nxt
            continue

        body, truncated = _decompress(raw.body, headers.get("content-encoding"))
        return FetchOutcome(
            requested_url=url,
            final_url=current,
            status=raw.status,
            content_type=headers.get("content-type"),
            body=body,
            sha256=hashlib.sha256(body).hexdigest() if raw.status == 200 else None,
            fetched_at=fetched_at,
            redirect_chain=chain,
            cross_origin_redirect=_chain_crossed_origin(url, chain),
            truncated=truncated,
        )

    # unreachable: loop always returns
    return FetchOutcome(url, None, 0, None, b"", None, fetched_at, chain, error="fetch loop fell through")


def _origin(url: str) -> tuple[str, str | None, int]:
    p = urlparse(url)
    return (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80))


def _chain_crossed_origin(start_url: str, chain: list[dict]) -> bool:
    start = _origin(start_url)
    return any(_origin(hop["url"]) != start for hop in chain)
