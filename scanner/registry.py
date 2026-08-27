"""
Mechanical existence and provenance-signal checks for package / domain references.

This module answers two *different* questions and never conflates them:

  1. Existence  -- does a name resolve to a real package / a real domain
     right now?  (registry HTTP lookup / DNS lookup)
  2. Provenance signal -- does the registry metadata for that name point
     back at the vendor the documentation claims to be?  (compare the
     package's declared homepage / repository / project URLs against the
     origin of the document that referenced it)

Existence is not legitimacy. A name that resolves may still be an attacker
squatting a formerly-dangling slot. PR1 does not attempt full provenance
verification (signing, trusted publishers, domain ownership) -- it records
enough signal for the audit layer to distinguish "unclaimed" from "exists,
provenance unverified" from "exists, homepage/repo on the same site as the
documenting origin" (alignment evidence, not proof).

All external state is time-varying: every result carries ``observed_at``
(when the lookup happened) and ``source`` ("live" or "fixture").

Every network call goes through an injectable callable, so the module is
fully testable offline: pass ``http_get`` / ``dns_resolve``, or build a
``RegistryClient.from_fixture(...)`` from a mock-registry JSON snapshot.

No package is ever installed. No domain is contacted beyond a DNS lookup.
Only registry metadata APIs are read.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

USER_AGENT = "semantic-intent-scanner/0.4 (+https://github.com/Ocherokee/semantic-intent-scanner)"

# Ecosystem -> which package-manager commands resolve to it.
ECOSYSTEM_FOR_TOOL = {
    "pip": "pypi",
    "pip3": "pypi",
    "uv": "pypi",
    "uvx": "pypi",
    "pipx": "pypi",
    "poetry": "pypi",
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "npx": "npm",
}

# Index / registry hosts an --index-url / --registry override may point at
# without being treated as a dependency-confusion signal.
OFFICIAL_INDEX_HOSTS = {
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
}

HttpGet = Callable[[str], "HttpResponse"]
DnsResolve = Callable[[str], bool]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class HttpResponse:
    status: int
    body: bytes = b""

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass
class PackageStatus:
    ecosystem: str
    name: str
    exists: bool
    observed_at: str = field(default_factory=_now_iso)
    source: str = "live"  # "live" | "fixture"
    age_days: int | None = None
    latest_version: str | None = None
    maintainer_count: int | None = None
    deprecated: bool = False
    # Hosts the registry metadata associates with this package (homepage,
    # repository, project URLs). Empty means the registry gave us nothing to
    # corroborate provenance with -- NOT that the package is fine.
    provenance_urls: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def newly_registered(self) -> bool:
        return self.age_days is not None and self.age_days < 30


@dataclass
class DomainStatus:
    domain: str
    resolves: bool
    observed_at: str = field(default_factory=_now_iso)
    source: str = "live"
    error: str | None = None


# ---------------------------------------------------------------------------
# Default (real) transports
# ---------------------------------------------------------------------------

def _default_http_get(url: str, timeout: float = 5.0) -> HttpResponse:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - registry API host, json only
            return HttpResponse(status=resp.status, body=resp.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        return HttpResponse(status=exc.code, body=b"")
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        return HttpResponse(status=0, body=str(exc).encode("utf-8"))


def _default_dns_resolve(host: str, timeout: float = 3.0) -> bool:
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

@dataclass
class RegistryClient:
    http_get: HttpGet = _default_http_get
    dns_resolve: DnsResolve = _default_dns_resolve
    mode: str = "live"  # "live" | "fixture" -- propagated to every result's .source
    _cache: dict = field(default_factory=dict, repr=False)

    # -- packages ---------------------------------------------------------

    def check_package(self, ecosystem: str, name: str) -> PackageStatus:
        key = ("pkg", ecosystem, name.lower())
        if key in self._cache:
            return self._cache[key]
        if ecosystem == "pypi":
            status = self._check_pypi(name)
        elif ecosystem == "npm":
            status = self._check_npm(name)
        else:
            status = PackageStatus(ecosystem, name, exists=False, error=f"unknown ecosystem {ecosystem!r}")
        status.source = self.mode
        self._cache[key] = status
        return status

    def _check_pypi(self, name: str) -> PackageStatus:
        resp = self.http_get(f"https://pypi.org/pypi/{name}/json")
        if resp.status == 404:
            return PackageStatus("pypi", name, exists=False)
        if resp.status != 200:
            return PackageStatus("pypi", name, exists=False, error=f"pypi returned {resp.status}")
        try:
            data = resp.json()
        except (ValueError, UnicodeDecodeError) as exc:
            return PackageStatus("pypi", name, exists=True, error=f"unparseable pypi response: {exc}")
        info = data.get("info", {}) or {}
        releases = data.get("releases", {}) or {}
        upload_times = [
            f["upload_time_iso_8601"]
            for files in releases.values()
            for f in files
            if f.get("upload_time_iso_8601")
        ]
        prov = list(info.get("project_urls", {} or {}).values()) if info.get("project_urls") else []
        for extra in (info.get("home_page"), info.get("package_url"), info.get("project_url")):
            if extra:
                prov.append(extra)
        return PackageStatus(
            ecosystem="pypi",
            name=name,
            exists=True,
            age_days=_age_days(min(upload_times)) if upload_times else None,
            latest_version=info.get("version"),
            maintainer_count=None,  # pypi json does not expose the maintainer list
            provenance_urls=_clean_urls(prov),
        )

    def _check_npm(self, name: str) -> PackageStatus:
        resp = self.http_get(f"https://registry.npmjs.org/{name}")
        if resp.status == 404:
            return PackageStatus("npm", name, exists=False)
        if resp.status != 200:
            return PackageStatus("npm", name, exists=False, error=f"npm returned {resp.status}")
        try:
            data = resp.json()
        except (ValueError, UnicodeDecodeError) as exc:
            return PackageStatus("npm", name, exists=True, error=f"unparseable npm response: {exc}")
        created = (data.get("time", {}) or {}).get("created")
        dist_tags = data.get("dist-tags", {}) or {}
        repo = data.get("repository")
        repo_url = repo.get("url") if isinstance(repo, dict) else (repo if isinstance(repo, str) else None)
        bugs = data.get("bugs")
        bugs_url = bugs.get("url") if isinstance(bugs, dict) else (bugs if isinstance(bugs, str) else None)
        prov = [u for u in (data.get("homepage"), repo_url, bugs_url) if u]
        return PackageStatus(
            ecosystem="npm",
            name=name,
            exists=True,
            age_days=_age_days(created) if created else None,
            latest_version=dist_tags.get("latest"),
            maintainer_count=len(data.get("maintainers", []) or []) or None,
            deprecated=bool(data.get("deprecated")),
            provenance_urls=_clean_urls(prov),
        )

    # -- domains ---------------------------------------------------------

    def check_domain(self, domain: str) -> DomainStatus:
        key = ("dns", domain.lower())
        if key in self._cache:
            return self._cache[key]
        try:
            resolves = self.dns_resolve(domain)
            status = DomainStatus(domain=domain, resolves=resolves, source=self.mode)
        except Exception as exc:  # noqa: BLE001 - resolver contract is "return bool or raise"
            status = DomainStatus(domain=domain, resolves=False, source=self.mode, error=str(exc))
        self._cache[key] = status
        return status

    # -- fixtures ------------------------------------------------------

    @classmethod
    def from_fixture(cls, fixture: str | Path | dict) -> "RegistryClient":
        """
        Build a client backed by a mock-registry snapshot. Shape::

            {
              "pypi": {
                "requests":  {"exists": true, "age_days": 3000},
                "foo-sdk":   {"exists": false},
                "vendor-x":  {"exists": true, "age_days": 2,
                              "provenance_urls": ["https://vendor-x.example"]}
              },
              "npm":  {"chalk": {"exists": true}},
              "dns":  {"example.com": true, "nope.invalid": false}
            }

        Unknown names default to *not existing* -- a fixture must name every
        package/domain it expects to be treated as real. Results are marked
        ``source="fixture"`` and still carry an ``observed_at`` (the snapshot
        is a point-in-time observation, not a timeless fact).
        """
        data = fixture if isinstance(fixture, dict) else json.loads(Path(fixture).read_text("utf-8"))
        pkgs = {eco: {k.lower(): v for k, v in (data.get(eco) or {}).items()} for eco in ("pypi", "npm")}
        dns = {k.lower(): bool(v) for k, v in (data.get("dns") or {}).items()}

        def fake_http_get(url: str) -> HttpResponse:
            eco, name = _parse_registry_url(url)
            entry = pkgs.get(eco, {}).get(name.lower())
            if not entry or not entry.get("exists", False):
                return HttpResponse(status=404)
            return HttpResponse(status=200, body=json.dumps(_synth_registry_payload(eco, entry)).encode("utf-8"))

        def fake_dns(host: str) -> bool:
            return dns.get(host.lower(), False)

        return cls(http_get=fake_http_get, dns_resolve=fake_dns, mode="fixture")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_urls(urls: list[str | None]) -> list[str]:
    out: list[str] = []
    for u in urls:
        if not u or not isinstance(u, str):
            continue
        u = u.strip()
        if u.startswith("git+"):
            u = u[4:]
        if u.startswith(("http://", "https://", "git://", "ssh://")) and u not in out:
            out.append(u)
    return out


def _age_days(iso_timestamp: str) -> int | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(iso_timestamp, fmt)
            break
        except ValueError:
            continue
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)


def _parse_registry_url(url: str) -> tuple[str, str]:
    if "pypi.org/pypi/" in url:
        return "pypi", url.split("pypi.org/pypi/", 1)[1].rsplit("/json", 1)[0]
    if "registry.npmjs.org/" in url:
        return "npm", url.split("registry.npmjs.org/", 1)[1]
    return "", ""


def _synth_registry_payload(ecosystem: str, entry: dict) -> dict:
    stamp = _days_ago_iso(entry.get("age_days", 1000))
    prov = entry.get("provenance_urls", []) or []
    if ecosystem == "pypi":
        return {
            "info": {
                "version": entry.get("latest_version", "1.0.0"),
                "project_urls": {f"link{i}": u for i, u in enumerate(prov)},
                "home_page": prov[0] if prov else "",
            },
            "releases": {"1.0.0": [{"upload_time_iso_8601": stamp}]},
        }
    return {
        "time": {"created": stamp},
        "dist-tags": {"latest": entry.get("latest_version", "1.0.0")},
        "maintainers": [{"name": "m"}] * entry.get("maintainer_count", 1),
        "deprecated": entry.get("deprecated", False),
        "homepage": prov[0] if prov else None,
        "repository": {"url": prov[1]} if len(prov) > 1 else None,
    }


def _days_ago_iso(days: int) -> str:
    from datetime import timedelta

    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def index_host_is_official(url: str) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in OFFICIAL_INDEX_HOSTS)
