"""
Audit of a retrieved remote document for transitive-trust risk.

The attack class this represents (llms.txt is only the first instance):

    a remote documentation / instruction surface
      -> an agent retrieves it and treats the retrieved text as authority
      -> the text references or embeds operational instructions
      -> an external package / domain / index / tool is trusted transitively
      -> execution may occur with the agent's or the user's privileges

``analyze_document()`` takes any :class:`RemoteDocument` -- it is not
llms.txt-specific. Format adapters live elsewhere (see
``scanner/llms_txt.py``); this module is the format-agnostic engine.

Two kinds of evidence, kept distinct in every finding:

  * ``analysis_method="rule_based"`` -- produced by parsing the document
    text. Stable given the same bytes.
  * ``analysis_method="external_state"`` -- produced by a live registry /
    DNS lookup. Mechanical, but a snapshot of state that changes over
    time; carries ``observed_at``.
  * ``analysis_method="fixture"`` -- the same lookup answered from an
    offline snapshot (tests).

Existence is never treated as legitimacy. ``provenance_state`` records
which of {unclaimed, unknown, unverified, origin_aligned, conflicting}
applies:

  * ``unclaimed``      -- registry 404 / NXDOMAIN at observation time
  * ``unknown``        -- the lookup failed or was inconclusive
  * ``unverified``     -- the resource exists, but the available evidence
                          does not establish provenance either way (a
                          different-site homepage is NOT a conflict)
  * ``origin_aligned`` -- declared homepage/repository metadata is on the
                          same registrable site as the document origin.
                          Alignment EVIDENCE, not proof of legitimacy.
  * ``conflicting``    -- contradictory / broken provenance evidence (e.g.
                          a declared homepage host that does not resolve)

An existing-but-unverified reference still produces a finding (recorded at
low, raised by aggravators).

Nothing here fetches, executes, or installs anything.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

from .registry import ECOSYSTEM_FOR_TOOL, RegistryClient, index_host_is_official
from .remote_fetch import FetchOutcome

RISK_ORDER = ["low", "medium", "high", "critical"]

# Bundled typosquat targets. Small on purpose -- catches the common cases in
# agent-tooling docs, not an exhaustive registry mirror.
POPULAR_PACKAGES = {
    "pypi": {
        "requests", "urllib3", "boto3", "numpy", "pandas", "flask", "django",
        "fastapi", "pydantic", "httpx", "anthropic", "openai", "langchain",
        "setuptools", "pip", "click", "rich", "pytest",
    },
    "npm": {
        "react", "lodash", "chalk", "express", "axios", "commander", "debug",
        "next", "vue", "typescript", "eslint", "webpack", "vite", "dotenv",
    },
}

# Two-part public suffixes we want _same_site() to treat as one label.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "com.br", "co.in",
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class RemoteDocument:
    origin_url: str
    final_url: str | None
    body: str
    sha256: str | None
    fetched_at: str
    redirect_chain: list[dict] = field(default_factory=list)
    cross_origin_redirect: bool = False
    truncated: bool = False

    @property
    def origin_host(self) -> str:
        return (urlparse(self.final_url or self.origin_url).hostname or "").lower()

    @classmethod
    def from_fetch_outcome(cls, outcome: FetchOutcome) -> "RemoteDocument":
        return cls(
            origin_url=outcome.requested_url,
            final_url=outcome.final_url,
            body=outcome.text(),
            sha256=outcome.sha256,
            fetched_at=outcome.fetched_at,
            redirect_chain=outcome.redirect_chain,
            cross_origin_redirect=outcome.cross_origin_redirect,
            truncated=outcome.truncated,
        )


@dataclass
class InstallCommand:
    raw: str
    tool: str
    ecosystem: str | None
    package: str | None
    kind: str  # pkg_install | vcs_install | pipe_to_shell | script_download
    index_url: str | None = None


@dataclass
class Finding:
    invariant_id: str          # "I5" | "I8"
    finding_type: str          # see module docstring / README
    risk: str                  # low | medium | high | critical
    summary: str
    evidence: str
    analysis_method: str       # rule_based | external_state | fixture
    observed_at: str | None = None
    provenance_state: str | None = None  # unclaimed | unknown | unverified | origin_aligned | conflicting
    detail: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Text extraction (rule-based)
# ---------------------------------------------------------------------------

_INSTALL_RE = re.compile(
    r"""(?P<tool>pip3?|uv\s+pip|uvx|pipx|poetry|npm|pnpm|yarn|bun|npx)\s+
        (?P<verb>install|add|run|i)?\s*
        (?P<args>[^\n\r`]+)""",
    re.VERBOSE,
)
_PIPE_TO_SHELL_RE = re.compile(
    r"(?P<fetch>curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?P<shell>sh|bash|zsh)\b", re.IGNORECASE
)
_SCRIPT_DOWNLOAD_RE = re.compile(
    r"(?:curl|wget)\s+[^\n]*?https?://\S+\.(?:sh|bash|py|ps1)\b", re.IGNORECASE
)
_URL_RE = re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})(?:[/\s)\"']|$)", re.IGNORECASE)
# Text shaped to make the agent *act* on the document rather than read it. Used
# only as an aggravating signal in PR1; a dedicated finding type + the judge
# pass (PR3) handle this shape directly.
_EXEC_FRAMING_RE = re.compile(
    r"(before (responding|you respond|answering|you answer|handling the user"
    r"|your first (message|reply|response))"
    r"|run (these|the following) (steps?|commands?) before"
    r"|execute (this file|these steps|the following|it\b)"
    r"|do not summar(ise|ize) (this|the)"
    r"|add (this|the following) to your (system prompt|agent'?s? (instructions|system prompt)))",
    re.IGNORECASE,
)
_INDEX_FLAG_RE = re.compile(r"--(?:extra-index-url|index-url|registry)[=\s]+(\S+)")
_VERSION_SPLIT_RE = re.compile(r"[=<>~!@\[]")
_VALUE_FLAGS = {
    "--index-url", "--extra-index-url", "--registry", "-i", "-r", "--requirement",
    "-c", "--constraint", "-t", "--target", "--prefix",
}


def extract_install_commands(text: str) -> list[InstallCommand]:
    cmds: list[InstallCommand] = []

    for m in _PIPE_TO_SHELL_RE.finditer(text):
        cmds.append(InstallCommand(m.group(0).strip(), m.group("fetch").lower(), None, None, "pipe_to_shell"))

    for m in _SCRIPT_DOWNLOAD_RE.finditer(text):
        raw = m.group(0).strip()
        if any(raw in c.raw for c in cmds if c.kind == "pipe_to_shell"):
            continue
        cmds.append(InstallCommand(raw, "curl", None, None, "script_download"))

    for m in _INSTALL_RE.finditer(text):
        tool = re.sub(r"\s+", " ", m.group("tool").strip().lower())
        tool_key = "uv" if tool == "uv pip" else tool
        verb = (m.group("verb") or "").lower()
        if tool_key in {"npm", "pnpm", "yarn", "bun"} and verb not in {"install", "i", "add", ""}:
            continue
        if tool_key in {"pip", "pip3", "pipx", "poetry", "uv"} and verb not in {"install", ""}:
            continue
        args = m.group("args").strip()
        im = _INDEX_FLAG_RE.search(args)
        index_url = im.group(1) if im else None
        packages = _packages_from_args(args)
        ecosystem = ECOSYSTEM_FOR_TOOL.get(tool_key)
        raw = f"{tool} {verb} {args}".strip()
        if not packages:
            cmds.append(InstallCommand(raw, tool_key, ecosystem, None, "pkg_install", index_url))
            continue
        for pkg in packages:
            if pkg.startswith(("git+", "http://", "https://")):
                cmds.append(InstallCommand(raw, tool_key, ecosystem, None, "vcs_install", index_url))
            else:
                cmds.append(InstallCommand(raw, tool_key, ecosystem, pkg, "pkg_install", index_url))
    return _dedupe(cmds)


def _packages_from_args(args: str) -> list[str]:
    out: list[str] = []
    skip_next = False
    for tok in args.split():
        if skip_next:
            skip_next = False
            continue
        if tok in _VALUE_FLAGS:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        if tok in {"install", "add", "run", "i"}:
            continue
        if tok in {".", ".."} or tok.endswith((".txt", ".toml", ".lock", ".json", ".cfg")):
            continue
        if tok.startswith(("git+", "http://", "https://")):
            out.append(tok)
            continue
        if tok.startswith("@"):
            m = re.match(r"^(@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", tok)
            name = m.group(1) if m else tok
        else:
            name = _VERSION_SPLIT_RE.split(tok, 1)[0].strip().strip('"').strip("'")
        if name and re.match(r"^@?[A-Za-z0-9._/\-]+$", name):
            out.append(name)
    return out


def extract_referenced_domains(text: str, *, exclude_host: str | None = None) -> list[str]:
    seen: dict[str, None] = {}
    for m in _URL_RE.finditer(text):
        host = m.group(1).lower().rstrip(".")
        if exclude_host and _same_site(host, exclude_host):
            continue
        seen.setdefault(host, None)
    return list(seen)


def _dedupe(cmds: list[InstallCommand]) -> list[InstallCommand]:
    seen, out = set(), []
    for c in cmds:
        key = (c.tool, c.ecosystem, c.package, c.kind, c.index_url)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


# ---------------------------------------------------------------------------
# Site / provenance helpers
# ---------------------------------------------------------------------------

def _registrable(host: str) -> str:
    host = (host or "").lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _same_site(a: str, b: str) -> bool:
    if not a or not b:
        return False
    a, b = a.lower().strip("."), b.lower().strip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a) or _registrable(a) == _registrable(b)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_target(ecosystem: str | None, name: str) -> str | None:
    if not ecosystem:
        return None
    bare = name.split("/")[-1].lower()
    for popular in POPULAR_PACKAGES.get(ecosystem, ()):
        if bare != popular and _levenshtein(bare, popular) <= 2 and abs(len(bare) - len(popular)) <= 2:
            return popular
    return None


def _bump(risk: str, steps: int = 1) -> str:
    return RISK_ORDER[min(len(RISK_ORDER) - 1, RISK_ORDER.index(risk) + steps)]


def _method_for(source: str) -> str:
    return "fixture" if source == "fixture" else "external_state"


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_document(doc: RemoteDocument, registry: RegistryClient | None = None) -> list[Finding]:
    registry = registry or RegistryClient()
    findings: list[Finding] = []
    host = doc.origin_host
    src = {"source_url": doc.final_url or doc.origin_url, "source_sha256": doc.sha256}

    if doc.cross_origin_redirect:
        findings.append(Finding(
            "I8", "cross_origin_instruction", "medium",
            "the document was retrieved via a redirect to a different origin than requested",
            " -> ".join(h["url"] for h in doc.redirect_chain) or f"{doc.origin_url} -> {doc.final_url}",
            analysis_method="rule_based", observed_at=doc.fetched_at,
            detail={**src, "redirect_chain": doc.redirect_chain},
        ))

    commands = extract_install_commands(doc.body)
    doc_has_execution = (
        any(c.kind in ("pipe_to_shell", "script_download") for c in commands)
        or bool(_EXEC_FRAMING_RE.search(doc.body))
    )

    for cmd in commands:
        findings.extend(_analyze_command(cmd, registry, doc, host, src, doc_has_execution))

    for domain in extract_referenced_domains(doc.body, exclude_host=host):
        f = _analyze_domain(domain, registry, host, src)
        if f:
            findings.append(f)

    return findings


def _analyze_command(cmd: InstallCommand, registry: RegistryClient, doc: RemoteDocument,
                     host: str, src: dict, doc_has_execution: bool) -> list[Finding]:
    detail = {**src, "raw": cmd.raw}

    if cmd.kind == "pipe_to_shell":
        return [Finding("I5", "pipe_to_shell", "high",
                        "the document tells the agent to pipe a downloaded script straight into a shell",
                        cmd.raw, analysis_method="rule_based", observed_at=doc.fetched_at, detail=detail)]
    if cmd.kind == "script_download":
        return [Finding("I5", "script_download", "medium",
                        "the document instructs downloading and running a remote script",
                        cmd.raw, analysis_method="rule_based", observed_at=doc.fetched_at, detail=detail)]

    out: list[Finding] = []

    if cmd.index_url and not index_host_is_official(cmd.index_url):
        idx_host = urlparse(cmd.index_url).hostname or ""
        dstatus = registry.check_domain(idx_host)
        unclaimed = not dstatus.resolves and dstatus.error is None
        out.append(Finding(
            "I8", "index_url_override", "critical" if unclaimed else "high",
            "the install command redirects the package index to a non-official host"
            + (" that does not resolve (an unclaimed slot)" if unclaimed else ""),
            cmd.index_url, analysis_method=_method_for(dstatus.source),
            observed_at=dstatus.observed_at,
            provenance_state="unclaimed" if unclaimed else "unverified",
            detail={**detail, "index_url": cmd.index_url, "index_resolves": dstatus.resolves},
        ))

    if cmd.kind == "vcs_install":
        out.append(Finding(
            "I8", "vcs_install", "medium",
            "the install command pulls a package directly from a VCS URL (provenance not checked in PR1)",
            cmd.raw, analysis_method="rule_based", observed_at=doc.fetched_at, detail=detail,
        ))
        return out

    if not cmd.package or not cmd.ecosystem:
        return out

    status = registry.check_package(cmd.ecosystem, cmd.package)
    method = _method_for(status.source)
    squat = _typosquat_target(cmd.ecosystem, cmd.package)

    if not status.exists and status.error is None:
        out.append(Finding(
            "I8", "dangling_package", "critical",
            f"the install command names a {cmd.ecosystem} package that is not registered "
            f"(an unclaimed slot an attacker can register later)",
            cmd.package, analysis_method=method, observed_at=status.observed_at,
            provenance_state="unclaimed",
            detail={**detail, "ecosystem": cmd.ecosystem, "package": cmd.package,
                    "resembles": squat},
        ))
        return out

    if status.error:
        out.append(Finding(
            "I8", "unverified_package_provenance", "medium",
            f"could not verify the {cmd.ecosystem} package (registry lookup error) -- treat as unverified",
            f"{cmd.package}: {status.error}", analysis_method=method,
            observed_at=status.observed_at, provenance_state="unknown", detail=detail,
        ))
        return out

    # Package exists. Existence is NOT legitimacy -- classify provenance.
    state, why = _classify_existing_package(status, host, registry)
    aggravated = (
        bool(squat) or status.newly_registered or status.deprecated
        or bool(cmd.index_url) or doc_has_execution or state == "conflicting"
    )

    if state == "origin_aligned" and not aggravated:
        # Positive alignment evidence and nothing else concerning. Recorded at
        # low so a reviewer/judge sees the state -- alignment is not proof.
        out.append(Finding(
            "I8", "unverified_package_provenance", "low",
            f"{cmd.ecosystem} package '{cmd.package}': provenance {state} -- {why}",
            cmd.package, analysis_method=method, observed_at=status.observed_at,
            provenance_state=state,
            detail={**detail, "ecosystem": cmd.ecosystem, "package": cmd.package,
                    "age_days": status.age_days, "provenance_urls": status.provenance_urls,
                    "documented_origin": host, "resembles": squat},
        ))
        return out

    # Base severity by state; every risk signal on top raises it.
    risk = "medium" if state == "conflicting" else "low"
    reasons = [why]

    if squat:
        risk = "high" if RISK_ORDER.index(risk) < RISK_ORDER.index("high") else risk
        reasons.append(f"name is one edit from the popular package {squat!r}")
    elif status.newly_registered:
        risk = _bump(risk)
        reasons.append(f"registered only {status.age_days} days ago")

    if status.deprecated:
        risk = _bump(risk) if risk == "low" else risk
        reasons.append("package is marked deprecated")
    if cmd.index_url:
        risk = _bump(risk)
        reasons.append("install command also overrides the package index")
    if doc_has_execution:
        risk = _bump(risk)
        reasons.append("same document also contains run-this / run-before-responding instructions")

    out.append(Finding(
        "I8", "unverified_package_provenance", risk,
        f"{cmd.ecosystem} package '{cmd.package}' exists but provenance is {state}: "
        + "; ".join(reasons),
        cmd.package, analysis_method=method, observed_at=status.observed_at,
        provenance_state=state,
        detail={**detail, "ecosystem": cmd.ecosystem, "package": cmd.package,
                "age_days": status.age_days, "provenance_urls": status.provenance_urls,
                "documented_origin": host, "resembles": squat},
    ))
    return out


def _classify_existing_package(status, doc_host: str, registry: RegistryClient) -> tuple[str, str]:
    """
    Return (provenance_state, explanation) for a package that EXISTS.

    PR1 does no full provenance verification (no trusted-publisher data, no
    signing check). From registry metadata alone it distinguishes:

      conflicting    -- a declared homepage/repository host does not resolve;
                        the evidence the package offers about itself is broken
      origin_aligned -- a declared homepage/repository URL is on the same
                        registrable site as the document origin. Positive
                        ALIGNMENT evidence -- not proof of legitimacy.
      unverified     -- the package exists but the available evidence does not
                        establish provenance either way. A different-site
                        homepage (e.g. code on github.com, docs on the vendor
                        site) is NOT a conflict -- it just isn't alignment.

    'mismatched' / true identity conflict is reserved for contradictory
    provenance evidence PR1 does not yet gather.
    """
    prov_hosts = sorted({(urlparse(u).hostname or "").lower() for u in status.provenance_urls} - {""})
    if not prov_hosts:
        return "unverified", f"the registry exposes no homepage/repository metadata to check against {doc_host!r}"

    aligned = any(_same_site(h, doc_host) for h in prov_hosts)
    dead = [h for h in prov_hosts
            if (d := registry.check_domain(h)).error is None and not d.resolves]
    if dead and not aligned:
        return "conflicting", f"a declared homepage/repository host does not resolve ({dead})"
    if aligned:
        return "origin_aligned", (
            "a declared homepage/repository URL is on the same registrable site as the document "
            "origin (alignment evidence, not proof of legitimacy)"
        )
    return "unverified", (
        f"declared URLs {prov_hosts} are on different sites than the document origin {doc_host!r}; "
        "not a conflict by itself, but provenance is not established"
    )


def _analyze_domain(domain: str, registry: RegistryClient, host: str, src: dict) -> Finding | None:
    status = registry.check_domain(domain)
    method = _method_for(status.source)
    if not status.resolves and status.error is None:
        return Finding(
            "I8", "dangling_domain", "critical",
            "the document references a domain that does not resolve (an unclaimed slot)",
            domain, analysis_method=method, observed_at=status.observed_at,
            provenance_state="unclaimed", detail={**src, "domain": domain},
        )
    if status.error:
        return Finding(
            "I8", "unverified_domain_provenance", "medium",
            "could not resolve the referenced domain (lookup error) -- treat as unverified",
            f"{domain}: {status.error}", analysis_method=method,
            observed_at=status.observed_at, provenance_state="unknown", detail={**src, "domain": domain},
        )
    if _same_site(domain, host):
        return None  # same site as the document itself
    return Finding(
        "I8", "unverified_domain_provenance", "low",
        f"the document points at a third-party domain; nothing corroborates that {host!r} controls it",
        domain, analysis_method=method, observed_at=status.observed_at,
        provenance_state="unverified", detail={**src, "domain": domain, "documented_origin": host},
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def overall_risk(findings: list[Finding]) -> str:
    return max((f.risk for f in findings), key=RISK_ORDER.index) if findings else "low"


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
