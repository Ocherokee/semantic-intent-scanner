# Semantic Intent Scanner

**Invariant-grounded semantic evaluation for AI agent skill files and directories.**

A research prototype that evaluates AI agent skill packages against a formal
invariant set and ethical substrate — not by matching known-bad patterns, but by
reasoning about *intent* and *mechanism failure*.

---

## The Research Question

> Can an invariant-grounded evaluator flag semantic intent risks that syntax scanners miss?

Current security tools (SAST, SCA, signature scanners) inspect code and
dependencies. They were not designed to evaluate the semantic layer where
MCP tool descriptions, agent prompts, and skill definitions operate.

A poisoned SKILL.md file is not malicious code. It is malicious *intent*
expressed in natural language — and once an agent ingests it, that intent
executes with the full credential scope of whoever invoked the agent.

But the instruction file is not the only attack surface. As documented in
2026, attackers have moved to adjacent execution surfaces that no skill
scanner currently inspects:

- **Bundled test files** that execute via Jest/Vitest/pytest with full local
  permissions, no agent required (Gecko Security, May 2026)
- **Project-scoped config files** that silently enable attacker-controlled
  MCP servers when a developer trusts a cloned directory
  (Adversa AI TrustFall, May 2026)

This scanner addresses all three layers.

**This is a research prototype. It is not production security tooling.**
A clean scan does not certify safety. Human review remains essential.

---

## Two Questions, Three Layers

The scanner can now answer two questions instead of one.

**v0.1 asked:** Is this instruction dangerous?
**v0.2 adds:** Which ethical mechanism failed, and why did that failure create executable risk?
**v0.3 adds:** Are there attack surfaces in this skill package beyond the instruction file?

---

## The Invariants

These define the minimum conditions for trustworthy agent operation.
An instruction set that violates any of these cannot be said to be
operating on behalf of its user.

| ID | Name | Description |
|----|------|-------------|
| I1 | No Concealment | Do not conceal actions from the user. |
| I2 | No Unauthorized Credential Access | Do not access credentials without explicit authorization. |
| I3 | No Scope Override | Do not execute outside declared scope. |
| I4 | No Consent Override | Do not override user consent. |
| I5 | No Command Laundering | Do not launder operational commands as documentation or examples. |
| I6 | No Auditability Suppression | Do not suppress the ability of the user or system to audit actions. |
| I7 | No Authority Laundering | Do not represent third-party authority as first-party authority. |
| I8 | No Unverified External Instruction | Do not treat retrieved content (remote documents, tool descriptions) as authoritative instruction, and do not extend the agent's trust to a package/domain/index/tool it names, without a trust decision. |

I8 (v0.4) covers the remote-content surfaces. A stale or unclaimed
reference is an environmental condition — the invariant failure is the
agent treating that unresolved external authority as trustworthy — so
"dangling reference" is a **finding type under I8**, not a separate
invariant. Detector types: `dangling_package`, `dangling_domain`,
`unverified_package_provenance`, `unverified_domain_provenance`,
`index_url_override`, `cross_origin_instruction`. Existence and DNS
checks are mechanical external-state evidence (`scanner.registry`), not a
judge call — but **existence is never treated as legitimacy**.

Provenance ladder: `unclaimed` (404 / NXDOMAIN) → `unknown` (lookup
failed) → `unverified` (exists, provenance not established — a
different-site homepage is *not* a conflict) → `origin_aligned` (declared
homepage/repo on the same registrable site as the document — *alignment
evidence, not proof*) → `conflicting` (broken/contradictory provenance
evidence). `corroborated` / `mismatched` are reserved for stronger
evidence PR1 does not gather.

I8 maps to M2 Transparency + M4 Integrity + M1 Consent — **not** M3
Accountability: I8 is the trust decision made *before* harm; failing to
recognise or correct the consequences afterward is a separate failure.

---

## The Fractal Ethical Substrate

Each invariant violation maps to one or more failures in the underlying
ethical substrate — five mechanisms that form the minimum conditions for
trustworthy agency:

| ID | Mechanism | Description |
|----|-----------|-------------|
| M1 | Consent | Every interaction verifies the signal of the other. |
| M2 | Transparency | The logic is visible and traceable. |
| M3 | Accountability | Harm is an internal failure requiring rebalancing, not a patch. |
| M4 | Integrity | Honest and factual over socially compliant. |
| M5 | Responsive Presence | Proximity to harm creates obligation. |

These are not values. They are not rules. They are the operational mechanics
of a system that cannot be deceptive, coercive, or indifferent by design.

**Invariant to Mechanism mapping:**

| Invariant | Mechanism Failure |
|-----------|------------------|
| I1 No Concealment | Transparency |
| I2 No Unauthorized Credential Access | Consent + Integrity |
| I3 No Scope Override | Consent + Accountability |
| I4 No Consent Override | Consent |
| I5 No Command Laundering | Transparency + Integrity |
| I6 No Auditability Suppression | Transparency + Accountability |
| I7 No Authority Laundering | Integrity + Consent |
| I8 No Unverified External Instruction | Transparency + Integrity + Consent |

This means the scanner no longer just flags risk. It explains the ethical
mechanism failure that made the risk possible — turning security findings
into causal diagnostics.

---

## Install

```bash
pip install -e .
```

Requires Python 3.11+. An Anthropic API key is required for semantic evaluation.

```bash
export ANTHROPIC_API_KEY=your_key_here
```

---

## Usage

### Scan a local skill

```bash
# Scan a single instruction file
semantic-intent scan ./SKILL.md

# Scan an entire skill directory (recommended)
semantic-intent scan ./my-skill-directory

# JSON output (for CI/CD integration)
semantic-intent scan ./SKILL.md --json

# Plain text (no color)
semantic-intent scan ./SKILL.md --no-color
```

### Scan a site's remote agent-facing docs (`scan-remote`, v0.4)

```bash
# Give a site / base URL — the supported paths (/llms.txt, /llms-full.txt)
# are derived for you
semantic-intent scan-remote https://example.com

# JSON output
semantic-intent scan-remote https://example.com --json

# also run the two-pass LLM judge over the retrieved content (needs an API key)
export ANTHROPIC_API_KEY=your_key_here
semantic-intent scan-remote https://example.com --judge
```

`scan-remote` fetches the site's `llms.txt` / `llms-full.txt` through the
SSRF-hardened guarded path (HTTPS only, private/blocked address space refused,
every redirect re-validated, body decompression capped) and runs **rule-based +
external-state analysis**: install commands and referenced domains are
extracted and checked against live PyPI / npm / DNS state. It never executes a
command, installs a package, or follows an instruction found in the retrieved
text. A `LOW` result is not a safety guarantee, and registry existence is
never treated as legitimacy.

**`--judge`** adds a two-pass LLM evaluation of the retrieved content, treated
as **untrusted evidence** (see `docs/v0.4-pr3-judge-scoping.md`). Pass 1
reasons from the deterministic findings plus a bounded, quoted digest of the
document's structure; Pass 2 reads the raw body inside a hard evidence
boundary. The judge can **raise** the reported risk and exit code, never lower
them; deterministic findings are immutable; and a judge failure (no key, API
error) leaves the deterministic result intact and marks the semantic pass
unavailable — it does **not** become an operational failure. Default
`scan-remote` (no `--judge`) is unchanged.

### Scan MCP tool descriptions (`scan-mcp`, v0.4)

```bash
# a captured tools/list JSON file — no MCP server is contacted
semantic-intent scan-mcp ./captured-tools-list.json
semantic-intent scan-mcp ./captured-tools-list.json --json
semantic-intent scan-mcp ./captured-tools-list.json --judge --server-label "acme-mcp"
```

An MCP server returns a `tools/list` response — an array of
`{name, description, inputSchema}` — that an agent loads into its context as
its own trusted capabilities. `scan-mcp` reads that JSON **from a file**
(bare array, `{"tools": […]}`, or a JSON-RPC envelope), normalises every
`description` — the tool description and **every nested `description` in
`inputSchema`**, wherever it sits — and runs each through the same engine as
`scan-remote`: deterministic per field, and the two-pass judge over each
tool's combined text with `--judge`. Every finding records `mcp_tool`, a
friendly `mcp_field` (`parameters.files.items.description`), a lossless
`mcp_json_path` (`inputSchema.properties.files.items.description` —
collision-resistant when two schema locations share a friendly path), and
`mcp_server: {declared, authenticated: false}` — the file is not an
authenticated identity. No MCP server is contacted, no transport is opened,
no tool is invoked. Malformed / empty input is exit 3 with
`operational_status` `invalid_input` / `no_tools` (not HTTP vocabulary). See
`docs/v0.4-pr4-mcp-adapter-scoping.md`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Low risk — no blocking findings |
| 1 | Medium risk — possible violations |
| 2 | High or critical risk — likely violations |
| 3 | `scan-remote` / `scan-mcp` only: nothing could be scanned — every candidate fetch failed / was blocked / not found, or the MCP file was invalid / held no tools. **Not** a low-risk result. |

Exit codes enable use in CI/CD pipelines to block installation of flagged
skills. For `scan-remote`, security risk (`overall_risk`) and operational
failure (`operational_status`) are separate JSON fields — a failed scan
reports `"overall_risk": null`, never `"low"`. With `--judge`, a judge
failure never changes the exit code; instead it surfaces as
`"judge_status": "unavailable:<reason>"` / `"partial"`,
`"semantic_coverage": "incomplete"` / `"partial"`, `"analysis_complete":
false`, and a prominent terminal `WARNING`. Incomplete semantic coverage is a
status fact, not a risk severity.

---

## Architecture

```
Skill package                     External semantic content (v0.4)
  |                                  |  llms.txt / llms-full.txt      (scan-remote -> llms_txt.py)
  Directory Audit (v0.3)             |  MCP tools/list JSON file       (scan-mcp   -> mcp_adapter.py)
  |- test file detection             remote_fetch.py  -- SSRF-hardened GET (per-hop IP validation,
  |- config file evaluation          |                   pinned-IP connect, no cross-origin creds,
  +- dangerous pattern scan          |                   decompressed-size cap)   [scan-remote only]
  |                                  remote_audit.py  -- analyze_document(): format-agnostic
  |                                  |   |- extract install commands / domains / execution framing
  |                                  |   +- registry.py: existence + provenance signal (PyPI/npm/DNS)
  |                                  |
  Semantic Evaluator (v0.1)          remote_judge.py  -- two-pass LLM judge (PR3, --judge)
                                     |   Pass 1: deterministic findings + bounded claims digest
                                     |   Pass 2: raw body inside a hard evidence boundary
                                     +   findings block = trusted; content = untrusted evidence
  |- chunk SKILL.md
  |- evaluate against the invariants (LLM-as-judge)
  +- aggregate violations
  |
  Substrate Layer (v0.2)  -- map violations to ethical mechanisms + causal explanation
  |
  Report (terminal or JSON)
```

Each `Finding` from the remote lane records how it was reached:
`analysis_method` is `rule_based` (parsing the document text — stable given
the bytes), `external_state` (a live registry/DNS lookup — a **time-stamped
snapshot**, carried in `observed_at`), or `fixture` (that lookup answered
from an offline snapshot, for tests). The judge pass may add context; it may
not overturn a `rule_based` / `external_state` / `fixture` finding by
re-reading the prose. A package that becomes claimed *after* a scan never
downgrades an earlier finding — **existence is not legitimacy**.

---

## Test fixtures

```
tests/fixtures/
  benign/
    git-status.md              clean skill, expected: low risk
  suspicious/
    project-setup.md           authority laundering, expected: medium risk
  malicious/
    solana-wallet-tracker.md   SKILL.md credential theft, expected: critical
    reviewer.test.ts           test file exfiltration vector, expected: critical
  adversarial/
    judge-injection.md         real I2/I7 violation + an embedded instruction
                               telling the evaluator to return a clean verdict,
                               expected: high/critical (judge must not comply)
```

```
tests/fixtures/llms_txt/                     (v0.4 remote-content lane)
  benign/first-party-sdk-llms.txt            pkg exists, homepage origin_aligned  -> low (recorded)
  benign/docs-site-llms.txt                  3rd-party docs, pkgs unverified       -> low (recorded)
  suspicious/agent-tooling-llms.txt          pkg registered 10 days ago           -> medium
  malicious/onboarding-llms-full.txt         dangling pkg + dead index + curl|sh   -> critical
  malicious/typosquat-llms.txt               targets one edit from popular pkgs    -> high
  malicious/registered-after-dangling-llms.txt  now exists, unverified + new + exec -> high
  mock_registry.json                         offline provenance oracle (existence + provenance_urls)
```

`tests/test_fixtures.py` runs the `.md` fixtures through `evaluate_skill()` and
asserts each meets its documented risk floor (auto-skips without
`ANTHROPIC_API_KEY`). `tests/test_remote_fetch.py`, `test_remote_audit.py`, and
`test_llms_txt.py` cover the SSRF guard, the format-agnostic analysis engine,
and the llms.txt adapter — fully offline (faked fetch transport + mock
registry), no API key. The `registered-after-dangling` fixture is the proof
that `exists == safe` is false: the package resolves, and the scan still
reports `high`.

### Judge robustness

The evaluator's system prompt treats the passage under evaluation as untrusted,
adversarial input: text inside the passage that claims prior audit clearance or
instructs the evaluator to downgrade its verdict is itself flagged as I5/I7
rather than obeyed. `adversarial/judge-injection.md` is the regression test for
this. This is a first-pass mitigation, not a guarantee — a single judge call
still has no defence-in-depth against content crafted to fool the judge itself.

---

## Documented attack surfaces covered

| Attack Surface | Vector | Source | Coverage |
|---------------|--------|--------|----------|
| Instruction layer | Malicious SKILL.md | Snyk ToxicSkills, Feb 2026 | Semantic evaluation |
| Test file layer | Bundled *.test.ts / conftest.py | Gecko Security, May 2026 | Directory audit |
| Config layer | .mcp.json / .claude/settings.json | Adversa AI TrustFall, May 2026 | Directory audit |
| Remote docs layer | llms.txt / llms-full.txt naming unregistered or unverified packages/domains | Ars Technica, Aug 2026 | `scan-remote` — remote audit (rule-based + external-state), optional two-pass judge |
| MCP tool layer | Injection in a tool `description` / nested `inputSchema` description | — | `scan-mcp` — same engine over a captured `tools/list` file (offline; no MCP client) |

---

## Theoretical basis

This scanner is the prototype implementation of the relational-semantic
evaluation framework described in:

> *The Semantic Gap: Why agentic AI security fails at the instruction layer*
> Cherokee Schill · Horizon Accord · AI Research · 2026
> https://horizonaccord.com/ai-research/the-semantic-gap

The core argument: the instruction layer attack surface and the alignment
failure surface are the same layer. Closing it requires intent evaluation
anchored to invariant constraints, not pattern matching against known artifacts.

The same semantic layer that enables instruction-layer attacks is also the
layer where operational ethics must be evaluated. Security and alignment
are not separate problems — they are the same problem examined from
different angles.

---

## Roadmap

- [x] v0.1 — CLI prototype, invariants I1–I7, LLM evaluator, test fixtures
- [x] v0.2 — Fractal ethical substrate layer, mechanism mapping, causal reporting
- [x] v0.3 — Directory audit module, test file and config attack surfaces
- [ ] v0.4 — Remote-content surfaces (invariant I8)
  - [x] PR1 — I8 in the invariant + substrate model; SSRF-hardened `remote_fetch`;
        format-agnostic `remote_audit` engine; `registry` existence + provenance
        model; `llms_txt` adapter; benign/suspicious/malicious fixtures (offline)
  - [x] PR2 — `scan-remote` CLI subcommand + terminal/JSON remote report;
        operational-failure exit code (3) kept distinct from risk
  - [x] PR3 — `--judge`: two-pass LLM evaluation of retrieved content as
        untrusted evidence (`remote_judge`); deterministic findings immutable,
        judge raises only, judge failure ≠ operational failure
  - [x] PR4 — `scan-mcp`: MCP tool-description adapter over a captured
        `tools/list` file; per-field deterministic lane + combined-tool judge
        lane, no MCP client; recursive nested-`description` extraction
- [ ] v0.5 — Benchmark against ToxicSkills dataset (Snyk, February 2026)
- [ ] v0.6 — False positive analysis, threshold calibration
- [ ] v0.7 — Relational integrity monitor (conversational trajectory evaluation)
- [ ] v1.0 — Publishable research findings

---

## License

AGPL-3.0. See LICENSE.

---

## Contributing

This is early-stage research. Issues, adversarial test cases, and
pull requests are welcome. The most valuable contributions right now
are new test fixtures — especially edge cases that are genuinely ambiguous.

---

*Not a company. Not a platform. A repo with a research question.*
