# Semantic Intent Scanner

**Invariant-grounded semantic evaluation for AI agent skill files and directories.**

A research prototype that evaluates AI agent skill packages and external semantic
content against a formal invariant set and ethical substrate — not by matching
known-bad patterns, but by reasoning about *intent* and *mechanism failure*.

---

## Quick start

```bash
pip install -e .              # Python 3.11+
export ANTHROPIC_API_KEY=...   # needed for semantic judge paths
```

```bash
# Audit a local skill package
semantic-intent scan ./path/to/skill-directory/

# Scan a site's llms.txt / llms-full.txt through the guarded remote lane
semantic-intent scan-remote https://example.com

# Add the two-pass semantic judge
semantic-intent scan-remote https://example.com --judge

# Audit a captured MCP tools/list response — no MCP server is contacted
semantic-intent scan-mcp ./captured-tools-list.json
```

Run it against the repo's own fixtures to see a real offline detection in a few
seconds (no API key required for this one):

```text
$ semantic-intent scan tests/fixtures/malicious/

Semantic Intent Scanner — Directory Audit
Directory: tests/fixtures/malicious

Directory Risk: CRITICAL

Suspicious files found (1):

  tests/fixtures/malicious/reviewer.test.ts — CRITICAL
     Type:   test_file
     Reason: Test files are auto-discovered by Jest, Vitest, and Mocha via
             recursive glob patterns. Code in beforeAll() blocks executes
             silently during test runs, with full access to environment
             variables and the filesystem. Contains both credential access
             and network exfiltration patterns — consistent with data theft.
     Patterns detected: credential_access, filesystem_access, shell_execution, network_exfiltration
```

Exit codes are usable in CI: `0` low, `1` medium, `2` high/critical. Remote and
MCP scans also use `3` for **nothing analyzable** — an operational failure, not a
low-risk result.

---

## The Research Question

> Can an invariant-grounded evaluator flag semantic intent risks that syntax scanners miss?

Current security tools (SAST, SCA, signature scanners) inspect code and
dependencies. They were not designed to evaluate the semantic layer where MCP
tool descriptions, agent prompts, skill definitions, and retrieved agent-facing
documents operate.

A poisoned SKILL.md file is not malicious code. It is malicious *intent*
expressed in natural language — and once an agent ingests it, that intent can
shape behavior with the credential and capability scope of the invoking agent.

But the instruction file is not the only attack surface. As documented in 2026,
attackers have moved to adjacent execution surfaces:

- **Bundled test files** that execute via Jest/Vitest/pytest with full local
  permissions, no agent required (Gecko Security, May 2026)
- **Project-scoped config files** that silently enable attacker-controlled MCP
  servers when a developer trusts a cloned directory (Adversa AI TrustFall,
  May 2026)
- **Retrieved remote content** such as `llms.txt` / `llms-full.txt`, where an
  agent may extend trust to packages, domains, indexes, or instructions named by
  an external document
- **MCP tool metadata**, where tool descriptions and nested parameter
  descriptions enter the agent's context as capability guidance

This scanner covers several of those surfaces: local instruction files, bundled
test/config files, guarded remote documents, and captured MCP `tools/list`
metadata. That is **not** a claim to cover every instruction, configuration,
execution, or retrieved-content surface an agent can touch.

**This is a research prototype. It is not production security tooling.**
A clean scan does not certify safety. Human review remains essential.

---

## What the scanner asks

The scanner now answers several questions, not one.

**v0.1 asked:** Is this instruction dangerous?  
**v0.2 adds:** Which ethical mechanism failed, and why did that failure create executable risk?  
**v0.3 adds:** Are there attack surfaces in this skill package beyond the instruction file?  
**v0.4 adds:** Is external semantic content being allowed to direct behavior or extend trust without a trust decision — including remote documents and MCP tool metadata?

---

## The Invariants

These define the minimum conditions for trustworthy agent operation. An
instruction set that violates any of these cannot be said to be operating on
behalf of its user.

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

I8 (v0.4) covers remote-content surfaces. A stale or unclaimed reference is an
environmental condition — the invariant failure is the agent treating that
unresolved external authority as trustworthy — so "dangling reference" is a
**finding type under I8**, not a separate invariant. Detector types include
`dangling_package`, `dangling_domain`, `unverified_package_provenance`,
`unverified_domain_provenance`, `index_url_override`, and
`cross_origin_instruction`. Existence and DNS checks are mechanical
external-state evidence (`scanner.registry`), not a judge call — but
**existence is never treated as legitimacy**.

Provenance ladder: `unclaimed` (404 / NXDOMAIN) → `unknown` (lookup failed) →
`unverified` (exists, provenance not established) → `origin_aligned` (declared
homepage/repo on the same registrable site as the document — *alignment
evidence, not proof*) → `conflicting` (broken/contradictory provenance evidence).
`corroborated` / `mismatched` are reserved for stronger evidence not yet gathered.

I8 maps to M2 Transparency + M4 Integrity + M1 Consent — **not** M3
Accountability: I8 is the trust decision made *before* harm; failing to recognize
or correct consequences afterward is a separate failure.

---

## The Fractal Ethical Substrate

Each invariant violation maps to one or more failures in the underlying ethical
substrate — five mechanisms that form the minimum conditions for trustworthy
agency:

| ID | Mechanism | Description |
|----|-----------|-------------|
| M1 | Consent | Every interaction verifies the signal of the other. |
| M2 | Transparency | The logic is visible and traceable. |
| M3 | Accountability | Harm is an internal failure requiring rebalancing, not a patch. |
| M4 | Integrity | Honest and factual over socially compliant. |
| M5 | Responsive Presence | Proximity to harm creates obligation. |

These are not values. They are not rules. They are the operational mechanics of
a system that cannot be deceptive, coercive, or indifferent by design.

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

This means the scanner does not only flag risk. It explains the ethical
mechanism failure that made the risk possible — turning security findings into
causal diagnostics.

---

## Install

```bash
pip install -e .
```

Requires Python 3.11+. The deterministic directory/remote/MCP lanes can run
without a model. Semantic judge paths require an Anthropic API key.

```bash
export ANTHROPIC_API_KEY=your_key_here
```

---

## Usage

### Scan a local skill

```bash
semantic-intent scan ./SKILL.md
semantic-intent scan ./my-skill-directory
semantic-intent scan ./SKILL.md --json
semantic-intent scan ./SKILL.md --no-color
```

### Scan remote agent-facing docs

```bash
# /llms.txt and /llms-full.txt are derived from the site/base URL
semantic-intent scan-remote https://example.com
semantic-intent scan-remote https://example.com --json

# Optional two-pass semantic judge
semantic-intent scan-remote https://example.com --judge
```

`scan-remote` uses the SSRF-hardened guarded fetch path: HTTPS only,
private/blocked address space refused, every redirect revalidated, pinned-IP
transport, and a decompressed-body cap. It runs **rule-based + external-state**
analysis over install commands, referenced domains, and provenance signals. It
never executes a command, installs a package, or follows an instruction found in
the retrieved text.

`--judge` adds a two-pass LLM evaluation of the retrieved content as **untrusted
evidence**. Pass 1 sees immutable deterministic findings plus a bounded,
quoted structural digest. Pass 2 sees raw content only inside a hard-delimited
`RETRIEVED_CONTENT` evidence block. Deterministic findings are append-only and
non-downgradeable; the judge may add context or raise risk, never lower it.
Judge failure leaves the deterministic result intact and is reported as
incomplete semantic coverage rather than exit 3.

### Scan MCP tool descriptions

```bash
# Captured tools/list JSON — no MCP server is contacted
semantic-intent scan-mcp ./captured-tools-list.json
semantic-intent scan-mcp ./captured-tools-list.json --json
semantic-intent scan-mcp ./captured-tools-list.json --judge --server-label "acme-mcp"
```

`scan-mcp` accepts a bare tools array, `{ "tools": [...] }`, or a JSON-RPC
`{ "result": { "tools": [...] } }` envelope. It evaluates the tool name,
description, and every string-valued `description` nested under `inputSchema`.
The schema is treated as an untrusted string container; it is not executed or
resolved.

Deterministic analysis runs per field for precise provenance. The optional
judge sees one combined document per tool for cross-field reasoning. Findings
record the tool, a friendly `mcp_field`, and a lossless `mcp_json_path` so two
structurally different locations cannot collapse onto the same provenance
identifier. Synthetic `mcp://...` origins are identifiers only and are never
dereferenced. A captured file does not authenticate the MCP server that
purportedly supplied it.

No MCP client is started, no transport is opened, and no tool is invoked.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Low risk — no blocking findings |
| 1 | Medium risk — possible violations |
| 2 | High or critical risk — likely violations |
| 3 | `scan-remote` / `scan-mcp` only: nothing could be analyzed. **Not** a low-risk result. |

For `scan-remote`, exit 3 covers cases where every supported document failed,
was blocked, or was not found. For `scan-mcp`, it covers malformed/unrecognized
input (`invalid_input`) or a parsed file containing no tools (`no_tools`).
Security risk and operational status are separate. With `--judge`, incomplete
semantic coverage is also separate from both: it is exposed through
`judge_status`, `semantic_coverage`, and `analysis_complete`.

---

## Architecture

```text
Skill package                     External semantic content (v0.4)
  |                                  |  llms.txt / llms-full.txt   -> scan-remote
  Directory Audit (v0.3)             |  MCP tools/list JSON file    -> scan-mcp
  |- test file detection             |
  |- config file evaluation          remote_fetch.py -- guarded HTTPS fetch [remote only]
  +- dangerous pattern scan          |
  |                                  remote_audit.py -- format-agnostic deterministic analysis
  |                                  |  |- commands / domains / execution framing
  |                                  |  +- registry.py -- PyPI/npm/DNS existence + provenance
  |                                  |
  Semantic Evaluator (v0.1)          remote_judge.py -- two-pass semantic judge [--judge]
  |- chunk SKILL.md                   |  Pass 1: trusted deterministic findings + bounded digest
  |- evaluate invariants              |  Pass 2: raw body inside hard evidence boundary
  +- aggregate violations             +  content remains untrusted evidence
  |
  Substrate Layer (v0.2) -- invariant violations -> ethical mechanisms
  |
  Report (terminal or JSON)
```

Every remote/MCP `Finding` records how it was reached. `analysis_method` is
`rule_based` (stable given the bytes), `external_state` (a time-stamped live
registry/DNS observation), `fixture` (offline test snapshot), or `judge` for
semantic additions. A later change in external state does not rewrite an
earlier observation — **existence is not legitimacy**.

---

## Test fixtures

```text
tests/fixtures/
  benign/
    git-status.md              clean skill, expected: low risk
  suspicious/
    project-setup.md           authority laundering, expected: medium risk
  malicious/
    solana-wallet-tracker.md   SKILL.md credential theft, expected: critical
    reviewer.test.ts           test file exfiltration vector, expected: critical
  adversarial/
    judge-injection.md         embedded evaluator-directed instruction
```

```text
tests/fixtures/llms_txt/
  benign/first-party-sdk-llms.txt
  benign/docs-site-llms.txt
  suspicious/agent-tooling-llms.txt
  malicious/onboarding-llms-full.txt
  malicious/typosquat-llms.txt
  malicious/registered-after-dangling-llms.txt
  adversarial/judge-injection-llms.txt
  adversarial/situation-report-llms.txt
  mock_registry.json
```

```text
tests/fixtures/mcp/
  benign/weather.json
  suspicious/always-first.json
  malicious/exfil.json
  adversarial/derived-action.json
  adversarial/judge-injection.json
  adversarial/param-injection.json
```

Offline tests cover the guarded fetch path, format-agnostic remote analysis,
registry provenance, remote reporting, MCP field extraction/provenance, and
judge orchestration through fake clients. API-gated tests exercise the live
semantic judge when `ANTHROPIC_API_KEY` is available.

### Judge robustness

Remote semantic judging is deliberately layered rather than trusted as a
replacement for deterministic evidence. Pass 1 limits exposure to
attacker-authored text; Pass 2 isolates raw content as data; chunk verdicts are
reconciled before pass disagreement is evaluated; and material disagreement is
surfaced rather than averaged away. Adversarial fixtures explicitly attempt to
instruct the evaluator to return an all-clear verdict.

This is defense in depth, not a guarantee. An LLM judge remains a probabilistic
component and must not be allowed to erase deterministic evidence.

---

## Documented attack surfaces and failure patterns

| Attack Surface | Vector | Source | Coverage |
|---------------|--------|--------|----------|
| Instruction layer | Malicious SKILL.md | Snyk ToxicSkills, Feb 2026 | Semantic evaluation |
| Test file layer | Bundled `*.test.ts` / `conftest.py` | Gecko Security, May 2026 | Directory audit |
| Config layer | `.mcp.json` / `.claude/settings.json` | Adversa AI TrustFall, May 2026 | Directory audit |
| Remote docs layer | `llms.txt` / `llms-full.txt` naming unregistered or unverified packages/domains | Ars Technica, Aug 2026 | `scan-remote`: deterministic remote audit + optional two-pass judge |
| MCP tool layer | Injection in tool `description` or nested `inputSchema` descriptions | — | `scan-mcp`: offline audit of captured `tools/list` metadata + optional judge |
| Inbox / operational-message layer | Routine business communication whose structure induces a task-completing agent to execute a remediation without verifying the sender's authority | Horizon Accord case study, Aug 2026 | Documented pattern only — not yet a scanner surface |

The last row is a **failure pattern**, not current tool coverage. Standing
semantic-layer failure modes and their real-world case studies are catalogued in
[`docs/semantic-failure-patterns.md`](docs/semantic-failure-patterns.md), mapped
to the Invariant Set and the substrate.

---

## Theoretical basis

This scanner is the prototype implementation of the relational-semantic
evaluation framework described in:

> *The Semantic Gap: Why agentic AI security fails at the instruction layer*  
> Cherokee Schill · Horizon Accord · AI Research · 2026  
> https://horizonaccord.com/ai-research/the-semantic-gap

The core argument: the instruction-layer attack surface and the alignment
failure surface are the same layer. Closing it requires intent evaluation
anchored to invariant constraints, not pattern matching against known artifacts.

The same semantic layer that enables instruction-layer attacks is also the layer
where operational ethics must be evaluated. Security and alignment are not
separate problems — they are the same problem examined from different angles.

[`docs/semantic-failure-patterns.md`](docs/semantic-failure-patterns.md) is the
standing catalogue of semantic-layer failure modes. It opens with a framework
primitive: **understanding is not verification; verification is not
authorization**. These are orthogonal checks: a claim can be true without its
speaker having authority to cause the contemplated action.

The first entry, **SFP-1 Workflow Injection**, examines **Semantic Authority
Collapse**: an agent treating a plausible, goal-fitting remediation as
self-authorizing. The deliberate attacker technique is **Authorization
Laundering** — disguising the authorization decision as routine task completion.
The objective can remain intact while the adversary hijacks the path selected to
reach it.

---

## Roadmap

- [x] v0.1 — CLI prototype, invariants I1–I7, LLM evaluator, test fixtures
- [x] v0.2 — Fractal ethical substrate layer, mechanism mapping, causal reporting
- [x] v0.3 — Directory audit module, test file and config attack surfaces
- [x] v0.4 — Remote-content surfaces (invariant I8)
  - [x] PR1 — I8; guarded remote fetch; format-agnostic remote audit; registry/DNS provenance; `llms.txt` adapter
  - [x] PR2 — `scan-remote` CLI + terminal/JSON reports; exit 3 separates operational failure from risk
  - [x] PR3 — two-pass semantic judge over retrieved content as untrusted evidence
  - [x] PR4 — `scan-mcp` adapter for captured MCP `tools/list` metadata
- [x] v0.5 — Stable machine-readable finding contract (`schema_version: "0.1"`)
- [ ] v0.6 — Benchmark against a labelled corpus / ToxicSkills-derived dataset
- [ ] v0.7 — False-positive analysis, threshold calibration
- [ ] v0.8 — Relational integrity monitor (conversational trajectory evaluation)
- [ ] v1.0 — Publishable research findings

The v0.5 contract is independently versioned from the scanner package and
legacy report envelopes. It defines canonical observation, rationale,
remediation-outcome, and declarative-retest semantics while preserving existing
outputs through explicit adapters. See
[`docs/v0.5-finding-contract.md`](docs/v0.5-finding-contract.md) for the schema,
validation rules, compatibility policy, and migration guidance.

**The next priority is empirical, not conceptual:** benchmark the frozen I1–I8
system, characterize false positives and false negatives, and calibrate risk
thresholds. Misclassifications should become retained test cases rather than an
excuse to move the invariants during measurement.

---

## License

**AGPL-3.0-or-later.** Copyright (C) 2026 Rowan Lóchrann (Cherokee Schill)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. The full canonical license text is in [LICENSE](LICENSE).

---

## Contributing

This is early-stage research. Issues, adversarial test cases, and pull requests
are welcome. The most valuable contributions right now are labelled benchmark
cases and genuinely ambiguous edge cases.

---

*Not a company. Not a platform. A repo with a research question.*
