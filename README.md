# Semantic Intent Scanner

**Invariant-grounded semantic evaluation for AI agent skill files and directories.**

A research prototype that evaluates AI agent skill packages against a formal
invariant set and ethical substrate — not by matching known-bad patterns, but by
reasoning about *intent* and *mechanism failure*.

---

## Quick start

```bash
pip install -e .              # Python 3.11+
export ANTHROPIC_API_KEY=...   # needed for semantic evaluation of instruction files
```

```bash
# Audit a whole skill package — instruction file plus the surfaces around it
# (bundled test files, project config). The directory audit runs without an API key.
semantic-intent scan ./path/to/skill-directory/

# A single instruction file (semantic evaluation; needs ANTHROPIC_API_KEY)
semantic-intent scan ./SKILL.md

# JSON for CI
semantic-intent scan ./SKILL.md --json
```

Run it against the repo's own fixtures to see a real detection in a few seconds
(no API key required for this one):

```
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

Exit code is `0` / `1` / `2` by risk level, so a flagged skill can block a CI job.
The semantic evaluation of instruction content — invariant violations and the
ethical-mechanism reasoning below — is the part that calls the model.

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

And the instruction that reaches an agent is not always local. A retrieved
remote document — an `llms.txt`, a tool description served by an MCP server —
is untrusted content that an agent may act on as if it were authoritative.

This scanner inspects several of these surfaces: the instruction file
(semantic evaluation), bundled test and config files (directory audit), and
retrieved remote documents such as `llms.txt` (remote-audit engine, v0.4).
MCP tool-description surfaces are planned. Coverage of each surface is
described below and in the roadmap — this is not a claim to cover every
instruction, configuration, execution, and retrieved-content surface an agent
touches.

**This is a research prototype. It is not production security tooling.**
A clean scan does not certify safety. Human review remains essential.

---

## What the scanner asks

The scanner now answers several questions, not one.

**v0.1 asked:** Is this instruction dangerous?
**v0.2 adds:** Which ethical mechanism failed, and why did that failure create executable risk?
**v0.3 adds:** Are there attack surfaces in this skill package beyond the instruction file?
**v0.4 adds:** Does a retrieved remote document (e.g. `llms.txt`) name a package, domain, package index, or tool that the agent would extend trust to without a provenance check?

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

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Low risk — no violations detected |
| 1 | Medium risk — possible violations |
| 2 | High or critical risk — likely violations |

Exit codes enable use in CI/CD pipelines to block installation of flagged skills.

---

## Architecture

```
Skill package                     Retrieved remote document (v0.4)
  |                                  |  llms.txt / llms-full.txt  (MCP tool descriptions: PR4)
  Directory Audit (v0.3)             remote_fetch.py  -- SSRF-hardened GET (per-hop IP validation,
  |- test file detection             |                   pinned-IP connect, no cross-origin creds,
  |- config file evaluation          |                   decompressed-size cap)
  +- dangerous pattern scan          remote_audit.py  -- analyze_document(): format-agnostic
  |                                  |   |- extract install commands / domains / execution framing
  |                                  |   +- registry.py: existence + provenance signal (PyPI/npm/DNS)
  |                                  |
  Semantic Evaluator (v0.1)  <-------+  (judge pass consumes findings as evidence; PR3)
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

## Documented attack surfaces and failure patterns

| Attack Surface | Vector | Source | Coverage |
|---------------|--------|--------|----------|
| Instruction layer | Malicious SKILL.md | Snyk ToxicSkills, Feb 2026 | Semantic evaluation |
| Test file layer | Bundled *.test.ts / conftest.py | Gecko Security, May 2026 | Directory audit |
| Config layer | .mcp.json / .claude/settings.json | Adversa AI TrustFall, May 2026 | Directory audit |
| Remote docs layer | llms.txt / llms-full.txt naming unregistered or unverified packages/domains | Ars Technica, Aug 2026 | Remote-audit engine (rule-based + external-state); `scan-remote` CLI in review (#4) |
| MCP tool layer | Injection in a server's tool `description` fields | — | Planned, v0.4 PR4 |
| Inbox / operational-message layer | Ordinary business communication whose operational structure (reported failure state + named managed asset + deadline + single "remediation") induces a task-completing agent to execute the remediation without verifying the sender's authority | Horizon Accord case study, Aug 2026 | Documented pattern only — see [`docs/semantic-failure-patterns.md`](docs/semantic-failure-patterns.md); not yet a scanner surface |

The last row is a **failure pattern**, not current tool coverage. Standing
semantic-layer failure modes and their real-world case studies are catalogued
in [`docs/semantic-failure-patterns.md`](docs/semantic-failure-patterns.md),
mapped to the Invariant Set and the substrate.

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

[`docs/semantic-failure-patterns.md`](docs/semantic-failure-patterns.md) is the
standing catalogue of semantic-layer failure modes — patterns that graduate
out of per-version scoping work once their invariant mapping is settled, each
kept with a real-world case study. It opens with a framework primitive:
**understanding is not verification; verification is not authorization** —
three orthogonal checks an agent must keep separate, since a claim can be true
without its speaker having authority to act on it. The first entry, **SFP-1
Workflow Injection**, examines an agent treating a plausible, goal-fitting
action as self-authorising (an I8 failure reached through a monitored
information channel), using a phishing email received at Horizon Accord as the
case.

---

## Roadmap

- [x] v0.1 — CLI prototype, invariants I1–I7, LLM evaluator, test fixtures
- [x] v0.2 — Fractal ethical substrate layer, mechanism mapping, causal reporting
- [x] v0.3 — Directory audit module, test file and config attack surfaces
- [ ] v0.4 — Remote-content surfaces (invariant I8)
  - [x] PR1 — I8 in the invariant + substrate model; SSRF-hardened `remote_fetch`;
        format-agnostic `remote_audit` engine; `registry` existence + provenance
        model; `llms_txt` adapter; benign/suspicious/malicious fixtures (offline)
  - [ ] PR2 — `scan-remote` CLI subcommand + report sections *(in review: #4)*
  - [ ] PR3 — two-pass judge over retrieved content, as untrusted evidence *(in review: #5, stacked on #4)*
  - [ ] PR4 — MCP tool-description adapter
- [ ] v0.5 — Benchmark against ToxicSkills dataset (Snyk, February 2026)
- [ ] v0.6 — False positive analysis, threshold calibration
- [ ] v0.7 — Relational integrity monitor (conversational trajectory evaluation)
- [ ] v1.0 — Publishable research findings

The near-term priority after v0.4 lands is empirical, not conceptual:
benchmarking against a labelled dataset, false-positive analysis, and
threshold calibration. The framework is far enough along to deserve
technical review; measured detection and false-positive rates are what
would move it from a functioning framework toward a research result.

---

## License

**AGPL-3.0-or-later.** Copyright (C) 2026 Rowan Lóchrann (Cherokee Schill)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. The full license text is in [LICENSE](LICENSE).

---

## Contributing

This is early-stage research. Issues, adversarial test cases, and
pull requests are welcome. The most valuable contributions right now
are new test fixtures — especially edge cases that are genuinely ambiguous.

---

*Not a company. Not a platform. A repo with a research question.*
