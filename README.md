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

## The Seven Invariants

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
Skill package
  |
  Directory Audit (v0.3)
  |- test file detection
  |- config file evaluation
  +- dangerous pattern scan
  |
  Semantic Evaluator (v0.1)
  |- chunk SKILL.md
  |- evaluate against 7 invariants (LLM-as-judge)
  +- aggregate violations
  |
  Substrate Layer (v0.2)
  |- map violations to ethical mechanisms
  +- generate causal explanation
  |
  Report (terminal or JSON)
```

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
```

---

## Documented attack surfaces covered

| Attack Surface | Vector | Source | Coverage |
|---------------|--------|--------|----------|
| Instruction layer | Malicious SKILL.md | Snyk ToxicSkills, Feb 2026 | Semantic evaluation |
| Test file layer | Bundled *.test.ts / conftest.py | Gecko Security, May 2026 | Directory audit |
| Config layer | .mcp.json / .claude/settings.json | Adversa AI TrustFall, May 2026 | Directory audit |

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

- [x] v0.1 — CLI prototype, seven invariants, LLM evaluator, test fixtures
- [x] v0.2 — Fractal ethical substrate layer, mechanism mapping, causal reporting
- [x] v0.3 — Directory audit module, test file and config attack surfaces
- [ ] v0.4 — Benchmark against ToxicSkills dataset (Snyk, February 2026)
- [ ] v0.5 — False positive analysis, threshold calibration
- [ ] v0.6 — Relational integrity monitor (conversational trajectory evaluation)
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
