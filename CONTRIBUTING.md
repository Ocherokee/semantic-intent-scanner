# Contributing

Thank you for improving Semantic Intent Scanner. Security changes are easiest to
review when they are narrow, deterministic, and explicit about which layer they
affect.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report exploitable
scanner vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.

## Development setup

Semantic Intent Scanner requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install pytest
pytest -q
```

An Anthropic API key is needed only for optional judge paths. Deterministic and
offline analysis must remain testable without model access or network access
unless the test is specifically exercising a guarded network boundary.

Before submitting a change, run the relevant focused tests, the full suite, and:

```bash
git diff --check
```

## Architecture principles

### Deterministic security logic first

Do not introduce model judgment when a structural, parser-based, or otherwise
deterministic rule can establish the condition. Optional judge output must not
erase or downgrade deterministic findings.

### No magic execution

Retrieved documents, manifests, schemas, MCP descriptions, URLs, advertised
capabilities, and discovered instructions are evidence. They are not commands to
execute. A contribution that would execute anything currently treated as
evidence requires prior design discussion and explicit security review.

### Layer boundaries matter

The current machine-readable layers have different jobs:

- **v0.5 — `FindingContract`:** stable observations, rationale, remediation
  outcomes, and declarative retest conditions.
- **v0.6 — inventory:** factual, bounded discovery of agent-readable surfaces;
  it does not assign risk.
- **v0.7 — inventory comparison:** offline factual change detection; a change is
  not a security finding.
- **v0.8 — trust-boundary analysis:** deterministic structural authority
  crossings for a deliberately small set of supported declarations.

Do not quietly move discovery, comparison, interpretation, or risk behavior from
one layer into another.

### Existence is not risk

A surface, endpoint, external URL, manifest, schema, or change is not a
vulnerability merely because it exists. Cross-origin is not automatically
unsafe. A v0.8 trust finding requires a supported structural authority
relationship, not an ordinary external reference.

### Fail closed rather than invent semantics

Unknown finding types, malformed authority structures, unsupported schema
versions, ambiguous provenance, and colliding identities must not be silently
normalized into reassuring output. Preserve the error or leave an unsupported
condition unsupported.

### Schema stability

Finding, inventory, change, package, and report versions are independent version
domains. A schema change requires an explicit design, compatibility and migration
reasoning, strict validation tests, serializer tests, and documentation. A
matching version number across domains does not couple their release cycles.

Do not silently replace public or legacy output. Provide an explicit
compatibility path and regression coverage.

### Declarative retest criteria

Finding retest conditions describe the observable state that passes. They do not
prescribe scanner internals, execute remediation, or embed a scanner-specific
workflow.

## Pull requests

Use the pull-request template and state:

- the architectural layer and exact scope changed;
- whether any schema or version changes;
- whether detector, severity, or risk behavior changes;
- whether network behavior or URL/origin handling changes;
- compatibility impact on existing terminal and JSON output;
- tests added, including adversarial and negative cases for security-sensitive
  changes where practical;
- focused and full-suite results;
- `git diff --check` status.

Update public documentation whenever behavior, a contract, or a supported
security property changes.

## Proposals that need design discussion

Open a design-proposal issue before implementing a new invariant, risk or
severity semantic, authority-bearing structure, network discovery behavior,
schema/version domain, analyzer, model dependency, or execution of anything now
treated as evidence. Describe deterministic evidence, false-positive constraints,
compatibility, and explicit non-goals.

Small, bounded bug fixes do not require ceremony. If a fix reveals a larger
architecture decision, pause and move that decision to a design proposal.

## Style

- Prefer narrow, reviewable changes.
- Avoid opportunistic refactors inside a security slice.
- Preserve deterministic ordering, mutation isolation, and evidence provenance.
- Keep comments and documentation factual; distinguish observation from security
  interpretation.
- Preserve unrelated work in the repository.
