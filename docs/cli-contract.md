# CLI / output / exit-code / network contract

*Status: v0.11 stabilization. This documents the actual current public CLI —
verified against `scanner/cli.py` and the existing test suite, including
targeted empirical checks run against this exact commit — not an intended or
future redesign. It does not change, and is not permitted to imply a change
to, any exit code, network behavior, detector, threshold, risk mapping,
invariant, or schema.*

Package: `semantic-intent-scanner`. Console entry point: `semantic-intent`
(`scanner.cli:main`). Seven subcommands: `scan`, `scan-remote`, `scan-mcp`,
`inventory`, `inventory-diff`, `trust-analyze`, `audit`.

Every example and exit code below was reproduced against this commit, not
copied from prior prose. Where prior documentation or roadmap language
differed from actual behavior, that is called out explicitly (§8).

---

## 1. Network and model matrix

| Command | Guarded remote fetch (HTTPS, SSRF-hardened) | Registry/DNS provenance lookups | Model API call | `ANTHROPIC_API_KEY` |
| --- | --- | --- | --- | --- |
| `scan <file>` | no | no | **always** (no deterministic mode) | **required** — absent key is a handled operational failure (exit 3; §8.1) |
| `scan <dir>` / `--dir` | no | no | only if a candidate instruction file is found (`SKILL.md`, `skill.md`, `Skill.md`, `README.md`, in that order) | required only in that case; absent key is a handled operational failure (exit 3) |
| `scan-remote <url>` | yes — `llms.txt` / `llms-full.txt` | **yes, always** (packages/domains named in the fetched document) | opt-in, `--judge` only | irrelevant by default; needed for `--judge` to do anything (absent key → graceful `unavailable:no_api_key`, not a crash) |
| `scan-mcp <file>` | no (reads a local file) | **yes, always** (packages/domains named in the captured tool text) | opt-in, `--judge` only | same as `scan-remote --judge` |
| `inventory <url>` | yes — bounded, same-origin, depth ≤ 2 | no | no | irrelevant |
| `inventory-diff <a> <b>` | no | no | no | irrelevant |
| `trust-analyze <inventory>` | no | no | no | irrelevant |
| `audit` | only for selected `--remote` inputs (same as `scan-remote`); `--mcp` consumes a local captured file and does **not** perform guarded document fetching | only if `--remote`/`--mcp` selected (`--mcp` may still perform registry/DNS lookups on names in the captured file, same as `scan-mcp`) | `--skill` always; `--remote`/`--mcp` opt-in via `--judge` | required for `--skill` (**caught gracefully here**, unlike bare `scan` — §8.1); optional for `--judge` |

"Registry/DNS provenance lookups" is a distinct, narrower network surface from
"guarded remote fetch": it is live HTTP `GET` to two fixed hosts
(`pypi.org`, `registry.npmjs.org`) plus `socket.getaddrinfo` DNS resolution
for domains/packages *named inside already-retrieved or already-captured
text*. It is not SSRF-guarded the way document retrieval is, because it never
fetches a document body from a caller-supplied URL — it only resolves
identity for names the deterministic analyzer already extracted
(`scanner/registry.py`). It runs by default in `scan-remote` and `scan-mcp`
with **no flag to disable it** and is independent of `--judge`.

No command starts an MCP transport, connects to an MCP server, invokes a
tool, executes analyzed content, or installs a package. `scan-mcp` reads only
a local, previously captured `tools/list` JSON file.

---

## 2. `scan`

**Purpose:** evaluate a single instruction file, or a skill directory, for
invariant violations using the model-backed semantic evaluator plus
(for directories) the deterministic directory audit.

**Arguments:** positional `path` (file or directory). Flags: `--dir` (force
directory mode even if `path` looks like a file), `--json`, `--no-color`,
`--api-key` (overrides `ANTHROPIC_API_KEY`).

**Network:** none directly; the Anthropic SDK resolves its own endpoint.

**Model:** semantic evaluation (`scanner/evaluator.py`) has **no deterministic
mode** — every file scan and every directory scan that finds a candidate
instruction file calls the model. A directory with no candidate instruction
file runs the deterministic directory audit only and makes no model call.

**`ANTHROPIC_API_KEY`:** required whenever a model call happens. With no key
and no `--api-key`, `scan <file>` and a directory scan that finds a non-empty
candidate instruction file print a concise handled error to stderr, make no
model call, and exit **3** — see §8.1.

**stdout/stderr:** progress ("Scanning `<path>`...", or "Auditing directory
`<path>`...") on stderr. The report itself (terminal or JSON) on stdout.
The missing-credential path prints only a concise error (plus directory
discovery progress in directory mode), with no traceback or report.

**Output form:** `--json` prints a legacy JSON report
(`scanner: version: file: overall_risk: violation_count: violations:
chunks_evaluated: disclaimer:`); default is a colorized terminal report
(`--no-color` for plain text). Directory mode's JSON is
`{"directory_audit": {...}, "semantic_evaluation": {...} | null}`.

**Exit codes (verified in `cmd_scan_file` / `cmd_scan_directory`):**

| Code | Condition |
| --- | --- |
| 0 | risk `low` |
| 1 | risk `medium`, **or** path not found, **or** not a file, **or** file empty, **or** input exceeds the 2 MiB local-artifact bound, **or** input is not UTF-8 |
| 2 | risk `high` or `critical` |
| 3 | required API key is absent when semantic evaluation would run; handled operational failure, no model call |
| 2 (argparse) | unknown command/flag/missing positional (`argparse` itself) |

For directory mode, the worse of the directory-audit risk and the semantic
risk (when computed) selects the code by the same 0/1/2 mapping.

**Operational failure:** missing model credentials use exit 3, matching the
existing operational-failure convention used elsewhere. Other existing
invalid-input cases remain exit 1, so they are still not distinguishable from
a genuine `medium` risk finding by exit code alone. The global exit-code
system is otherwise unchanged (see also `docs/v1.0-release-readiness.md`).

**Bounded/fail-closed:** file reads are capped at
`MAX_LOCAL_ARTIFACT_BYTES` (2 MiB; `scanner/resource_limits.py`); exceeding it
is a handled `ValueError` → exit 1, not a crash. Public error strings are
truncated to 240 characters.

**Deterministic vs model-backed:** directory audit (test/config/pattern
detection) is deterministic. Semantic evaluation is entirely model-backed;
there is no offline equivalent for a single instruction file.

**Caveats:** a credential is still required for semantic evaluation. Missing
credentials are rejected at the CLI boundary before constructing a model
client; other model/API failures retain their existing behavior.

---

## 3. `scan-remote`

**Purpose:** audit a site's agent-facing remote documents (`llms.txt`,
`llms-full.txt`) for dangling/unverified package, index, and domain
references, plus execution-framing patterns — deterministically by default.

**Arguments:** positional `url` (site or base URL). Flags: `--json`,
`--no-color`, `--judge` (adds the two-pass LLM judge over retrieved content),
`--api-key`.

**Network:** guarded HTTPS fetch (`scanner/remote_fetch.py`: HTTPS-only,
every redirect re-validated by scheme/hostname/resolved IP, private/
reserved/loopback/link-local/CGNAT/metadata address space refused, pinned-IP
connect, `MAX_REDIRECTS = 5`, response body capped at `MAX_BODY_BYTES = 512
KiB` after decompression) plus, always, live registry/DNS lookups for any
package or domain the retrieved document names (§1).

**Model:** only with `--judge`. Judge failure (no key, API error, unparseable
response) is caught and reported as `judge_status: unavailable:<reason>` /
`semantic_coverage: incomplete`; it never raises an exception and never
changes the deterministic risk or exit code.

**`ANTHROPIC_API_KEY`:** irrelevant unless `--judge` is passed. With
`--judge` and no key: graceful `unavailable:no_api_key`, exit code driven by
the deterministic risk alone.

**stdout/stderr:** progress + guard-mode description on stderr; report on
stdout.

**Output form:** `--json` → an object with `scanner, version, scan_mode:
"remote", target, timestamp, operational_status, exit_code, overall_risk
(null if not scanned), documents_attempted, documents_retrieved, documents[],
finding_count, findings[], disclaimer`, plus `judge_status`,
`semantic_coverage`, `analysis_complete`, `judge` when `--judge` was used.
Default: colorized terminal report.

**Exit codes (`remote_exit_code` in `scanner/report.py`, verified):**

| Code | Condition |
| --- | --- |
| 0 | `overall_risk == low` |
| 1 | `overall_risk == medium` |
| 2 | `overall_risk in (high, critical)` |
| 3 | operational failure — nothing was analyzable (see below) |
| 2 (argparse) | unknown command/flag/missing positional |

**Operational failure (exit 3), verified via `remote_operational_status`:**
every candidate document blocked by the guard (`fetch_blocked`), every
candidate 404 (`not_found`), or every fetch failed for another reason
(`fetch_failed`). `overall_risk` is `null` in the JSON in this case, never
`"low"`.

**Bounded/fail-closed:** SSRF guard as above; a judge failure never
downgrades or removes a deterministic finding (append-only union, verified in
`tests/test_remote_judge.py` and `tests/test_cli_remote.py`).

**Deterministic vs model-backed:** the rule-based/registry lane is
deterministic; `--judge` is probabilistic and explicitly marked as such in
output (`semantic_coverage`, `analysis_complete`).

**Caveats:** a `low` result is not a safety guarantee — it only means no
rule-based/registry finding fired (and, with `--judge`, that the judge did
not raise it). Registry existence is never treated as legitimacy.

---

## 4. `scan-mcp`

**Purpose:** audit a captured MCP `tools/list` JSON file — tool names, tool
descriptions, and every string-valued `description` nested anywhere under
`inputSchema` — as untrusted external content, using the same deterministic
+ optional-judge engine as `scan-remote`.

**Arguments:** positional `file` (path to a captured JSON artifact). Flags:
`--json`, `--no-color`, `--judge`, `--api-key`, `--server-label` (provenance
label only — **not** an authentication mechanism; the captured file never
authenticates the server that supplied it).

**Network:** none for retrieval — the input is a local file, and **no MCP
server is contacted, no transport is opened, and no tool is invoked** (verified: `cmd_scan_mcp` only opens the file with `Path.is_file()` / reads
JSON). Registry/DNS lookups still run by default (§1) because the
deterministic analyzer extracts package/domain names from the tool text
exactly as `scan-remote` does.

**Model:** only with `--judge`, same contract as `scan-remote --judge`.

**`ANTHROPIC_API_KEY`:** same as `scan-remote`.

**stdout/stderr:** progress on stderr; report on stdout (same shapes as
`scan-remote`, with `scan_mode: "mcp"` and an `mcp_server: {declared,
authenticated: false}` field in JSON).

**Exit codes — same numeric contract as `scan-remote`** (`remote_exit_code`
is shared code), but the **operational-failure vocabulary differs and is
MCP-specific, not HTTP-shaped** (verified in `remote_operational_status`):

| Code | Condition |
| --- | --- |
| 0 / 1 / 2 | same risk mapping as `scan-remote` |
| 3 | `invalid_input` (file is not valid JSON, or not a recognized `tools/list` shape) or `no_tools` (parsed, but zero tool definitions) |
| **1** | **missing file** — `cmd_scan_mcp` checks `Path.is_file()` before any analysis and returns 1 directly; this is a different code path from the 3-vs-missing-file handling in `inventory-diff`/`trust-analyze` (verified empirically; see §8.2) |
| 2 (argparse) | unknown command/flag/missing positional |

**Bounded/fail-closed:** a malformed individual tool entry (no usable
`name`) is skipped and counted, not treated as a fatal error, as long as at
least one tool parses; a completely unrecognized file shape is `invalid_input`
rather than a silently empty success.

**Deterministic vs model-backed:** identical split to `scan-remote`.

**Caveats:** "offline" here means no MCP transport — it does **not** mean no
network at all; the same registry/DNS lookups as `scan-remote` still occur by
default.

---

## 5. `inventory`

**Purpose:** produce a bounded, factual, agent-readable-surface inventory
(`robots.txt`, `llms.txt`, sitemaps, AI manifests, OpenAPI schemas, advertised
endpoints) for one HTTPS origin. No detector, no risk lane, no judge.

**Arguments:** positional `url` (must resolve to an HTTPS origin).

**Network:** guarded HTTPS fetch, same hardened transport as `scan-remote`
(`scanner/remote_fetch.guarded_fetch`), bounded discovery: same-origin only,
`MAX_DISCOVERY_DEPTH = 2`, `MAX_INVENTORY_ENTRIES = 32`,
`MAX_DECLARATIONS_PER_RESOURCE = 16`, structured documents capped at
`MAX_STRUCTURED_DOCUMENT_BYTES = 512 KiB` (`scanner/surface_inventory.py`).
No crawling beyond same-origin declared references.

**Model:** none. **`ANTHROPIC_API_KEY`:** irrelevant.

**stdout/stderr:** progress note on stderr; the inventory JSON on stdout.

**Output form:** one JSON object (`inventory_schema_version, target_origin,
entries[], truncated`), sorted keys, `schemas/inventory-0.1.schema.json`.

**Exit codes (verified empirically and in `cmd_inventory`):**

| Code | Condition |
| --- | --- |
| 0 | a valid inventory artifact was produced, **regardless of finding count** — inventory has no risk concept |
| 3 | `InventoryError` — verified: non-HTTPS target ("inventory supports HTTPS resources only") and any other canonicalization failure |
| 2 (argparse) | unknown command/flag/missing positional |

**Operational failure:** exit 3 is the only failure mode; there is no
partial-success/risk distinction because inventory is a factual artifact, not
a security finding stream.

**Bounded/fail-closed:** every limit above is enforced with an explicit
`truncated` flag in the output rather than silently stopping; a malformed
declared reference (bad manifest URL, malformed OpenAPI `servers` entry) is
recorded as a bounded structural error, not silently dropped.

**Deterministic vs model-backed:** entirely deterministic. Two runs may
still differ in *content* because the target's live web state can change
between runs — that is expected observational variability, not
non-determinism of logic.

---

## 6. `inventory-diff`

**Purpose:** compare two previously saved inventory JSON artifacts and report
factual changes. No network, no re-discovery, no risk interpretation.

**Arguments:** positional `previous`, `current` (paths to inventory JSON
files).

**Network:** none. **Model:** none. **`ANTHROPIC_API_KEY`:** irrelevant.

**stdout/stderr:** the change-set JSON on stdout; errors on stderr.

**Output form:** one JSON object (`change_schema_version,
previous_inventory_schema_version, current_inventory_schema_version,
target_origin, changes[]`), `schemas/change-0.1.schema.json`.

**Exit codes (verified empirically and in `cmd_inventory_diff`):**

| Code | Condition |
| --- | --- |
| 0 | a valid comparison was produced, regardless of how many changes exist |
| 3 | file cannot be read, is not UTF-8, is not valid JSON (including non-finite numbers, explicitly rejected), exceeds the 2 MiB bound, or the two inventories are not comparable (`InventoryDiffError` / `ChangeValidationError`, both `ValueError` subclasses — all caught) |
| 2 (argparse) | unknown command/flag/missing positional |

**Operational failure:** exit 3 only; verified with malformed JSON and with
a missing file (both produce exit 3 via the same `except (OSError,
UnicodeError, json.JSONDecodeError, ValueError)` clause).

**Bounded/fail-closed:** local reads capped at 2 MiB; non-finite JSON
numbers (`NaN`/`Infinity`) explicitly rejected rather than silently parsed.

**Deterministic vs model-backed:** entirely deterministic and side-effect
free — comparing the same two artifacts twice yields byte-identical output.

---

## 7. `trust-analyze`

**Purpose:** analyze one saved inventory artifact for deterministic
structural authority crossings (e.g. a manifest naming a cross-origin API/MCP
endpoint, an OpenAPI `servers[].url` pointing off-origin). No retrieval, no
execution, no model judgment — conservative, structural-only findings mapped
to I8 at `low`.

**Arguments:** positional `inventory` (path to an inventory JSON artifact).

**Network:** none. **Model:** none. **`ANTHROPIC_API_KEY`:** irrelevant.

**stdout/stderr:** a JSON **array** of canonical `FindingContract` objects on
stdout (verified empirically: an inventory with no authority crossings prints
`[]`); errors on stderr.

**Output form:** JSON array, `schemas/finding-0.1.schema.json` per element.

**Exit codes (verified empirically and in `cmd_trust_analyze`):**

| Code | Condition |
| --- | --- |
| 0 | a valid analysis was produced, regardless of finding count |
| 3 | file cannot be read (verified: missing file), is not valid JSON (verified), or is not a well-formed/supported inventory (verified: a JSON object missing required inventory fields reports the exact missing-field list and exits 3) |
| 2 (argparse) | unknown command/flag/missing positional |

**Operational failure:** exit 3 only, same pattern as `inventory-diff`.

**Bounded/fail-closed:** local reads capped at 2 MiB; non-finite JSON numbers
rejected; unsupported/malformed inventory shapes fail closed rather than
silently returning zero findings for an unreadable structure.

**Deterministic vs model-backed:** entirely deterministic; no LLM judgment,
no prompt-injection inference, no interpretation of arbitrary external links
beyond the specifically supported manifest/OpenAPI authority fields.

---

## 8. `audit`

**Purpose:** run one or more explicitly selected existing analyzers
(directory, semantic, remote, MCP, trust) into one canonical composite
finding stream (`FindingContract` throughout). No implicit defaults, no
analyzer runs unless its flag is given.

**Arguments (all optional, but at least one analyzer input is required):**
`--directory PATH` (repeatable), `--skill PATH` (repeatable), `--remote URL`
(repeatable), `--mcp FILE` (repeatable), `--trust-inventory PATH`
(repeatable), `--judge` (applies to selected `--remote`/`--mcp` inputs only),
`--api-key`, `--server-label` (requires at least one `--mcp`). Repeated
selections of the same analyzer are numbered `directory:2`, `remote:3`, etc.
(`_numbered_id`).

**Network / Model:** per selected analyzer, exactly as documented above for
`scan-remote` (`--remote`), `scan-mcp` (`--mcp`), and the semantic evaluator
(`--skill`, always model-backed). `--directory` and `--trust-inventory` are
always local-only.

**`ANTHROPIC_API_KEY`:** required for `--skill`. A model failure (including a
missing key) here is a
handled `Exception` turned into `AdapterOutcome("failed_operational", ...)`
(verified in `scanner/composite_audit.py::semantic_adapter`). Optional for
`--judge` on `--remote`/`--mcp`.

**stdout/stderr:** invocation errors (no analyzer selected, `--judge` without
`--remote`/`--mcp`, `--server-label` without `--mcp`) on stderr, exit 3
before any adapter runs; otherwise the composite JSON on stdout.

**Output form:** one JSON object — `schema_version, requested_analyzers[],
executions[] (analyzer_id, status, finding_count, semantic_coverage, reason?),
findings[]` (each a canonical `FindingContract` tagged with its source
analyzer) — `schemas/composite-0.1.schema.json`. Inventory and inventory-diff
artifacts are deliberately **not** part of `audit`; they remain separate
factual commands.

**Exit codes (`composite_exit_code`, verified empirically):**

| Code | Condition |
| --- | --- |
| 0 | no selected analyzer's execution status starts with `failed_` — **regardless of finding count or overall severity**; `audit` has no aggregate risk exit |
| 3 | at least one analyzer execution is `failed_invalid_input` or `failed_operational`; also returned directly for the pre-execution invocation errors above |
| 2 (argparse) | unknown command/flag/missing positional |

**Operational failure — the important divergence from standalone commands
(verified by reading `_remote_outcome` and confirmed against
`remote_operational_status`):** inside `audit`, a `--remote`/`--mcp` input
that finds **nothing to analyze** (`not_found` / `no_tools`) is classified
`not_applicable`, which is **not** a `failed_*` status and therefore does
**not** contribute to exit 3. The same condition run through the standalone
`scan-remote`/`scan-mcp` command **is** exit 3. Only a genuinely blocked/
failed fetch, or invalid MCP input, is `failed_operational` /
`failed_invalid_input` inside `audit`. Document this distinction to anyone
building CI around exit codes: "operational failure" means something
narrower inside `audit` than it does standalone.

**Bounded/fail-closed:** every adapter fails closed on invalid input
(`failed_invalid_input`) rather than silently producing an empty success —
verified for a nonexistent `--directory` path and reproduced above.

**Deterministic vs model-backed:** `--directory` and `--trust-inventory` are
always deterministic; `--skill` is always model-backed; `--remote`/`--mcp`
are deterministic by default and model-backed only with `--judge`.
`semantic_coverage` on each execution (`not_requested` / `complete` /
`partial` / `incomplete`) makes this explicit per analyzer in the output.

---

## Verified exit-code summary (all commands)

| Code | `scan` | `scan-remote` | `scan-mcp` | `inventory` | `inventory-diff` | `trust-analyze` | `audit` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | low risk | low risk | low risk | valid artifact | valid comparison | valid analysis | no analyzer failed |
| 1 | medium risk **or** several invalid-input cases | medium risk | medium risk | — | — | — | — |
| 2 | high/critical risk | high/critical risk | high/critical risk | — | — | — | — |
| 3 | missing model credentials | nothing analyzable | invalid input / no tools | `InventoryError` | read/JSON/comparison failure | read/JSON/analysis failure | ≥1 analyzer `failed_*`, or a pre-execution invocation error |
| 1 (special) | — | — | **missing file** (own explicit check, not the shared exit-3 path) | — | — | — | — |
| 2 (argparse) | every command: unknown subcommand, unknown flag, or missing required positional |

---

## Known caveats verified in this slice

### 8.1 `scan` missing-key handling

With `ANTHROPIC_API_KEY` unset and no `--api-key`,
`semantic-intent scan tests/fixtures/benign/git-status.md` reports:

```
Error: Anthropic API key required; use --api-key or set ANTHROPIC_API_KEY
```

and exits **3**. `cmd_scan_file` and `cmd_scan_directory` check for an explicit
key or `ANTHROPIC_API_KEY` immediately before calling `evaluate_skill`, so the
predictable credential-absence case never constructs an Anthropic client.
Directory scans without a candidate instruction file remain deterministic and
need no credential.

`scanner/remote_judge.py::judge_document` likewise checks for a key before
constructing a client and returns
`JudgeResult(status="unavailable:no_api_key", ...)` — no exception, no
traceback — and `scanner/composite_audit.py::semantic_adapter` wraps the
same `evaluate_skill` call in a `try/except Exception` that turns any
failure (including a missing key) into `AdapterOutcome("failed_operational",
...)`.

This check is intentionally narrow: unrelated evaluator, SDK, and API errors
are not broadly swallowed or reclassified. Detector/model prompts, model
selection, thresholds, verdict logic, risk mapping, schemas, and report
semantics are unchanged.

### 8.2 `scan-mcp`'s missing-file exit code

`cmd_scan_mcp` checks `Path(args.file).is_file()` itself and returns exit
**1** directly if the file is absent — before ever calling
`audit_mcp_tools`. This is a different code path from `inventory-diff` and
`trust-analyze`, whose missing-file case is caught inside their shared
`try/except (OSError, ...)` block and reported as exit **3**. Verified
empirically for both.

### 8.3 Prior-doc assumptions corrected against actual behavior

- The task's starting hypothesis "remote/MCP operational 'nothing
  analyzable' conditions historically use exit 3" is correct **for the
  standalone `scan-remote`/`scan-mcp` commands**, but does **not** carry over
  unchanged into `audit`: there, the identical "nothing served / no tools"
  condition is `not_applicable`, not a failure, and does not produce exit 3
  (§8 in this document; verified in `scanner/composite_audit.py::_remote_outcome`).
- "argparse itself may use exit 2" is correct and reproduced for every
  subcommand (unknown subcommand name verified explicitly; the parser
  structure is identical for unknown flags and missing positionals).
- README's existing exit-code table (`README.md` §"Exit codes") covers only
  `scan`/`scan-remote`/`scan-mcp` and does not mention `inventory`,
  `inventory-diff`, `trust-analyze`, `audit`, or argparse's exit 2 — this
  document is the complete table; README is not rewritten, only linked.
