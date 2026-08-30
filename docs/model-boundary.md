# Deterministic vs model-backed behaviour

*Status: v0.11 stabilization. Interfaces described here are candidates for the
1.0 stable promise; the model-backed lanes are explicitly **not**.*

The scanner has two kinds of behaviour and this document draws the line
between them so a release consumer knows exactly what is being promised.

## 1. Deterministic behaviour — the release gate

Everything except the two lanes named in §2 is deterministic. Given the same
inputs it produces the same findings, the same severities, the same schema
artifacts, and the same exit codes. It performs no model call.

**A fresh checkout with no `ANTHROPIC_API_KEY` runs the entire deterministic
test suite.** The `live_model` marker names the model-backed tests, so the
deterministic gate is:

```
pytest -m "not live_model"
```

With no credential this deselects exactly the eight `live_model` tests
(§3) and skips nothing else.

Deterministic surfaces:

| Surface | Module | Model? |
| --- | --- | ---: |
| Directory audit | `scanner/directory_audit.py` | no |
| Remote llms.txt deterministic lane | `scanner/llms_txt.py`, `scanner/remote_audit.py` | no |
| Captured MCP deterministic lane | `scanner/mcp_adapter.py` | no |
| Registry / DNS provenance | `scanner/registry.py` | no |
| Guarded fetch | `scanner/remote_fetch.py` | no |
| Surface inventory | `scanner/surface_inventory.py` | no |
| Inventory diff | `scanner/inventory_diff.py` | no |
| Trust-boundary analysis | `scanner/trust_analysis.py` | no |
| Composite orchestration | `scanner/composite_audit.py` | only if a selected sub-analyzer is model-backed |
| All four contract validators + serializers | `finding_contract`, `surface_inventory`, `inventory_diff`, `composite_audit` | no |

The deterministic lanes carry external-state variability (`observed_at`
timestamps, live registry/DNS answers, fetch results). Canonical
serialization is byte-stable for the *same validated static object*; new
acquisition runs are observations and are not promised to reproduce bytes.
That is a determinism-of-logic promise, not a determinism-of-observation
promise.

## 2. Model-backed behaviour — optional, probabilistic, experimental

Exactly **two** modules call the Anthropic API. A test
(`tests/test_model_boundary.py::test_only_the_two_model_modules_touch_anthropic`)
fails the build if any other `scanner/` module imports `anthropic` or names
`anthropic.Anthropic`.

| Lane | Module | Entry points | Triggered by |
| --- | --- | --- | --- |
| Semantic skill evaluator | `scanner/evaluator.py` | `scan <file>`, `scan <dir>` with an instruction file, `audit --skill` | always (this lane has no deterministic mode) |
| Two-pass retrieved-content / MCP judge | `scanner/remote_judge.py` | `scan-remote --judge`, `scan-mcp --judge`, `audit --judge` | opt-in flag only |

### Model identifiers (tested assumptions)

Each lane names its model inline:

| Where | Value |
| --- | --- |
| `scanner/evaluator.py` (`evaluate_chunk`) | `claude-opus-4-5` |
| `scanner/remote_judge.py` (`DEFAULT_JUDGE_MODEL`) | `claude-opus-5` |

The semantic evaluator's identifier (`claude-opus-4-5`) is superseded. It is
left unchanged here because changing it alters a probabilistic path that was
not exercised in this slice; that change belongs in a protected pre-release
evaluation. See `docs/v1.0-release-readiness.md`.

### Contract of the judge lane (mocked-client tested)

The judge is a wrapper around a probabilistic call. Its **wrapper** behaviour
is deterministic and is covered by fake-client tests
(`tests/test_remote_judge.py`, plus orchestration coverage in
`tests/test_cli_remote.py`, `tests/test_llms_txt.py`, `tests/test_cli_mcp.py`,
`tests/test_mcp_adapter.py`):

| Property | Where |
| --- | --- |
| Two-pass orchestration, worst verdict wins per invariant | `test_two_passes_worst_verdict_wins_per_invariant` |
| Pass-1 / Pass-2 material disagreement becomes its own escalated finding | `test_material_disagreement_becomes_its_own_finding_and_escalates` |
| Response parsing; unparseable → `unavailable:parse_error` | `test_unparseable_response_is_unavailable_parse_error` |
| API exception → `unavailable:api_error`, no crash | `test_api_exception_is_unavailable_api_error` |
| No credential → `unavailable:no_api_key`, zero calls | `test_no_api_key_is_unavailable_not_a_crash` |
| Evidence boundary: Pass 1 gets a bounded structured digest, never raw body | `test_claims_block_is_structured_and_bounded_no_raw_body` |
| Evidence boundary: deterministic findings are the *trusted* input block | `test_findings_block_marks_deterministic_as_the_trusted_input` |
| Large body chunked, per-chunk verdicts reconciled | `test_pass2_chunks_a_large_body_and_reconciles_worst_chunk` |
| Semantic coverage roll-up (`complete` / `partial` / `incomplete`) | `test_partial_judge_coverage_across_documents` |
| **Non-downgrade**: a judge result never lowers a deterministic severity | `test_judge_never_lowers_a_deterministic_critical` |
| Judge failure never becomes an operational failure (exit code unchanged) | `test_judge_failure_is_not_destructive`, `test_all_documents_judge_fail_is_not_exit_3` |
| `--judge` absent → byte-identical to the deterministic run, no `judge*` keys | `test_judge_default_off_leaves_result_and_report_unchanged`, `test_default_no_judge_adds_no_judge_keys` |

### What is *not* promised

* the model's verdict on any given input;
* that adversarial prompt-injection resistance holds for future model
  versions (the live tests record current behaviour, not a guarantee);
* that a semantic finding will appear where a human would expect one, or that
  one will not appear where a human would not — semantic efficacy is
  uncalibrated.

### Guarantees that *do* hold under model failure or model nonsense

* deterministic findings are authoritative and are never removed or
  downgraded by the model lane (append-only union);
* a model failure yields `judge_status: unavailable:<reason>` /
  `semantic_coverage: incomplete` and leaves the deterministic risk and exit
  code exactly as they were;
* the semantic skill evaluator, which has no deterministic mode, surfaces a
  `parse_error` chunk risk rather than inventing a verdict when the model
  returns unparseable output.

## 3. Live tests

Eight tests carry the `live_model` marker and make real API calls
(`tests/test_fixtures.py` in full, plus `test_live_judge_*` in
`tests/test_mcp_adapter.py` and `tests/test_remote_judge.py`). They also skip
themselves when `ANTHROPIC_API_KEY` is absent.

They are **not** a pull-request gate. Run them locally with a key:

```
pytest -m live_model
```

An isolated CI job that runs them without exposing the credential to
fork-PR code is future work, not part of this slice. They are integration
coverage and calibration inputs, not evidence of a stable contract.
