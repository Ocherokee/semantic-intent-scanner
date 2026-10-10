# Conditional Execution Analysis (opt-in prototype)

This module statically inspects bounded local Python source, limited JavaScript conditional snippets, and npm package.json lifecycle scripts. It **never runs the target code**, installs dependencies, contacts external infrastructure, or requests an API key.

Seven approved regression scenarios are covered in `tests/test_conditional_execution.py`: date-triggered credential transmission (high), debugger-dependent hidden execution (elevated), scheduled backup (informational), timeout/retry (informational), delayed npm install process (high), dynamically generated code (incomplete), and unchanged previously approved artifact (no new review if exact digest and policy version match).

Use `inspect_python`, `inspect_npm_manifest`, `inspect_javascript` or `inspect_path` from `scanner.conditional_execution`. Results are **static observations only**: `rule`, `concern`, `line` and an evidence description. They are not canonical scanner findings or automated quarantine decisions.

## Security and limitations

- JavaScript inspection is a bounded heuristic, **not a real AST parser**. Nested scopes, minified source, imported calls, renamed APIs, shell script details, indirect dataflow, and obfuscation are not reliably resolved. Python AST inspection considers conditional body syntax, not complete cross-function dataflow.
- Timing checks and anti-debug logic also occur in benign software. High concern requires human review and/or further independent analysis, not a claim of exploitation.
- The 'unchanged' optimization verifies exact artifact bytes and policy version only. Revocation, new advisories, dependency changes, and baseline expiration are separate controls and must be enforced by the host.
- A real quarantine decision belongs to an independent installation/runtime supervisor, not to this scanner library.
- No existing CLI command, eight invariants, schema, report, or network restrictions are changed. Nothing is attached to default scanning. Further parser strengthening and evaluation are prerequisites for enforcement.
