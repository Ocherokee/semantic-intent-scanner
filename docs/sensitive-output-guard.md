# Sensitive JSON output guard (opt-in prototype)

This module addresses a *separate* security boundary from the existing
scanner: **authorized retrieval does not imply authorized disclosure**.
It does not change the eight invariants, CLI, report schemas, network
fetch restrictions, or existing default scan outputs.

Call \`scanner.sensitive_output.safe_json_response(..., allowed_paths=...)\`
with a field allowlist defined by the trusted application operator, never
by the requester or retrieved data. Paths are tuples of JSON keys; use
\`"*"\` for array elements. Only allowlisted leaves may be released.
Unknown fields and credential-bearing names are redacted. Obvious token
patterns are suppressed even on allowlisted fields. Objects and arrays
retain their shape. Invalid JSON, unsupported input, and traversal/size
limits raise \`DisclosureBlocked\`: do not return the original payload.

## Critical limits

- This is a library component, **not yet integrated into any runtime agent**.
  Installing this scanner alone will not prevent a cloud agent from leaking data.
- Field names and token patterns cannot identify arbitrary secrets under
  misleading keys. Prefer narrow positive allowlists and explicit known schemas.
- Allowlisted prose can include unknown secret formats; do not describe this
  implementation as a complete DLP mechanism.
- Caller must authenticate/authorize requester, enforce access restrictions
  *before* retrieval, sanitize error paths and logs, and apply final outbound
  controls. The existing SSRF guard remains unchanged.
- Never place raw secret-bearing input in scanner findings or model prompts.
- No cloud credentials, live metadata endpoints, or model API calls are
  required for the synthetic tests.

Test: \`pytest tests/test_sensitive_output.py\`.
