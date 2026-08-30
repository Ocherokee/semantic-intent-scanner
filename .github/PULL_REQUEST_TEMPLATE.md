## Summary

What changed, and why?

## Layer / scope

- [ ] Documentation or governance only
- [ ] Detector or rule behavior
- [ ] Finding contract
- [ ] Inventory or discovery
- [ ] Inventory diff or baseline
- [ ] Trust-boundary analysis
- [ ] CLI or reporting
- [ ] Network or security boundary
- [ ] Other: <!-- explain -->

## Compatibility impact

- [ ] No schema or version change
- [ ] No existing output-format change
- [ ] No detector, severity, or risk change
- [ ] No network-behavior change

Explain every unchecked item:

## Security properties

Does this PR execute previously inert or untrusted content, add network access,
add a new authority interpretation, change URL/origin/redirect behavior, or add
model/LLM judgment? If yes, explain the boundary and safeguards.

## Verification

- Focused tests: <!-- command and result -->
- Full suite: <!-- command and result -->
- [ ] `git diff --check` passes
- [ ] Regression/adversarial tests added where applicable

## Documentation

- [ ] Public behavior and schema documentation is updated, or no update is needed
