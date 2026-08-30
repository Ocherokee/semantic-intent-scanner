# Security Policy

Semantic Intent Scanner is a research prototype. It can support security review,
but it is not a certification product, a guarantee of safety, or a replacement
for independent assessment.

## Reporting a scanner vulnerability

Please report exploitable vulnerabilities privately before discussing them in a
public issue, pull request, discussion, fixture, or proof of concept.

When GitHub private vulnerability reporting is available, use **Security →
Report a vulnerability** in this repository, or open the repository's
[private advisory form](https://github.com/Ocherokee/semantic-intent-scanner/security/advisories/new).
That route creates a private Security Advisory draft visible to repository
maintainers. If the form is unavailable, do not publish exploit details; check
the repository Security tab for an enabled private reporting route.

We do not publish a private email address and do not promise a response or
resolution SLA. Maintainers will coordinate disclosure according to the report's
impact, reproducibility, and available project capacity.

## Security-sensitive reports

Private reporting is appropriate for scanner behavior such as:

- bypassing SSRF, HTTPS-only, pinned-transport, body, timeout, or guarded-fetch
  restrictions;
- bypassing same-origin, explicit-port, redirect, URL canonicalization, or
  redirect-hop validation;
- executing retrieved documents, manifests, schemas, MCP descriptions, URLs,
  instructions, or capabilities where the scanner promises observation only;
- parser behavior that turns untrusted input into executable behavior;
- a trust-boundary classification defect with material security impact;
- malformed input that silently weakens validation or downgrades a security
  result;
- bypassing provenance, schema-version, or strict contract validation;
- a serializer or report path that fabricates, mutates, conceals, or suppresses
  security-relevant evidence;
- scanner behavior that exposes credentials, tokens, secrets, or authenticated
  request material.

A prompt-injection example, malicious fixture, dangerous instruction, or
cross-origin reference is not automatically a vulnerability in the scanner.
These are inputs the project is designed to inspect. The report should identify
a failure in the scanner's stated security properties or behavior.

## What to include

Please provide enough information for a bounded, independent reproduction:

- affected version and exact commit, if known;
- affected command, module, or path;
- minimal reproduction and the smallest necessary input;
- expected behavior and observed behavior;
- security impact and realistic preconditions;
- whether network interaction, DNS, registries, redirects, or other external
  state is involved;
- proposed remediation or a passing retest condition, if known.

Remove unrelated secrets and personal data. Do not test against systems or
accounts you are not authorized to access.

## Public issues

Use normal GitHub issues for ordinary false positives or false negatives,
feature requests, expected handling of malformed fixtures, usability problems,
and documentation defects. If investigation reveals an exploitable scanner
vulnerability, stop adding details publicly and move the report to the private
Security Advisory path.
