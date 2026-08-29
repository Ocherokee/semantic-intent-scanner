# AI Defensive-Surge Roadmap

**Status:** planning note

**Scope:** defensive, observational scanner capabilities
**Primary source:** [A call for collective action on cyber defense](https://openai.com/collective-cyberdefense/)

## Purpose and boundary

The coalition calls for organizations to fix their highest-risk weaknesses,
verify that fixes and compensating controls work, improve least privilege and
defense in depth, test defenses continuously, share tested playbooks and
machine-usable defensive knowledge, build observability, and keep agentic
identities traceable and accountable.

This scanner can make a focused contribution: continuously inspect
agent-readable software and remote-content surfaces, identify observable trust
and authority failures, preserve evidence, and make remediation verifiable. It
is not a general vulnerability scanner, an offensive agent, an incident-response
platform, or a substitute for internal access-control review.

## Current Coverage

### On `master`

- **Deterministic local surface inspection.** Directory audit detects dangerous
  commands and settings in test and configuration surfaces, including MCP
  configuration. Findings are tied to named invariants rather than presented as
  free-form suspicion.
- **Semantic review of instruction-bearing files.** The judge lane evaluates
  local skill and documentation text against I1-I8, with the evaluated passage
  explicitly treated as untrusted input.
- **Remote-document acquisition with defensive fetch controls.** The generic
  fetcher enforces HTTPS, validates every redirect hop, rejects private and
  special-use destinations, pins transport to a validated IP, preserves
  explicit ports, treats port changes as cross-origin, applies timeouts and
  redirect limits, and caps decompressed content. It records the final URL,
  redirect chain, content hash, observation time, truncation, and origin change.
- **Agent-readable remote-content analysis.** The format-agnostic remote lane
  extracts install commands, pipe-to-shell and script-download patterns,
  alternate package indexes, package references, domains, and cross-origin
  instruction paths. The `llms.txt` adapter covers `/llms.txt` and
  `/llms-full.txt` without making either filename the architecture.
- **Existence separated from provenance.** Registry and DNS observations use a
  provenance ladder (`unclaimed`, `unknown`, `unverified`, `origin_aligned`,
  `conflicting`). A name resolving is never treated as proof of legitimacy.
  Findings distinguish rule-based analysis from time-varying external-state
  evidence and preserve observation timestamps.
- **Verifiable, bounded evidence.** Findings retain invariant, type, risk,
  summary, evidence, analysis method, provenance state, source URL, and source
  hash. Offline fixtures make regression tests repeatable while production
  observations remain explicitly time-dependent.
- **Trust-boundary model.** I8, No Unverified External Instruction, maps to
  M2 Transparency + M4 Integrity + M1 Consent. Dangling references and
  unresolved provenance are detector findings beneath I8, not separate ethical
  invariants.

### Additional v0.4 coverage now on `master`

- **Remote CLI and reports.** `semantic-intent scan-remote <url>` runs the
  remote lane and emits terminal or JSON reports with per-document provenance.
  It distinguishes security risk from an operational failure to scan, so an
  unavailable target is never reported as low risk.
- **Bounded semantic second pass.** Remote content can receive a judge pass
  that treats retrieved text as untrusted data, supplies mechanical findings as
  protected evidence, and does not let semantic interpretation erase those
  findings.
- **MCP tool-description inspection.** `semantic-intent scan-mcp <path>` audits
  captured `tools/list` payloads without starting a server or calling a tool.
  It covers tool and parameter descriptions, hidden directives, instruction
  patterns, obfuscation, capability mismatch, and tool shadowing.
- **Workflow Injection model.** The failure-pattern catalogue documents
  Workflow Injection as a breakdown between understanding, truth verification,
  and authority verification. This remains documented analysis, not a claim
  that the scanner monitors inboxes, tickets, chat, or webhooks.

This coverage aligns most directly with the coalition's calls to find dangerous
weaknesses, test defenses continuously, verify results, strengthen defensive
tools, build observability, and share tested defensive knowledge. It does not
yet satisfy those recommendations end to end.

## v0.5-v1 Candidates

Candidates are ordered by architectural dependency, not market priority.

### v0.5: inventory and stable defensive output

1. **Agent-readable attack-surface inventory**
   - Discover and report `robots.txt`, `llms.txt` variants, sitemaps, public
     API/schema references, advertised MCP or agent endpoints, AI/plugin
     manifests, machine-readable instruction resources, relevant security
     headers, and exposed model/tool metadata.
   - Record what was attempted, retrieved, blocked, absent, redirected, or
     truncated. Absence or fetch failure must never be reported as low risk.

2. **Stable machine-readable finding contract**
   - Version the report schema separately from the scanner package.
   - Normalize the chain
     `observation -> invariant -> evidence -> severity -> remediation -> retest`.
   - Preserve source hashes and time-varying evidence so CI systems and other
     defensive tools can compare scans without mistaking stale observations for
     current truth.

3. **Passive prompt-injection surface classes**
   - Add bounded, non-executing findings for untrusted instruction surfaces,
     privilege-crossing instructions, external tool redirection, hidden agent
     directives, and unbounded remote context.
   - Detect constructions and trust-boundary conditions; do not attempt to make
     the target agent perform them.

4. **Remediation and retest semantics**
   - Give each finding a concrete externally testable pass condition.
   - Support before/after comparison so a defender can verify that a fix or
     compensating control changed the observable condition rather than merely
     suppressing the report.

### v0.6-v0.8: continuous verification

5. **Repeatable baseline and change detection**
   - Compare signed or content-addressed scan snapshots.
   - Highlight newly exposed surfaces, provenance changes, redirects, new
     authority crossings, and regressions after remediation.
   - Keep scheduling and notification outside the core scanner; expose stable
     exit behavior and artifacts that CI or an operator can schedule.

6. **Externally observable least-privilege checks**
   - Inspect declared tool capabilities, public schemas, manifests, and remote
     instructions for authority broader than their stated purpose.
   - Report only what can be supported by public evidence. Do not infer internal
     IAM state from an external scan.

7. **Cross-surface trust-chain analysis**
   - Correlate a document, redirect, package/index, domain, manifest, and tool
     declaration when they form one observable authority chain.
   - Keep worst-finding aggregation available, but add chain evidence so risk
     does not become an unexplained score.

8. **Defensive interchange and tested playbooks**
   - Export redacted, reproducible finding patterns and retest conditions that
     maintainers and security tools can consume.
   - Design sharing as opt-in and privacy-preserving; never transmit scanned
     content or target details by default.

### v0.9-v1: broader verification without becoming a general attack platform

9. **AI-generated-code scrutiny at the scanner boundary**
   - Add an opt-in adapter for repositories or patches identified by the caller
     as AI-generated, using the same local, non-executing audit lanes.
   - Focus on agent-specific trust and authority failures; rely on established
     SAST, dependency, and secret-scanning tools for general code security.

10. **Observability and accountability fields**
    - Where supplied by the target or calling environment, preserve agent,
      tool, model, policy, and execution-context identifiers in evidence.
    - Validate presence and consistency of trace metadata without claiming to
      establish a real-world identity.

11. **Critical-infrastructure deployment profile**
    - Provide conservative defaults, offline registry snapshots, bounded
      resource use, exportable evidence, and compensating-control retests for
      environments where disruption is unacceptable.
    - Treat deployment assistance, funding, and operational ownership as partner
      responsibilities rather than scanner features.

## Explicitly Out of Scope

- **Offensive exploitation or autonomous attack.** No payload delivery,
  credential use, package installation, command execution, persistence,
  evasion, or destructive validation. The scanner observes; it does not prove a
  finding by compromising the target.
- **Unbounded active testing.** No unsolicited probing beyond documented,
  bounded retrieval adapters. Authorized penetration testing belongs in a
  separately governed tool and engagement.
- **General CVE, SAST, DAST, dependency, malware, or secret-scanning replacement.**
  Integrations may consume or link those results, but this project remains
  focused on agent-readable surfaces and semantic trust boundaries.
- **Internal IAM truth.** External declarations can reveal excessive apparent
  authority, but the scanner cannot certify actual least privilege, strong
  authentication, or internal access controls without an explicitly scoped
  internal adapter.
- **SOC and incident-response operations.** Alert triage, containment,
  eradication, recovery, forensics, and emergency coordination are not scanner
  responsibilities.
- **Model-access programs and critical-infrastructure funding.** Responsible
  frontier-model access, trusted-access programs, grants, training, and hands-on
  deployment support are organizational and policy programs.
- **Attribution, retaliation, or imposing costs on attackers.** Those are law
  enforcement, government, provider, and incident-response functions.
- **Global identity infrastructure.** The scanner may validate supplied trace
  fields; it will not create or certify a universal agent identity system.
- **Automatic publication of target data or threat intelligence.** Sharing is
  opt-in, redacted, evidence-backed, and governed by the operator.
- **Ethical Guardian Layer.** A future guardian could evaluate an agent's
  proposed action before authority is exercised, but that is a separate policy
  and decision architecture. It remains a future note only and is not part of
  this scanner's roadmap or implementation scope.

## Roadmap test

A proposed feature belongs here only if it improves the scanner's ability to
observe an agent-facing surface, identify a trust or authority condition,
preserve verifiable evidence, recommend a bounded remediation, or retest that
condition. If it requires the scanner to execute the suspect instruction,
operate the defended system, adjudicate broad ethical policy, or become an
offensive platform, it is outside this project's scope.
