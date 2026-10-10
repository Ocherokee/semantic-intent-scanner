# Changelog

## Unreleased

- Extend existing I5 `pipe_to_shell` findings to bounded download pipelines
  containing text transformations; preserve exact command evidence and existing
  finding schemas/severity. Canonical remediation and retest text now include
  transformed pipelines.
- Add shared concealed content-to-action guidance to both semantic evaluators
  under existing I5/I8 criteria, with benign and adversarial evaluation fixtures.
- Document unsupported cases and the distinction between auditing instructions
  and preventing exploitation or detecting a hidden controller in malware.

## 1.0.0

1.0.0 stabilizes the documented deterministic interfaces and contracts,
including their schemas, serializers, operational boundaries, and CLI behavior.
The finding, inventory, change, and composite schema versions remain `0.1`.

This release does not claim certified safety, independently validated detector
efficacy, precision, recall, F1, generalization, or calibrated model-backed
semantic efficacy. Model-backed paths remain probabilistic and experimental,
and a clean result does not certify safety.
