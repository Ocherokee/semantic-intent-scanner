"""
Model identifiers for the optional, probabilistic, model-backed lanes.

Importing this module performs **no** network I/O and requires no credential.

The lanes that read these identifiers -- the semantic skill evaluator
(``scanner.evaluator``) and the two-pass retrieved-content / MCP judge
(``scanner.remote_judge``) -- are **not** part of the deterministic release
gate. A fresh checkout with no ``ANTHROPIC_API_KEY`` runs the entire
deterministic test suite without them, and a model failure never erases a
deterministic finding. See ``docs/model-boundary.md``.

These constants are the *tested assumptions* published for the release: the
model a live run is expected to call. They are single-sourced here so the
value appears in exactly one place.

KNOWN PRE-1.0 ITEM: ``SEMANTIC_EVALUATOR_MODEL`` is a superseded identifier
(``claude-opus-4-5``). It is retained unchanged in the v0.11 stabilization
slice because the semantic lane is probabilistic and was not exercised here;
aligning it with ``JUDGE_MODEL`` is a probabilistic-path change that belongs
in a protected pre-release evaluation, and is tracked as a required pre-1.0
fix in ``docs/v1.0-release-readiness.md``.
"""

from __future__ import annotations

# Model the semantic skill evaluator (scanner.evaluator.evaluate_chunk) calls.
SEMANTIC_EVALUATOR_MODEL = "claude-opus-4-5"

# Model the retrieved-content / MCP two-pass judge (scanner.remote_judge) calls.
JUDGE_MODEL = "claude-opus-5"

__all__ = ["SEMANTIC_EVALUATOR_MODEL", "JUDGE_MODEL"]
