"""Semantic Intent Scanner - invariant-grounded evaluation of AI agent skill files and remote content."""

from .directory_audit import audit_directory
from .evaluator import evaluate_skill
from .invariants import INVARIANTS, INVARIANT_MAP
from .llms_txt import audit_llms_txt
from .remote_audit import RemoteDocument, analyze_document
from .remote_judge import JudgeResult, judge_document
from .substrate import (
    SUBSTRATE_MECHANISMS,
    get_bridge_for_invariant,
    get_mechanisms_for_invariant,
)

__all__ = [
    "audit_directory",
    "evaluate_skill",
    "INVARIANTS",
    "INVARIANT_MAP",
    "audit_llms_txt",
    "RemoteDocument",
    "analyze_document",
    "judge_document",
    "JudgeResult",
    "SUBSTRATE_MECHANISMS",
    "get_bridge_for_invariant",
    "get_mechanisms_for_invariant",
]
