"""Semantic Intent Scanner - invariant-grounded evaluation of AI agent skill files and remote content."""

from .directory_audit import audit_directory
from .evaluator import evaluate_skill
from .finding_contract import (
    FINDING_SCHEMA_VERSION,
    FindingContract,
    adapt_directory_finding,
    adapt_remote_finding,
    adapt_semantic_violation,
    serialize_finding_contract,
    serialize_finding_contracts,
    validate_finding_contract,
)
from .invariants import INVARIANTS, INVARIANT_MAP
from .inventory_diff import (
    CHANGE_SCHEMA_VERSION,
    InventoryChangeSet,
    compare_inventories,
    serialize_change_set,
    validate_change_set,
)
from .llms_txt import audit_llms_txt
from .mcp_adapter import audit_mcp_tools
from .remote_audit import RemoteDocument, analyze_document
from .remote_judge import JudgeResult, judge_document
from .substrate import (
    SUBSTRATE_MECHANISMS,
    get_bridge_for_invariant,
    get_mechanisms_for_invariant,
)
from .surface_inventory import (
    INVENTORY_SCHEMA_VERSION,
    SurfaceInventory,
    discover_inventory,
    serialize_inventory,
    validate_inventory,
)

__all__ = [
    "audit_directory",
    "evaluate_skill",
    "FINDING_SCHEMA_VERSION",
    "FindingContract",
    "adapt_directory_finding",
    "adapt_remote_finding",
    "adapt_semantic_violation",
    "serialize_finding_contract",
    "serialize_finding_contracts",
    "validate_finding_contract",
    "INVARIANTS",
    "INVARIANT_MAP",
    "CHANGE_SCHEMA_VERSION",
    "InventoryChangeSet",
    "compare_inventories",
    "serialize_change_set",
    "validate_change_set",
    "audit_llms_txt",
    "audit_mcp_tools",
    "RemoteDocument",
    "analyze_document",
    "judge_document",
    "JudgeResult",
    "SUBSTRATE_MECHANISMS",
    "get_bridge_for_invariant",
    "get_mechanisms_for_invariant",
    "INVENTORY_SCHEMA_VERSION",
    "SurfaceInventory",
    "discover_inventory",
    "serialize_inventory",
    "validate_inventory",
]
