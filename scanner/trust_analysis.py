"""Deterministic structural trust-boundary analysis over v0.6 inventories."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from .finding_contract import (
    EvidenceItem,
    FindingContract,
    Observation,
    Remediation,
    Retest,
    serialize_finding_contracts,
    validate_finding_contract,
)
from .surface_inventory import (
    SurfaceInventory,
    canonical_origin,
    inventory_as_dict,
    validate_inventory,
)

SUPPORTED_ENDPOINT_KINDS = frozenset({"mcp_endpoint", "agent_endpoint", "openapi_server"})


class TrustAnalysisError(ValueError):
    """Raised when deterministic authority extraction cannot proceed safely."""


@dataclass(frozen=True, order=True)
class AuthorityEdge:
    source_surface_type: str
    source_url: str
    declaring_origin: str
    source_field: str
    target_surface_type: str
    target_url: str
    target_origin: str
    relationship_type: str
    provenance_kind: str
    boundary: str


def _materialize(value: SurfaceInventory | Mapping[str, Any]) -> dict[str, Any]:
    validate_inventory(value)
    if isinstance(value, SurfaceInventory):
        return inventory_as_dict(value)
    return copy.deepcopy(dict(value))


def _source_aliases(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    aliases: dict[str, dict[str, Any]] = {}
    for entry in entries:
        urls = {entry["resource_url"]}
        final_url = entry["observation"].get("final_url")
        if final_url is not None:
            urls.add(final_url)
        for url in urls:
            existing = aliases.get(url)
            if existing is not None and (
                existing["surface_type"], existing["resource_url"]
            ) != (entry["surface_type"], entry["resource_url"]):
                raise TrustAnalysisError(f"declaring source URL is ambiguous: {url}")
            aliases[url] = entry
    return aliases


def _relationship_sources(entry: Mapping[str, Any]) -> set[str]:
    return {
        relationship["resource_url"]
        for relationship in entry["relationships"]
        if relationship["relationship"] == "declared_by"
    }


def _edge_for_declaration(
    target: Mapping[str, Any],
    discovery: Mapping[str, Any],
    sources: Mapping[str, dict[str, Any]],
) -> AuthorityEdge | None:
    provenance_kind = discovery["kind"]
    source_url = discovery.get("source_url")
    if source_url is None:
        return None

    target_type = target["surface_type"]
    metadata = target["metadata"]
    endpoint_kind = metadata.get("endpoint_kind")
    if "endpoint_kind" in metadata and not isinstance(endpoint_kind, str):
        raise TrustAnalysisError(
            f"malformed endpoint_kind for authority target {target['resource_url']}"
        )
    if target_type == "advertised_endpoint" and endpoint_kind in SUPPORTED_ENDPOINT_KINDS:
        expected_provenance = (
            "schema_declaration" if endpoint_kind == "openapi_server" else "manifest_declaration"
        )
        if provenance_kind != expected_provenance:
            raise TrustAnalysisError(
                f"authority endpoint provenance is contradictory for {target['resource_url']}"
            )

    expected_source_type: str
    source_field: str
    relationship_type: str
    if target_type == "api_schema" and provenance_kind == "manifest_declaration":
        expected_source_type = "ai_manifest"
        source_field = "api.url"
        relationship_type = "action_schema_delegation"
    elif (
        target_type == "advertised_endpoint"
        and provenance_kind == "manifest_declaration"
        and endpoint_kind in {"mcp_endpoint", "agent_endpoint"}
    ):
        expected_source_type = "ai_manifest"
        source_field = endpoint_kind
        relationship_type = "capability_delegation"
    elif (
        target_type == "advertised_endpoint"
        and provenance_kind == "schema_declaration"
        and endpoint_kind == "openapi_server"
    ):
        expected_source_type = "api_schema"
        source_field = "servers[].url"
        relationship_type = "capability_delegation"
    else:
        return None

    if source_url not in _relationship_sources(target):
        raise TrustAnalysisError(
            f"authority declaration lacks matching declared_by relationship: {source_url}"
        )
    source = sources.get(source_url)
    if source is None:
        raise TrustAnalysisError(f"authority declaration source is not in inventory: {source_url}")
    if source["surface_type"] != expected_source_type:
        raise TrustAnalysisError(
            f"authority declaration source type is contradictory for {source_url}"
        )
    if source["observation"]["status"] != "retrieved":
        raise TrustAnalysisError(f"authority declaration source was not retrieved: {source_url}")
    declaring_origin = canonical_origin(source_url)
    target_origin = canonical_origin(target["resource_url"])
    boundary = "same_origin" if declaring_origin == target_origin else "cross_origin"
    return AuthorityEdge(
        source_surface_type=source["surface_type"],
        source_url=source_url,
        declaring_origin=declaring_origin,
        source_field=source_field,
        target_surface_type=target_type,
        target_url=target["resource_url"],
        target_origin=target_origin,
        relationship_type=relationship_type,
        provenance_kind=provenance_kind,
        boundary=boundary,
    )


def extract_authority_edges(
    inventory: SurfaceInventory | Mapping[str, Any],
) -> tuple[AuthorityEdge, ...]:
    """Extract only explicitly supported structural authority declarations."""
    data = _materialize(inventory)
    entries = data["entries"]
    sources = _source_aliases(entries)
    edges: list[AuthorityEdge] = []
    seen: set[AuthorityEdge] = set()
    for target in entries:
        for discovery in target["discovery"]:
            edge = _edge_for_declaration(target, discovery, sources)
            if edge is None:
                continue
            if edge in seen:
                raise TrustAnalysisError(
                    f"duplicate authority edge: {edge.source_url} -> {edge.target_url}"
                )
            seen.add(edge)
            edges.append(edge)
    return tuple(sorted(edges))


def _finding_for_edge(edge: AuthorityEdge) -> FindingContract:
    if edge.relationship_type == "action_schema_delegation":
        finding_type = "cross_origin_action_schema_delegation"
        target_label = "action schema"
    else:
        finding_type = "cross_origin_capability_delegation"
        target_label = "capability endpoint"
    finding = FindingContract(
        finding_type=finding_type,
        severity="low",
        invariant_id="I8",
        resource=edge.source_url,
        observation=Observation(
            summary=(
                f"{edge.source_surface_type} at {edge.source_url} delegates {target_label} "
                f"authority through {edge.source_field} to {edge.target_url} on another origin."
            ),
            evidence=(
                EvidenceItem("authority_source", edge.source_url, source=edge.source_url),
                EvidenceItem("declaring_origin", edge.declaring_origin, source=edge.source_url),
                EvidenceItem("source_field", edge.source_field, source=edge.source_url),
                EvidenceItem("authority_target", edge.target_url, source=edge.source_url),
                EvidenceItem("target_origin", edge.target_origin, source=edge.source_url),
                EvidenceItem("relationship_type", edge.relationship_type, source=edge.source_url),
                EvidenceItem("boundary", edge.boundary, source=edge.source_url),
                EvidenceItem("provenance", edge.provenance_kind, source=edge.source_url),
            ),
        ),
        rationale=(
            "The declaration gives a resource on a different canonical origin structural "
            "authority over agent-visible actions or capabilities. Cross-origin authority "
            "requires an independent trust decision; this finding does not characterize the "
            "target's content or intent."
        ),
        remediation=Remediation(
            "Action or capability authority is constrained to the declaring origin or its "
            "independent authenticated trust relationship is established."
        ),
        retest=Retest(
            "the supported declaration no longer delegates action or capability authority "
            "across an origin boundary without an independently established trust relationship"
        ),
        context={
            "authority_edge": {
                "source_surface_type": edge.source_surface_type,
                "source_url": edge.source_url,
                "declaring_origin": edge.declaring_origin,
                "source_field": edge.source_field,
                "target_surface_type": edge.target_surface_type,
                "target_url": edge.target_url,
                "target_origin": edge.target_origin,
                "relationship_type": edge.relationship_type,
                "provenance_kind": edge.provenance_kind,
                "boundary": edge.boundary,
            }
        },
    )
    validate_finding_contract(finding)
    return finding


def analyze_trust_boundaries(
    inventory: SurfaceInventory | Mapping[str, Any],
) -> tuple[FindingContract, ...]:
    """Return v0.5 findings for supported cross-origin authority edges only."""
    findings = tuple(
        _finding_for_edge(edge)
        for edge in extract_authority_edges(inventory)
        if edge.boundary == "cross_origin"
    )
    return findings


def serialize_trust_findings(findings: tuple[FindingContract, ...]) -> str:
    """Serialize trust findings through the existing v0.5 list serializer."""
    return serialize_finding_contracts(findings)
