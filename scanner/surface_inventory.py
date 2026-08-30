"""Bounded inventory of public agent-readable surfaces.

This module records existence and observable metadata only. It does not invoke
detectors, assign risk, produce findings, or interpret retrieved instructions.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree

from .remote_fetch import FetchOutcome, Resolver, Transport, guarded_fetch

INVENTORY_SCHEMA_VERSION = "0.1"
SUPPORTED_INVENTORY_SCHEMA_VERSIONS = frozenset({INVENTORY_SCHEMA_VERSION})

MAX_INVENTORY_ENTRIES = 32
MAX_DISCOVERY_DEPTH = 2
MAX_DECLARATIONS_PER_RESOURCE = 16
MAX_METADATA_STRING = 512
MAX_STRUCTURED_DOCUMENT_BYTES = 512 * 1024

SURFACE_TYPES = frozenset({
    "robots", "llms", "sitemap", "ai_manifest", "api_schema",
    "advertised_endpoint",
})
PROVENANCE_KINDS = frozenset({
    "well_known_path", "scanner_known_path", "robots_declaration",
    "sitemap_declaration", "manifest_declaration", "schema_declaration",
})
OBSERVATION_STATUSES = frozenset({
    "retrieved", "not_found", "blocked", "failed", "advertised",
})

_MANIFEST_PATHS = frozenset({
    "/.well-known/ai-plugin.json",
    "/.well-known/agent.json",
    "/.well-known/mcp.json",
})
_SCHEMA_BASENAMES = frozenset({
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
})


class InventoryError(ValueError):
    """Base error for inventory discovery and validation."""


class InventoryValidationError(InventoryError):
    """Raised when an inventory object violates schema ``0.1``."""


@dataclass(frozen=True)
class DiscoveryRecord:
    kind: str
    source_url: str | None = None


@dataclass(frozen=True)
class SurfaceRelationship:
    relationship: str
    resource_url: str


@dataclass(frozen=True)
class SurfaceObservation:
    status: str
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    fetched_at: str | None = None
    sha256: str | None = None
    redirect_chain: tuple[dict[str, Any], ...] = ()
    cross_origin_redirect: bool | None = None
    truncated: bool | None = None
    error: str | None = None
    blocked_reason: str | None = None


@dataclass(frozen=True)
class InventoryEntry:
    surface_type: str
    resource_url: str
    discovery: tuple[DiscoveryRecord, ...]
    observation: SurfaceObservation
    relationships: tuple[SurfaceRelationship, ...] = ()
    metadata: dict[str, Any] | None = None
    schema_version: str = INVENTORY_SCHEMA_VERSION


@dataclass(frozen=True)
class SurfaceInventory:
    target_origin: str
    entries: tuple[InventoryEntry, ...]
    truncated: bool = False
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION


@dataclass
class _EntryBuilder:
    surface_type: str
    resource_url: str
    depth: int
    discovery: dict[tuple[str, str | None], DiscoveryRecord]
    relationships: dict[tuple[str, str], SurfaceRelationship]
    observation: SurfaceObservation
    metadata: dict[str, Any]


def _remove_dot_segments(path: str) -> str:
    """Apply RFC 3986 dot-segment removal without collapsing empty segments."""
    source = path
    output = ""
    while source:
        if source.startswith("../"):
            source = source[3:]
        elif source.startswith("./"):
            source = source[2:]
        elif source.startswith("/./"):
            source = source[2:]
        elif source == "/.":
            source = "/"
        elif source.startswith("/../"):
            source = source[3:]
            output = output.rsplit("/", 1)[0]
        elif source == "/..":
            source = "/"
            output = output.rsplit("/", 1)[0]
        elif source in {".", ".."}:
            source = ""
        else:
            start = 1 if source.startswith("/") else 0
            slash = source.find("/", start)
            if slash < 0:
                output += source
                source = ""
            else:
                output += source[:slash]
                source = source[slash:]
    return output or "/"


def canonicalize_url(url: str) -> str:
    """Canonicalize a public HTTPS resource without changing its query."""
    if not isinstance(url, str) or not url.strip():
        raise InventoryError("resource URL must be a non-empty string")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise InventoryError(f"invalid resource URL: {exc}") from exc
    if parsed.scheme.lower() != "https":
        raise InventoryError("inventory supports HTTPS resources only")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise InventoryError("resource URL requires a hostname and must not contain userinfo")
    host = parsed.hostname.lower()
    if host.endswith(".."):
        raise InventoryError("resource URL hostname has multiple trailing dots")
    host = host.removesuffix(".")
    if not host:
        raise InventoryError("resource URL requires a hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise InventoryError("resource URL hostname is not valid IDNA") from exc
        labels = host.split(".")
        if any(
            not label or len(label) > 63
            or label.startswith("-") or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ) or len(host) > 253:
            raise InventoryError("resource URL hostname is malformed")
        canonical_host = host
    else:
        canonical_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    netloc = canonical_host if port in (None, 443) else f"{canonical_host}:{port}"
    path = _remove_dot_segments(parsed.path or "/")
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def canonical_origin(url: str) -> str:
    canonical = canonicalize_url(url)
    parsed = urlsplit(canonical)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _origin_key(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(canonicalize_url(url))
    return (parsed.scheme, parsed.hostname or "", parsed.port or 443)


def _same_origin(left: str, right: str) -> bool:
    return _origin_key(left) == _origin_key(right)


def _bounded_text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:MAX_METADATA_STRING]


def _surface_type_for_url(url: str) -> str | None:
    path = urlsplit(url).path.lower()
    basename = path.rsplit("/", 1)[-1]
    if path == "/robots.txt":
        return "robots"
    if basename in {"llms.txt", "llms-full.txt"}:
        return "llms"
    if path in _MANIFEST_PATHS:
        return "ai_manifest"
    if basename in _SCHEMA_BASENAMES:
        return "api_schema"
    if basename.endswith(".xml") and "sitemap" in basename:
        return "sitemap"
    return None


def _observation_from_fetch(outcome: FetchOutcome) -> SurfaceObservation:
    if outcome.ok:
        status = "retrieved"
    elif outcome.blocked_reason:
        status = "blocked"
    elif outcome.status == 404:
        status = "not_found"
    else:
        status = "failed"
    return SurfaceObservation(
        status=status,
        final_url=canonicalize_url(outcome.final_url) if outcome.final_url else None,
        http_status=outcome.status,
        content_type=outcome.content_type,
        fetched_at=outcome.fetched_at,
        sha256=outcome.sha256,
        redirect_chain=tuple(dict(hop) for hop in outcome.redirect_chain),
        cross_origin_redirect=outcome.cross_origin_redirect,
        truncated=outcome.truncated,
        error=outcome.error,
        blocked_reason=outcome.blocked_reason,
    )


def _parse_robots(text: str, source_url: str) -> list[tuple[str, str, dict[str, Any]]]:
    found: list[tuple[str, str, dict[str, Any]]] = []
    for line in text.splitlines():
        match = re.match(r"^\s*sitemap\s*:\s*(\S+)\s*$", line, re.IGNORECASE)
        if not match:
            continue
        try:
            url = canonicalize_url(urljoin(source_url, match.group(1)))
        except InventoryError:
            continue
        found.append(("sitemap", url, {}))
    return found[:MAX_DECLARATIONS_PER_RESOURCE]


def _parse_sitemap(text: str, source_url: str) -> tuple[list[tuple[str, str, dict[str, Any]]], dict[str, Any]]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        return [], {"parse_error": _bounded_text(str(exc))}
    found: list[tuple[str, str, dict[str, Any]]] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        try:
            url = canonicalize_url(urljoin(source_url, element.text.strip()))
        except InventoryError:
            continue
        surface_type = _surface_type_for_url(url)
        if surface_type:
            found.append((surface_type, url, {}))
        if len(found) >= MAX_DECLARATIONS_PER_RESOURCE:
            break
    root_type = root.tag.rsplit("}", 1)[-1]
    return found, {"xml_root": _bounded_text(root_type)}


def _load_json(text: str) -> tuple[Any | None, dict[str, Any]]:
    if len(text.encode("utf-8")) > MAX_STRUCTURED_DOCUMENT_BYTES:
        return None, {
            "parse_error": "structured document exceeds byte limit",
            "resource_limit": MAX_STRUCTURED_DOCUMENT_BYTES,
        }
    try:
        return json.loads(text), {}
    except (json.JSONDecodeError, UnicodeError) as exc:
        return None, {"parse_error": _bounded_text(str(exc))}


def _parse_manifest(text: str, source_url: str) -> tuple[list[tuple[str, str, dict[str, Any]]], dict[str, Any]]:
    payload, metadata = _load_json(text)
    if not isinstance(payload, dict):
        if payload is not None:
            metadata["parse_error"] = "manifest root must be an object"
        return [], metadata
    for key in ("name_for_model", "description_for_model", "schema_version"):
        value = _bounded_text(payload.get(key))
        if value is not None:
            metadata[key] = value
    found: list[tuple[str, str, dict[str, Any]]] = []
    api = payload.get("api")
    if "api" in payload:
        if not isinstance(api, dict) or not isinstance(api.get("url"), str):
            metadata["declaration_error"] = "api.url must be a string"
        else:
            try:
                found.append(("api_schema", canonicalize_url(urljoin(source_url, api["url"])), {}))
            except InventoryError as exc:
                metadata["declaration_error"] = f"api.url is invalid: {_bounded_text(str(exc))}"
    for key in ("mcp_endpoint", "agent_endpoint", "endpoint", "url"):
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        try:
            url = canonicalize_url(urljoin(source_url, value))
        except InventoryError as exc:
            metadata[f"{key}_declaration_error"] = _bounded_text(str(exc))
            continue
        found.append(("advertised_endpoint", url, {"endpoint_kind": key}))
    return found[:MAX_DECLARATIONS_PER_RESOURCE], metadata


def _parse_api_schema(text: str, source_url: str) -> tuple[list[tuple[str, str, dict[str, Any]]], dict[str, Any]]:
    if not urlsplit(source_url).path.lower().endswith(".json"):
        return [], {"parser": "not_available_for_yaml"}
    payload, metadata = _load_json(text)
    if not isinstance(payload, dict):
        if payload is not None:
            metadata["parse_error"] = "API schema root must be an object"
        return [], metadata
    schema_version = payload.get("openapi") or payload.get("swagger")
    bounded = _bounded_text(schema_version)
    if bounded is not None:
        metadata["declared_schema_version"] = bounded
    found: list[tuple[str, str, dict[str, Any]]] = []
    servers = payload.get("servers")
    if isinstance(servers, list):
        for index, server in enumerate(servers[:MAX_DECLARATIONS_PER_RESOURCE]):
            source_field = f"servers[{index}].url"
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                metadata[f"declaration_error_{index}"] = f"{source_field} must be a string"
                continue
            try:
                url = canonicalize_url(urljoin(source_url, server["url"]))
            except InventoryError as exc:
                metadata[f"declaration_error_{index}"] = f"{source_field} is invalid: {_bounded_text(str(exc))}"
                continue
            found.append(("advertised_endpoint", url, {
                "endpoint_kind": "openapi_server", "source_field": source_field,
            }))
    elif "servers" in payload:
        metadata["declaration_error"] = "servers must be an array"
    return found, metadata


def _discovery_key(record: DiscoveryRecord) -> tuple[str, str]:
    return (record.kind, record.source_url or "")


def _relationship_key(relationship: SurfaceRelationship) -> tuple[str, str]:
    return (relationship.relationship, relationship.resource_url)


def _entry_as_dict(entry: InventoryEntry) -> dict[str, Any]:
    observation = {"status": entry.observation.status}
    for key in (
        "final_url", "http_status", "content_type", "fetched_at", "sha256",
        "cross_origin_redirect", "truncated", "error", "blocked_reason",
    ):
        value = getattr(entry.observation, key)
        if value is not None:
            observation[key] = value
    if entry.observation.redirect_chain:
        observation["redirect_chain"] = [dict(hop) for hop in entry.observation.redirect_chain]
    out = {
        "schema_version": entry.schema_version,
        "surface_type": entry.surface_type,
        "resource_url": entry.resource_url,
        "discovery": [
            ({"kind": item.kind, "source_url": item.source_url}
             if item.source_url is not None else {"kind": item.kind})
            for item in entry.discovery
        ],
        "observation": observation,
        "relationships": [
            {"relationship": item.relationship, "resource_url": item.resource_url}
            for item in entry.relationships
        ],
        "metadata": copy.deepcopy(entry.metadata or {}),
    }
    return out


def inventory_as_dict(inventory: SurfaceInventory) -> dict[str, Any]:
    return {
        "inventory_schema_version": inventory.inventory_schema_version,
        "target_origin": inventory.target_origin,
        "entries": [_entry_as_dict(entry) for entry in inventory.entries],
        "truncated": inventory.truncated,
    }


def _json_compatible(value: Any, path: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise InventoryValidationError(f"{path} must not contain NaN or infinity")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_compatible(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InventoryValidationError(f"{path} keys must be strings")
            _json_compatible(item, f"{path}.{key}")
        return
    raise InventoryValidationError(f"{path} must contain only JSON-compatible values")


def _exact(value: Mapping[str, Any], required: set[str], allowed: set[str], path: str) -> None:
    if any(not isinstance(key, str) for key in value):
        raise InventoryValidationError(f"{path} keys must be strings")
    missing = sorted(required - set(value))
    unexpected = sorted(set(value) - allowed)
    if missing:
        raise InventoryValidationError(f"{path} missing required field(s): {', '.join(missing)}")
    if unexpected:
        raise InventoryValidationError(f"{path} has unexpected field(s): {', '.join(unexpected)}")


def _string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise InventoryValidationError(f"{path} must be a non-empty string")


def validate_inventory(value: SurfaceInventory | Mapping[str, Any]) -> None:
    data = inventory_as_dict(value) if isinstance(value, SurfaceInventory) else value
    if not isinstance(data, Mapping):
        raise InventoryValidationError("inventory must be an object")
    _exact(
        data, {"inventory_schema_version", "target_origin", "entries", "truncated"},
        {"inventory_schema_version", "target_origin", "entries", "truncated"}, "inventory",
    )
    version = data["inventory_schema_version"]
    _string(version, "inventory_schema_version")
    if version not in SUPPORTED_INVENTORY_SCHEMA_VERSIONS:
        raise InventoryValidationError(f"unsupported inventory_schema_version: {version!r}")
    _string(data["target_origin"], "target_origin")
    try:
        if canonical_origin(data["target_origin"]) != data["target_origin"]:
            raise InventoryValidationError("target_origin must be a canonical HTTPS origin")
    except InventoryError as exc:
        raise InventoryValidationError(f"target_origin is invalid: {exc}") from exc
    if not isinstance(data["truncated"], bool):
        raise InventoryValidationError("truncated must be a boolean")
    entries = data["entries"]
    if not isinstance(entries, list):
        raise InventoryValidationError("entries must be an array")
    if len(entries) > MAX_INVENTORY_ENTRIES:
        raise InventoryValidationError(f"entries must not exceed {MAX_INVENTORY_ENTRIES}")
    identities: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        path = f"entries[{index}]"
        if not isinstance(entry, Mapping):
            raise InventoryValidationError(f"{path} must be an object")
        _exact(
            entry,
            {"schema_version", "surface_type", "resource_url", "discovery", "observation", "relationships", "metadata"},
            {"schema_version", "surface_type", "resource_url", "discovery", "observation", "relationships", "metadata"},
            path,
        )
        if entry["schema_version"] != INVENTORY_SCHEMA_VERSION:
            raise InventoryValidationError(f"{path}.schema_version is unsupported")
        if entry["surface_type"] not in SURFACE_TYPES:
            raise InventoryValidationError(f"{path}.surface_type is unsupported")
        _string(entry["resource_url"], f"{path}.resource_url")
        try:
            if canonicalize_url(entry["resource_url"]) != entry["resource_url"]:
                raise InventoryValidationError(f"{path}.resource_url must be canonical")
        except InventoryError as exc:
            raise InventoryValidationError(f"{path}.resource_url is invalid: {exc}") from exc
        identity = (entry["surface_type"], entry["resource_url"])
        if identity in identities:
            raise InventoryValidationError(f"{path} duplicates an existing surface identity")
        identities.add(identity)
        discovery = entry["discovery"]
        if not isinstance(discovery, list) or not discovery:
            raise InventoryValidationError(f"{path}.discovery must be a non-empty array")
        for d_index, record in enumerate(discovery):
            d_path = f"{path}.discovery[{d_index}]"
            if not isinstance(record, Mapping):
                raise InventoryValidationError(f"{d_path} must be an object")
            _exact(record, {"kind"}, {"kind", "source_url"}, d_path)
            if record["kind"] not in PROVENANCE_KINDS:
                raise InventoryValidationError(f"{d_path}.kind is unsupported")
            if "source_url" in record:
                _string(record["source_url"], f"{d_path}.source_url")
                try:
                    if canonicalize_url(record["source_url"]) != record["source_url"]:
                        raise InventoryValidationError(f"{d_path}.source_url must be canonical")
                except InventoryError as exc:
                    raise InventoryValidationError(f"{d_path}.source_url is invalid: {exc}") from exc
        observation = entry["observation"]
        if not isinstance(observation, Mapping):
            raise InventoryValidationError(f"{path}.observation must be an object")
        allowed_observation = {
            "status", "final_url", "http_status", "content_type", "fetched_at", "sha256",
            "redirect_chain", "cross_origin_redirect", "truncated", "error", "blocked_reason",
        }
        _exact(observation, {"status"}, allowed_observation, f"{path}.observation")
        if observation["status"] not in OBSERVATION_STATUSES:
            raise InventoryValidationError(f"{path}.observation.status is unsupported")
        for string_field in (
            "final_url", "content_type", "fetched_at", "sha256", "error", "blocked_reason",
        ):
            if string_field in observation:
                _string(observation[string_field], f"{path}.observation.{string_field}")
        if "final_url" in observation:
            try:
                if canonicalize_url(observation["final_url"]) != observation["final_url"]:
                    raise InventoryValidationError(f"{path}.observation.final_url must be canonical")
            except InventoryError as exc:
                raise InventoryValidationError(f"{path}.observation.final_url is invalid: {exc}") from exc
        if "http_status" in observation and (
            not isinstance(observation["http_status"], int)
            or isinstance(observation["http_status"], bool)
            or observation["http_status"] < 0
        ):
            raise InventoryValidationError(f"{path}.observation.http_status must be a non-negative integer")
        for boolean_field in ("cross_origin_redirect", "truncated"):
            if boolean_field in observation and not isinstance(observation[boolean_field], bool):
                raise InventoryValidationError(f"{path}.observation.{boolean_field} must be a boolean")
        if "redirect_chain" in observation:
            chain = observation["redirect_chain"]
            if not isinstance(chain, list):
                raise InventoryValidationError(f"{path}.observation.redirect_chain must be an array")
            for hop_index, hop in enumerate(chain):
                hop_path = f"{path}.observation.redirect_chain[{hop_index}]"
                if not isinstance(hop, Mapping):
                    raise InventoryValidationError(f"{hop_path} must be an object")
                _exact(hop, {"url", "status"}, {"url", "status"}, hop_path)
                _string(hop["url"], f"{hop_path}.url")
                try:
                    if canonicalize_url(hop["url"]) != hop["url"]:
                        raise InventoryValidationError(f"{hop_path}.url must be canonical")
                except InventoryError as exc:
                    raise InventoryValidationError(f"{hop_path}.url is invalid: {exc}") from exc
                if not isinstance(hop["status"], int) or isinstance(hop["status"], bool):
                    raise InventoryValidationError(f"{hop_path}.status must be an integer")
        if observation["status"] == "advertised" and set(observation) != {"status"}:
            raise InventoryValidationError(f"{path}.observation advertised status cannot contain retrieval fields")
        _json_compatible(dict(observation), f"{path}.observation")
        relationships = entry["relationships"]
        if not isinstance(relationships, list):
            raise InventoryValidationError(f"{path}.relationships must be an array")
        for r_index, relationship in enumerate(relationships):
            r_path = f"{path}.relationships[{r_index}]"
            if not isinstance(relationship, Mapping):
                raise InventoryValidationError(f"{r_path} must be an object")
            _exact(relationship, {"relationship", "resource_url"}, {"relationship", "resource_url"}, r_path)
            if relationship["relationship"] != "declared_by":
                raise InventoryValidationError(f"{r_path}.relationship is unsupported")
            _string(relationship["resource_url"], f"{r_path}.resource_url")
            try:
                if canonicalize_url(relationship["resource_url"]) != relationship["resource_url"]:
                    raise InventoryValidationError(f"{r_path}.resource_url must be canonical")
            except InventoryError as exc:
                raise InventoryValidationError(f"{r_path}.resource_url is invalid: {exc}") from exc
        if not isinstance(entry["metadata"], dict):
            raise InventoryValidationError(f"{path}.metadata must be an object")
        _json_compatible(entry["metadata"], f"{path}.metadata")


def serialize_inventory(inventory: SurfaceInventory) -> str:
    if not isinstance(inventory, SurfaceInventory):
        raise InventoryValidationError("serializer requires a SurfaceInventory")
    validate_inventory(inventory)
    return json.dumps(
        inventory_as_dict(inventory), indent=2, sort_keys=True,
        ensure_ascii=False, allow_nan=False,
    )


def discover_inventory(
    target: str,
    *,
    fetcher: Callable[..., FetchOutcome] = guarded_fetch,
    transport: Transport | None = None,
    resolver: Resolver | None = None,
) -> SurfaceInventory:
    """Discover a deterministic, bounded inventory from one HTTPS origin."""
    target_origin = canonical_origin(target)
    builders: dict[tuple[str, str], _EntryBuilder] = {}
    queue: list[tuple[str, str]] = []
    fetched: set[tuple[str, str]] = set()
    inventory_truncated = False

    def add(
        surface_type: str,
        resource_url: str,
        provenance: DiscoveryRecord,
        *,
        depth: int,
        metadata: Mapping[str, Any] | None = None,
        fetch_authorized: bool = True,
    ) -> _EntryBuilder | None:
        nonlocal inventory_truncated
        try:
            resource_url = canonicalize_url(resource_url)
        except InventoryError:
            return None
        key = (surface_type, resource_url)
        source_url = provenance.source_url
        relationship = (
            SurfaceRelationship("declared_by", source_url)
            if source_url is not None else None
        )
        if key in builders:
            builder = builders[key]
            builder.depth = min(builder.depth, depth)
            builder.discovery[(provenance.kind, source_url)] = provenance
            if relationship:
                builder.relationships[_relationship_key(relationship)] = relationship
            if metadata:
                builder.metadata.update(metadata)
            return builder
        if len(builders) >= MAX_INVENTORY_ENTRIES:
            inventory_truncated = True
            return None
        should_fetch = (
            surface_type != "advertised_endpoint"
            and depth <= MAX_DISCOVERY_DEPTH
            and fetch_authorized
            and _same_origin(resource_url, target_origin)
        )
        observation = SurfaceObservation(status="failed" if should_fetch else "advertised")
        builder = _EntryBuilder(
            surface_type=surface_type,
            resource_url=resource_url,
            depth=depth,
            discovery={(provenance.kind, source_url): provenance},
            relationships=({_relationship_key(relationship): relationship} if relationship else {}),
            observation=observation,
            metadata=dict(metadata or {}),
        )
        builders[key] = builder
        if should_fetch:
            queue.append(key)
        return builder

    add("robots", f"{target_origin}/robots.txt", DiscoveryRecord("well_known_path"), depth=0)
    add("llms", f"{target_origin}/llms.txt", DiscoveryRecord("scanner_known_path"), depth=0)
    add("llms", f"{target_origin}/llms-full.txt", DiscoveryRecord("scanner_known_path"), depth=0)
    add(
        "ai_manifest", f"{target_origin}/.well-known/ai-plugin.json",
        DiscoveryRecord("well_known_path"), depth=0,
    )

    while queue:
        key = queue.pop(0)
        if key in fetched:
            continue
        fetched.add(key)
        builder = builders[key]
        outcome = fetcher(builder.resource_url, transport=transport, resolver=resolver)
        builder.observation = _observation_from_fetch(outcome)
        if not outcome.ok or builder.depth >= MAX_DISCOVERY_DEPTH:
            continue
        source_url = canonicalize_url(outcome.final_url or builder.resource_url)
        declarations: list[tuple[str, str, dict[str, Any]]] = []
        parsed_metadata: dict[str, Any] = {}
        if builder.surface_type == "robots":
            declarations = _parse_robots(outcome.text(), source_url)
            provenance_kind = "robots_declaration"
        elif builder.surface_type == "sitemap":
            declarations, parsed_metadata = _parse_sitemap(outcome.text(), source_url)
            provenance_kind = "sitemap_declaration"
        elif builder.surface_type == "ai_manifest":
            declarations, parsed_metadata = _parse_manifest(outcome.text(), source_url)
            provenance_kind = "manifest_declaration"
        elif builder.surface_type == "api_schema":
            declarations, parsed_metadata = _parse_api_schema(outcome.text(), source_url)
            provenance_kind = "schema_declaration"
        else:
            declarations = []
            provenance_kind = "sitemap_declaration"  # unused
        builder.metadata.update(parsed_metadata)
        normalized = sorted(
            declarations,
            key=lambda item: (item[1], item[0], json.dumps(item[2], sort_keys=True)),
        )
        for child_type, child_url, child_metadata in normalized[:MAX_DECLARATIONS_PER_RESOURCE]:
            add(
                child_type,
                child_url,
                DiscoveryRecord(provenance_kind, source_url),
                depth=builder.depth + 1,
                metadata=child_metadata,
                fetch_authorized=_same_origin(source_url, target_origin),
            )

    entries: list[InventoryEntry] = []
    for key in sorted(builders, key=lambda item: (item[1], item[0])):
        builder = builders[key]
        entries.append(InventoryEntry(
            surface_type=builder.surface_type,
            resource_url=builder.resource_url,
            discovery=tuple(sorted(builder.discovery.values(), key=_discovery_key)),
            observation=builder.observation,
            relationships=tuple(sorted(builder.relationships.values(), key=_relationship_key)),
            metadata=copy.deepcopy(builder.metadata),
        ))
    inventory = SurfaceInventory(target_origin, tuple(entries), inventory_truncated)
    validate_inventory(inventory)
    return inventory
