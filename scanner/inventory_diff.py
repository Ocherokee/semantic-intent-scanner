"""Deterministic, offline comparison of validated surface inventories."""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping

from .surface_inventory import (
    INVENTORY_SCHEMA_VERSION,
    SURFACE_TYPES,
    SurfaceInventory,
    canonical_origin,
    canonicalize_url,
    inventory_as_dict,
    validate_inventory,
)

CHANGE_SCHEMA_VERSION = "0.1"
SUPPORTED_CHANGE_SCHEMA_VERSIONS = frozenset({CHANGE_SCHEMA_VERSION})

CHANGE_TYPES = (
    "surface_added",
    "surface_removed",
    "retrieval_status_changed",
    "redirect_behavior_changed",
    "content_type_changed",
    "content_digest_changed",
    "retrieval_truncation_changed",
    "retrieval_error_changed",
    "provenance_changed",
    "relationship_changed",
    "metadata_changed",
    "inventory_truncation_changed",
)
_CHANGE_ORDER = {name: index for index, name in enumerate(CHANGE_TYPES)}
_EXPECTED_PATHS = {
    "surface_added": ("entry",),
    "surface_removed": ("entry",),
    "retrieval_status_changed": ("observation.http_status", "observation.status"),
    "redirect_behavior_changed": (
        "observation.cross_origin_redirect", "observation.final_url", "observation.redirect_chain",
    ),
    "content_type_changed": ("observation.content_type",),
    "content_digest_changed": ("observation.sha256",),
    "retrieval_truncation_changed": ("observation.truncated",),
    "retrieval_error_changed": ("observation.blocked_reason", "observation.error"),
    "provenance_changed": ("discovery",),
    "relationship_changed": ("relationships",),
    "metadata_changed": ("metadata",),
    "inventory_truncation_changed": ("truncated",),
}


class InventoryDiffError(ValueError):
    """Base error for inventory comparison and change validation."""


class ChangeValidationError(InventoryDiffError):
    """Raised when a change-set object violates schema ``0.1``."""


@dataclass(frozen=True, order=True)
class SurfaceIdentity:
    surface_type: str
    resource_url: str


@dataclass(frozen=True)
class InventoryChange:
    change_type: str
    surface_identity: SurfaceIdentity | None
    affected_paths: tuple[str, ...]
    previous: Any
    current: Any
    schema_version: str = CHANGE_SCHEMA_VERSION


@dataclass(frozen=True)
class InventoryChangeSet:
    target_origin: str
    previous_inventory_schema_version: str
    current_inventory_schema_version: str
    changes: tuple[InventoryChange, ...]
    change_schema_version: str = CHANGE_SCHEMA_VERSION


def _json_compatible(value: Any, path: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ChangeValidationError(f"{path} must not contain NaN or infinity")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_compatible(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ChangeValidationError(f"{path} keys must be strings")
            _json_compatible(item, f"{path}.{key}")
        return
    raise ChangeValidationError(f"{path} must contain only JSON-compatible values")


def _exact(value: Mapping[str, Any], required: set[str], path: str) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise ChangeValidationError(f"{path} keys must be strings")
    missing = sorted(required - keys)
    unexpected = sorted(keys - required)
    if missing:
        raise ChangeValidationError(f"{path} missing required field(s): {', '.join(missing)}")
    if unexpected:
        raise ChangeValidationError(f"{path} has unexpected field(s): {', '.join(unexpected)}")


def _nonempty_string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ChangeValidationError(f"{path} must be a non-empty string")


def _identity_as_dict(identity: SurfaceIdentity | None) -> dict[str, str] | None:
    if identity is None:
        return None
    return {"surface_type": identity.surface_type, "resource_url": identity.resource_url}


def _change_as_dict(change: InventoryChange) -> dict[str, Any]:
    return {
        "schema_version": change.schema_version,
        "change_type": change.change_type,
        "surface_identity": _identity_as_dict(change.surface_identity),
        "affected_paths": list(change.affected_paths),
        "previous": copy.deepcopy(change.previous),
        "current": copy.deepcopy(change.current),
    }


def change_set_as_dict(change_set: InventoryChangeSet) -> dict[str, Any]:
    return {
        "change_schema_version": change_set.change_schema_version,
        "target_origin": change_set.target_origin,
        "previous_inventory_schema_version": change_set.previous_inventory_schema_version,
        "current_inventory_schema_version": change_set.current_inventory_schema_version,
        "changes": [_change_as_dict(change) for change in change_set.changes],
    }


def validate_change_set(value: InventoryChangeSet | Mapping[str, Any]) -> None:
    data = change_set_as_dict(value) if isinstance(value, InventoryChangeSet) else value
    if not isinstance(data, Mapping):
        raise ChangeValidationError("change set must be an object")
    fields = {
        "change_schema_version", "target_origin", "previous_inventory_schema_version",
        "current_inventory_schema_version", "changes",
    }
    _exact(data, fields, "change_set")
    version = data["change_schema_version"]
    _nonempty_string(version, "change_schema_version")
    if version not in SUPPORTED_CHANGE_SCHEMA_VERSIONS:
        raise ChangeValidationError(f"unsupported change_schema_version: {version!r}")
    _nonempty_string(data["target_origin"], "target_origin")
    try:
        if canonical_origin(data["target_origin"]) != data["target_origin"]:
            raise ChangeValidationError("target_origin must be a canonical HTTPS origin")
    except ValueError as exc:
        raise ChangeValidationError(f"target_origin is invalid: {exc}") from exc
    for field in ("previous_inventory_schema_version", "current_inventory_schema_version"):
        if data[field] != INVENTORY_SCHEMA_VERSION:
            raise ChangeValidationError(f"{field} is unsupported")
    changes = data["changes"]
    if not isinstance(changes, list):
        raise ChangeValidationError("changes must be an array")
    seen_changes: set[tuple[str, str, str, tuple[str, ...]]] = set()
    order_keys: list[tuple[str, str, int, tuple[str, ...]]] = []
    for index, change in enumerate(changes):
        path = f"changes[{index}]"
        if not isinstance(change, Mapping):
            raise ChangeValidationError(f"{path} must be an object")
        change_fields = {
            "schema_version", "change_type", "surface_identity", "affected_paths",
            "previous", "current",
        }
        _exact(change, change_fields, path)
        if change["schema_version"] != CHANGE_SCHEMA_VERSION:
            raise ChangeValidationError(f"{path}.schema_version is unsupported")
        change_type = change["change_type"]
        if change_type not in CHANGE_TYPES:
            raise ChangeValidationError(f"{path}.change_type is unsupported")
        identity = change["surface_identity"]
        if change_type == "inventory_truncation_changed":
            if identity is not None:
                raise ChangeValidationError(f"{path}.surface_identity must be null")
        else:
            if not isinstance(identity, Mapping):
                raise ChangeValidationError(f"{path}.surface_identity must be an object")
            _exact(identity, {"surface_type", "resource_url"}, f"{path}.surface_identity")
            if identity["surface_type"] not in SURFACE_TYPES:
                raise ChangeValidationError(f"{path}.surface_identity.surface_type is unsupported")
            _nonempty_string(identity["resource_url"], f"{path}.surface_identity.resource_url")
            try:
                if canonicalize_url(identity["resource_url"]) != identity["resource_url"]:
                    raise ChangeValidationError(
                        f"{path}.surface_identity.resource_url must be canonical"
                    )
            except ValueError as exc:
                raise ChangeValidationError(
                    f"{path}.surface_identity.resource_url is invalid: {exc}"
                ) from exc
        affected_paths = change["affected_paths"]
        if (
            not isinstance(affected_paths, list)
            or not affected_paths
            or any(not isinstance(item, str) or not item for item in affected_paths)
            or affected_paths != sorted(set(affected_paths))
        ):
            raise ChangeValidationError(
                f"{path}.affected_paths must be a non-empty sorted array of unique strings"
            )
        if tuple(affected_paths) != _EXPECTED_PATHS[change_type]:
            raise ChangeValidationError(f"{path}.affected_paths do not match {change_type}")
        if change_type == "surface_added":
            if change["previous"] is not None or not isinstance(change["current"], Mapping):
                raise ChangeValidationError(
                    f"{path} must contain a null previous and an entry-object current"
                )
        elif change_type == "surface_removed":
            if not isinstance(change["previous"], Mapping) or change["current"] is not None:
                raise ChangeValidationError(
                    f"{path} must contain an entry-object previous and a null current"
                )
        elif change_type == "inventory_truncation_changed":
            if (
                not isinstance(change["previous"], bool)
                or not isinstance(change["current"], bool)
                or change["previous"] == change["current"]
            ):
                raise ChangeValidationError(f"{path} must compare two different booleans")
        elif change["previous"] == change["current"]:
            raise ChangeValidationError(f"{path} previous and current must differ")
        if change_type == "content_digest_changed":
            previous_digest = change["previous"]
            current_digest = change["current"]
            if (
                not isinstance(previous_digest, Mapping)
                or not isinstance(current_digest, Mapping)
                or not isinstance(previous_digest.get("sha256"), str)
                or not isinstance(current_digest.get("sha256"), str)
                or not previous_digest["sha256"]
                or not current_digest["sha256"]
            ):
                raise ChangeValidationError(
                    f"{path} requires comparable previous and current SHA-256 values"
                )
        _json_compatible(change["previous"], f"{path}.previous")
        _json_compatible(change["current"], f"{path}.current")
        if change_type in {"surface_added", "surface_removed"}:
            snapshot = change["current"] if change_type == "surface_added" else change["previous"]
            try:
                validate_inventory({
                    "inventory_schema_version": INVENTORY_SCHEMA_VERSION,
                    "target_origin": data["target_origin"],
                    "entries": [copy.deepcopy(dict(snapshot))],
                    "truncated": False,
                })
            except ValueError as exc:
                raise ChangeValidationError(f"{path} contains an invalid entry snapshot: {exc}") from exc
            if (
                snapshot["surface_type"] != identity["surface_type"]
                or snapshot["resource_url"] != identity["resource_url"]
            ):
                raise ChangeValidationError(f"{path} entry snapshot does not match surface_identity")
        identity_key = (
            identity["surface_type"] if isinstance(identity, Mapping) else "",
            identity["resource_url"] if isinstance(identity, Mapping) else "",
        )
        uniqueness_key = (*identity_key, change_type, tuple(affected_paths))
        if uniqueness_key in seen_changes:
            raise ChangeValidationError(f"{path} duplicates an existing change record")
        seen_changes.add(uniqueness_key)
        order_keys.append((*identity_key, _CHANGE_ORDER[change_type], tuple(affected_paths)))
    if order_keys != sorted(order_keys):
        raise ChangeValidationError("changes must use canonical deterministic ordering")


def serialize_change_set(change_set: InventoryChangeSet) -> str:
    if not isinstance(change_set, InventoryChangeSet):
        raise ChangeValidationError("serializer requires an InventoryChangeSet")
    validate_change_set(change_set)
    return json.dumps(
        change_set_as_dict(change_set),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )


def _materialize_inventory(value: SurfaceInventory | Mapping[str, Any]) -> dict[str, Any]:
    validate_inventory(value)
    if isinstance(value, SurfaceInventory):
        return inventory_as_dict(value)
    return copy.deepcopy(dict(value))


def _identity(entry: Mapping[str, Any]) -> SurfaceIdentity:
    return SurfaceIdentity(entry["surface_type"], entry["resource_url"])


def _sorted_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(copy.deepcopy(records), key=lambda item: json.dumps(item, sort_keys=True))


def _entry_state(entry: Mapping[str, Any]) -> dict[str, Any]:
    state = copy.deepcopy(dict(entry))
    state["discovery"] = _sorted_records(state["discovery"])
    state["relationships"] = _sorted_records(state["relationships"])
    state["observation"].pop("fetched_at", None)
    return state


def _change(
    change_type: str,
    identity: SurfaceIdentity | None,
    paths: tuple[str, ...],
    previous: Any,
    current: Any,
) -> InventoryChange:
    return InventoryChange(
        change_type,
        identity,
        tuple(sorted(paths)),
        copy.deepcopy(previous),
        copy.deepcopy(current),
    )


def _observation_projection(entry: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    observation = entry["observation"]
    return {field: copy.deepcopy(observation.get(field)) for field in fields}


def compare_inventories(
    previous: SurfaceInventory | Mapping[str, Any],
    current: SurfaceInventory | Mapping[str, Any],
) -> InventoryChangeSet:
    """Compare two validated inventories without mutation or network access."""
    before = _materialize_inventory(previous)
    after = _materialize_inventory(current)
    if before["target_origin"] != after["target_origin"]:
        raise InventoryDiffError("inventory target_origin values must match")

    before_entries = {_identity(entry): entry for entry in before["entries"]}
    after_entries = {_identity(entry): entry for entry in after["entries"]}
    changes: list[InventoryChange] = []

    for identity in sorted(before_entries.keys() - after_entries.keys()):
        changes.append(_change(
            "surface_removed", identity, ("entry",),
            _entry_state(before_entries[identity]), None,
        ))
    for identity in sorted(after_entries.keys() - before_entries.keys()):
        changes.append(_change(
            "surface_added", identity, ("entry",),
            None, _entry_state(after_entries[identity]),
        ))

    projections = (
        ("retrieval_status_changed", ("status", "http_status")),
        ("redirect_behavior_changed", ("final_url", "redirect_chain", "cross_origin_redirect")),
        ("content_type_changed", ("content_type",)),
        ("retrieval_truncation_changed", ("truncated",)),
        ("retrieval_error_changed", ("error", "blocked_reason")),
    )
    for identity in sorted(before_entries.keys() & after_entries.keys()):
        previous_entry = before_entries[identity]
        current_entry = after_entries[identity]
        for change_type, fields in projections:
            previous_value = _observation_projection(previous_entry, fields)
            current_value = _observation_projection(current_entry, fields)
            if previous_value != current_value:
                paths = tuple(f"observation.{field}" for field in fields)
                changes.append(_change(
                    change_type, identity, paths, previous_value, current_value,
                ))

        previous_digest = previous_entry["observation"].get("sha256")
        current_digest = current_entry["observation"].get("sha256")
        if (
            previous_digest is not None
            and current_digest is not None
            and previous_digest != current_digest
        ):
            changes.append(_change(
                "content_digest_changed", identity, ("observation.sha256",),
                {"sha256": previous_digest}, {"sha256": current_digest},
            ))

        previous_discovery = _sorted_records(previous_entry["discovery"])
        current_discovery = _sorted_records(current_entry["discovery"])
        if previous_discovery != current_discovery:
            changes.append(_change(
                "provenance_changed", identity, ("discovery",),
                previous_discovery, current_discovery,
            ))
        previous_relationships = _sorted_records(previous_entry["relationships"])
        current_relationships = _sorted_records(current_entry["relationships"])
        if previous_relationships != current_relationships:
            changes.append(_change(
                "relationship_changed", identity, ("relationships",),
                previous_relationships, current_relationships,
            ))
        if previous_entry["metadata"] != current_entry["metadata"]:
            changes.append(_change(
                "metadata_changed", identity, ("metadata",),
                previous_entry["metadata"], current_entry["metadata"],
            ))

    if before["truncated"] != after["truncated"]:
        changes.append(_change(
            "inventory_truncation_changed", None, ("truncated",),
            before["truncated"], after["truncated"],
        ))

    changes.sort(key=lambda item: (
        item.surface_identity.surface_type if item.surface_identity else "",
        item.surface_identity.resource_url if item.surface_identity else "",
        _CHANGE_ORDER[item.change_type],
        item.affected_paths,
    ))
    result = InventoryChangeSet(
        target_origin=before["target_origin"],
        previous_inventory_schema_version=before["inventory_schema_version"],
        current_inventory_schema_version=after["inventory_schema_version"],
        changes=tuple(changes),
    )
    validate_change_set(result)
    return result
