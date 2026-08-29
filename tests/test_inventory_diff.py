"""v0.7 deterministic inventory baseline comparison."""

from __future__ import annotations

import argparse
import copy
import json
import sys

import pytest

from scanner.cli import cmd_inventory_diff, main
from scanner.finding_contract import FINDING_SCHEMA_VERSION
from scanner.inventory_diff import (
    CHANGE_SCHEMA_VERSION,
    ChangeValidationError,
    InventoryDiffError,
    change_set_as_dict,
    compare_inventories,
    serialize_change_set,
    validate_change_set,
)
from scanner.surface_inventory import INVENTORY_SCHEMA_VERSION, InventoryValidationError


ORIGIN = "https://example.com"


def _entry(
    url: str = "https://example.com/llms.txt",
    *,
    surface_type: str = "llms",
    status: str = "retrieved",
    http_status: int | None = 200,
) -> dict:
    observation = {
        "status": status,
        "fetched_at": "2026-08-29T12:00:00Z",
        "redirect_chain": [{"url": url, "status": http_status or 0}],
        "cross_origin_redirect": False,
        "truncated": False,
    }
    if http_status is not None:
        observation["http_status"] = http_status
    if status == "retrieved":
        observation.update({
            "final_url": url,
            "content_type": "text/plain",
            "sha256": "a" * 64,
        })
    return {
        "schema_version": "0.1",
        "surface_type": surface_type,
        "resource_url": url,
        "discovery": [{"kind": "scanner_known_path"}],
        "observation": observation,
        "relationships": [],
        "metadata": {},
    }


def _inventory(*entries: dict, truncated: bool = False, origin: str = ORIGIN) -> dict:
    return {
        "inventory_schema_version": "0.1",
        "target_origin": origin,
        "entries": list(entries),
        "truncated": truncated,
    }


def _types(change_set) -> list[str]:
    return [change.change_type for change in change_set.changes]


def test_identical_inventories_produce_no_changes_and_ignore_fetch_time():
    previous = _inventory(_entry())
    current = copy.deepcopy(previous)
    current["entries"][0]["observation"]["fetched_at"] = "2026-08-30T12:00:00Z"
    result = compare_inventories(previous, current)
    assert result.changes == ()
    assert json.loads(serialize_change_set(result))["changes"] == []


def test_surface_added():
    current_entry = _entry()
    change = compare_inventories(_inventory(), _inventory(current_entry)).changes[0]
    assert change.change_type == "surface_added"
    assert change.previous is None
    assert change.current["resource_url"] == current_entry["resource_url"]
    assert "fetched_at" not in change.current["observation"]


def test_surface_removed():
    change = compare_inventories(_inventory(_entry()), _inventory()).changes[0]
    assert change.change_type == "surface_removed"
    assert change.current is None


def test_retrieval_status_change():
    previous = _entry()
    current = _entry(status="not_found", http_status=404)
    change = compare_inventories(_inventory(previous), _inventory(current)).changes[0]
    assert change.change_type == "retrieval_status_changed"
    assert change.previous == {"status": "retrieved", "http_status": 200}
    assert change.current == {"status": "not_found", "http_status": 404}


def test_redirect_behavior_change():
    previous = _entry()
    current = _entry()
    current["observation"].update({
        "final_url": "https://cdn.example.net/llms.txt",
        "redirect_chain": [
            {"url": "https://example.com/llms.txt", "status": 302},
            {"url": "https://cdn.example.net/llms.txt", "status": 200},
        ],
        "cross_origin_redirect": True,
    })
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "redirect_behavior_changed"
    ]


def test_content_type_and_digest_changes_are_separate_facts():
    previous = _entry()
    current = _entry()
    current["observation"]["content_type"] = "text/markdown"
    current["observation"]["sha256"] = "b" * 64
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "content_type_changed", "content_digest_changed",
    ]


def test_provenance_change_is_set_order_independent():
    previous = _entry()
    previous["discovery"] = [
        {"kind": "scanner_known_path"},
        {"kind": "sitemap_declaration", "source_url": "https://example.com/sitemap.xml"},
    ]
    current = copy.deepcopy(previous)
    current["discovery"].reverse()
    assert compare_inventories(_inventory(previous), _inventory(current)).changes == ()
    current["discovery"] = [{"kind": "scanner_known_path"}]
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "provenance_changed"
    ]


def test_relationship_change_is_set_order_independent():
    previous = _entry()
    previous["relationships"] = [
        {"relationship": "declared_by", "resource_url": "https://example.com/a.json"},
        {"relationship": "declared_by", "resource_url": "https://example.com/b.json"},
    ]
    current = copy.deepcopy(previous)
    current["relationships"].reverse()
    assert compare_inventories(_inventory(previous), _inventory(current)).changes == ()
    current["relationships"].pop()
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "relationship_changed"
    ]


def test_metadata_key_order_is_irrelevant_but_values_are_compared():
    previous = _entry()
    previous["metadata"] = {"name": "agent", "version": "1"}
    current = copy.deepcopy(previous)
    current["metadata"] = {"version": "1", "name": "agent"}
    assert compare_inventories(_inventory(previous), _inventory(current)).changes == ()
    current["metadata"]["version"] = "2"
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "metadata_changed"
    ]


def test_inventory_and_retrieval_truncation_changes_are_distinct():
    previous = _entry()
    current = _entry()
    current["observation"]["truncated"] = True
    assert _types(compare_inventories(
        _inventory(previous), _inventory(current, truncated=True),
    )) == ["inventory_truncation_changed", "retrieval_truncation_changed"]


def test_retrieval_error_change():
    previous = _entry(status="failed", http_status=503)
    previous["observation"]["error"] = "service unavailable"
    current = copy.deepcopy(previous)
    current["observation"]["error"] = "timeout"
    assert _types(compare_inventories(_inventory(previous), _inventory(current))) == [
        "retrieval_error_changed"
    ]


def test_multiple_changes_have_stable_order():
    first = _entry("https://example.com/llms.txt")
    second = _entry("https://example.com/llms-full.txt")
    current_first = copy.deepcopy(first)
    current_first["metadata"] = {"new": True}
    result = compare_inventories(_inventory(first), _inventory(current_first, second, truncated=True))
    assert _types(result) == [
        "inventory_truncation_changed", "surface_added", "metadata_changed",
    ]
    assert serialize_change_set(result) == serialize_change_set(result)


def test_input_entry_order_does_not_affect_output():
    first = _entry("https://example.com/llms.txt")
    second = _entry("https://example.com/llms-full.txt")
    forward = _inventory(first, second)
    reverse = _inventory(copy.deepcopy(second), copy.deepcopy(first))
    assert serialize_change_set(compare_inventories(forward, reverse)) == (
        serialize_change_set(compare_inventories(reverse, forward))
    )
    assert compare_inventories(forward, reverse).changes == ()


def test_explicit_ports_participate_in_exact_identity():
    previous = _entry("https://example.com:8443/llms.txt")
    current = _entry("https://example.com:9443/llms.txt")
    result = compare_inventories(
        _inventory(previous, origin="https://example.com:8443"),
        _inventory(current, origin="https://example.com:8443"),
    )
    assert _types(result) == ["surface_removed", "surface_added"]


def test_noncanonical_url_and_duplicate_identity_fail_closed():
    malformed = _inventory(_entry("https://EXAMPLE.com/llms.txt"))
    with pytest.raises(InventoryValidationError, match="canonical"):
        compare_inventories(malformed, _inventory())
    duplicate = _entry()
    with pytest.raises(InventoryValidationError, match="duplicates"):
        compare_inventories(_inventory(duplicate, copy.deepcopy(duplicate)), _inventory())


def test_malformed_and_unsupported_inventory_inputs_fail_closed():
    unsupported = _inventory()
    unsupported["inventory_schema_version"] = "0.2"
    with pytest.raises(InventoryValidationError, match="unsupported"):
        compare_inventories(unsupported, _inventory())
    malformed = _inventory()
    malformed["unexpected"] = True
    with pytest.raises(InventoryValidationError, match="unexpected"):
        compare_inventories(malformed, _inventory())
    nonfinite = _inventory(_entry())
    nonfinite["entries"][0]["metadata"] = {"score": float("nan")}
    with pytest.raises(InventoryValidationError, match="NaN"):
        compare_inventories(nonfinite, _inventory())


def test_different_target_origins_are_rejected_without_guessing():
    with pytest.raises(InventoryDiffError, match="must match"):
        compare_inventories(_inventory(), _inventory(origin="https://other.example"))


def test_comparison_does_not_mutate_or_share_with_inputs():
    previous = _inventory(_entry())
    current = copy.deepcopy(previous)
    current["entries"][0]["metadata"] = {"nested": {"value": "current"}}
    before_previous = copy.deepcopy(previous)
    before_current = copy.deepcopy(current)
    result = compare_inventories(previous, current)
    assert previous == before_previous
    assert current == before_current
    payload = change_set_as_dict(result)
    payload["changes"][0]["current"]["nested"]["value"] = "mutated"
    assert result.changes[0].current == {"nested": {"value": "current"}}


def test_empty_inventories_are_valid_and_deterministic():
    result = compare_inventories(_inventory(), _inventory())
    validate_change_set(result)
    assert result.changes == ()
    assert serialize_change_set(result) == serialize_change_set(result)


def test_change_schema_is_independent_and_contains_no_findings_or_risk():
    result = compare_inventories(_inventory(), _inventory(_entry()))
    payload = change_set_as_dict(result)
    assert CHANGE_SCHEMA_VERSION == "0.1"
    assert INVENTORY_SCHEMA_VERSION == "0.1"
    assert FINDING_SCHEMA_VERSION == "0.1"
    encoded = json.dumps(payload)
    assert "finding" not in encoded
    assert "severity" not in encoded
    assert "risk" not in encoded


def test_change_validation_is_strict_about_versions_fields_and_nonfinite_values():
    payload = change_set_as_dict(compare_inventories(_inventory(), _inventory(_entry())))
    payload["change_schema_version"] = "0.2"
    with pytest.raises(ChangeValidationError, match="unsupported"):
        validate_change_set(payload)
    payload["change_schema_version"] = "0.1"
    payload["unexpected"] = True
    with pytest.raises(ChangeValidationError, match="unexpected"):
        validate_change_set(payload)
    del payload["unexpected"]
    payload["changes"][0]["current"]["metadata"] = {"bad": float("inf")}
    with pytest.raises(ChangeValidationError, match="infinity"):
        validate_change_set(payload)


def test_change_validation_rejects_malformed_snapshots_paths_duplicates_and_order():
    added = change_set_as_dict(compare_inventories(_inventory(), _inventory(_entry())))
    added["changes"][0]["current"]["resource_url"] = "https://other.example/llms.txt"
    with pytest.raises(ChangeValidationError, match="does not match surface_identity"):
        validate_change_set(added)

    added = change_set_as_dict(compare_inventories(_inventory(), _inventory(_entry())))
    added["changes"][0]["affected_paths"] = ["metadata"]
    with pytest.raises(ChangeValidationError, match="do not match"):
        validate_change_set(added)

    added = change_set_as_dict(compare_inventories(_inventory(), _inventory(_entry())))
    added["changes"].append(copy.deepcopy(added["changes"][0]))
    with pytest.raises(ChangeValidationError, match="duplicates"):
        validate_change_set(added)

    first = _entry("https://example.com/llms.txt")
    second = _entry("https://example.com/llms-full.txt")
    unordered = change_set_as_dict(compare_inventories(_inventory(), _inventory(first, second)))
    unordered["changes"].reverse()
    with pytest.raises(ChangeValidationError, match="canonical deterministic ordering"):
        validate_change_set(unordered)


def test_cli_compares_local_artifacts_without_discovery(tmp_path, monkeypatch, capsys):
    previous_path = tmp_path / "previous.json"
    current_path = tmp_path / "current.json"
    previous_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    current_path.write_text(json.dumps(_inventory(_entry())), encoding="utf-8")
    monkeypatch.setattr(
        "scanner.cli.discover_inventory",
        lambda *_args, **_kwargs: pytest.fail("inventory-diff must not perform discovery"),
    )
    code = cmd_inventory_diff(argparse.Namespace(
        previous=str(previous_path), current=str(current_path),
    ))
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["changes"][0]["change_type"] == "surface_added"
    assert captured.err == ""


def test_inventory_diff_is_an_explicit_cli_subcommand(tmp_path, monkeypatch, capsys):
    previous_path = tmp_path / "previous.json"
    current_path = tmp_path / "current.json"
    previous_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    current_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "semantic-intent", "inventory-diff", str(previous_path), str(current_path),
    ])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["changes"] == []


def test_cli_rejects_non_json_and_nonfinite_artifacts(tmp_path, capsys):
    previous_path = tmp_path / "previous.json"
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    for invalid in ("{bad", '{"value": NaN}'):
        previous_path.write_text(invalid, encoding="utf-8")
        code = cmd_inventory_diff(argparse.Namespace(
            previous=str(previous_path), current=str(current_path),
        ))
        assert code == 3
    assert "Error:" in capsys.readouterr().err
