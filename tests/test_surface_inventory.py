"""v0.6 bounded agent-readable surface inventory."""

from __future__ import annotations

import argparse
import json

import pytest

from scanner.cli import cmd_inventory
from scanner.finding_contract import FINDING_SCHEMA_VERSION
from scanner.remote_fetch import FetchOutcome
from scanner.surface_inventory import (
    INVENTORY_SCHEMA_VERSION,
    MAX_INVENTORY_ENTRIES,
    DiscoveryRecord,
    InventoryEntry,
    InventoryValidationError,
    SurfaceInventory,
    SurfaceObservation,
    canonical_origin,
    canonicalize_url,
    discover_inventory,
    inventory_as_dict,
    serialize_inventory,
    validate_inventory,
)


def _outcome(
    url: str,
    *,
    status: int = 200,
    body: str = "",
    content_type: str = "text/plain",
    final_url: str | None = None,
    blocked_reason: str | None = None,
    error: str | None = None,
    truncated: bool = False,
    chain: list[dict] | None = None,
) -> FetchOutcome:
    final = final_url or url
    return FetchOutcome(
        requested_url=url,
        final_url=final if status else None,
        status=status,
        content_type=content_type,
        body=body.encode(),
        sha256=("a" * 64 if status == 200 else None),
        fetched_at="2026-08-29T12:00:00Z",
        redirect_chain=chain or ([{"url": url, "status": status}] if status else []),
        cross_origin_redirect=bool(final_url and canonical_origin(final_url) != canonical_origin(url)),
        truncated=truncated,
        error=error,
        blocked_reason=blocked_reason,
    )


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchOutcome]):
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str, **_kwargs) -> FetchOutcome:
        self.calls.append(url)
        return self.responses.get(url, _outcome(url, status=404, body=""))


def _by_url(inventory: SurfaceInventory) -> dict[str, InventoryEntry]:
    return {entry.resource_url: entry for entry in inventory.entries}


def test_url_canonicalization_preserves_nondefault_port_and_query():
    assert canonicalize_url("HTTPS://EXAMPLE.COM:8443/a/../schema?x=1#frag") == (
        "https://example.com:8443/schema?x=1"
    )


def test_default_443_is_same_canonical_origin():
    assert canonical_origin("https://EXAMPLE.com:443/path") == "https://example.com"


def test_equivalent_host_and_path_forms_canonicalize_identically():
    assert canonicalize_url("https://EXAMPLE.com./a/../schema.json#fragment") == (
        "https://example.com/schema.json"
    )
    assert canonical_origin("https://example.com./") == canonical_origin("https://example.com")


def test_userinfo_and_malformed_trailing_dot_hosts_are_rejected():
    with pytest.raises(ValueError, match="userinfo"):
        canonicalize_url("https://user@example.com/schema.json")
    with pytest.raises(ValueError, match="trailing dots"):
        canonicalize_url("https://example.com../schema.json")


def test_non_https_target_is_rejected():
    with pytest.raises(ValueError, match="HTTPS"):
        discover_inventory("http://example.com", fetcher=FakeFetcher({}))


def test_fixed_seed_surface_types_and_provenance():
    inventory = discover_inventory("https://example.com", fetcher=FakeFetcher({}))
    entries = _by_url(inventory)
    assert len(entries) == 4
    assert entries["https://example.com/robots.txt"].surface_type == "robots"
    assert entries["https://example.com/llms.txt"].surface_type == "llms"
    assert entries["https://example.com/llms-full.txt"].surface_type == "llms"
    assert entries["https://example.com/.well-known/ai-plugin.json"].surface_type == "ai_manifest"
    assert entries["https://example.com/robots.txt"].discovery == (DiscoveryRecord("well_known_path"),)
    assert entries["https://example.com/llms.txt"].discovery == (DiscoveryRecord("scanner_known_path"),)


def test_no_common_paths_are_guessed_beyond_fixed_seeds():
    fetcher = FakeFetcher({})
    discover_inventory("https://example.com", fetcher=fetcher)
    assert fetcher.calls == [
        "https://example.com/robots.txt",
        "https://example.com/llms.txt",
        "https://example.com/llms-full.txt",
        "https://example.com/.well-known/ai-plugin.json",
    ]
    assert not any("openapi" in url or url.endswith("/mcp") for url in fetcher.calls)


def test_robots_declares_sitemap_with_distinct_provenance():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    fetcher = FakeFetcher({robots: _outcome(robots, body=f"User-agent: *\nSitemap: {sitemap}\n")})
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[sitemap]
    assert entry.surface_type == "sitemap"
    assert entry.discovery == (DiscoveryRecord("robots_declaration", robots),)
    assert entry.relationships[0].relationship == "declared_by"


def test_sitemap_declares_supported_manifest_and_ignores_ordinary_pages():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    manifest = "https://example.com/.well-known/agent.json"
    xml = f"<urlset><url><loc>https://example.com/page</loc></url><url><loc>{manifest}</loc></url></urlset>"
    fetcher = FakeFetcher({
        robots: _outcome(robots, body=f"Sitemap: {sitemap}"),
        sitemap: _outcome(sitemap, body=xml, content_type="application/xml"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entries = _by_url(inventory)
    assert manifest in entries
    assert entries[manifest].discovery == (DiscoveryRecord("sitemap_declaration", sitemap),)
    assert "https://example.com/page" not in entries


def test_manifest_declares_api_schema_and_preserves_factual_metadata():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://example.com/openapi.json"
    payload = {
        "name_for_model": "weather",
        "description_for_model": "Weather data",
        "schema_version": "v1",
        "api": {"url": schema},
    }
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps(payload), content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entries = _by_url(inventory)
    assert entries[schema].surface_type == "api_schema"
    assert entries[schema].discovery == (DiscoveryRecord("manifest_declaration", manifest),)
    assert entries[manifest].metadata == {
        "name_for_model": "weather",
        "description_for_model": "Weather data",
        "schema_version": "v1",
    }


@pytest.mark.parametrize("declared", ["/openapi.json#section", "//example.com/openapi.json"])
def test_relative_and_scheme_relative_declarations_resolve_to_same_origin(declared):
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://example.com/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": declared}}), content_type="application/json"),
        schema: _outcome(schema, body="{}", content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert _by_url(inventory)[schema].observation.status == "retrieved"
    assert fetcher.calls.count(schema) == 1


def test_schema_declares_endpoint_without_fetching_it():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://example.com/openapi.json"
    endpoint = "https://api.example.com/v1"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": schema}}), content_type="application/json"),
        schema: _outcome(
            schema,
            body=json.dumps({"openapi": "3.1.0", "servers": [{"url": endpoint}]}),
            content_type="application/json",
        ),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[endpoint]
    assert entry.surface_type == "advertised_endpoint"
    assert entry.discovery == (DiscoveryRecord("schema_declaration", schema),)
    assert entry.observation.status == "advertised"
    assert endpoint not in fetcher.calls


def test_manifest_explicitly_advertises_mcp_endpoint_without_probe():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    endpoint = "https://example.com/mcp"
    fetcher = FakeFetcher({
        manifest: _outcome(
            manifest,
            body=json.dumps({"mcp_endpoint": endpoint}),
            content_type="application/json",
        ),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[endpoint]
    assert entry.metadata == {"endpoint_kind": "mcp_endpoint"}
    assert entry.observation.status == "advertised"
    assert endpoint not in fetcher.calls


def test_cross_origin_declared_schema_is_recorded_not_retrieved():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://schemas.example.net/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": schema}}), content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[schema]
    assert entry.observation.status == "advertised"
    assert schema not in fetcher.calls


def test_scheme_relative_cross_origin_declaration_is_not_retrieved():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://schemas.example.net/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(
            manifest,
            body=json.dumps({"api": {"url": "//schemas.example.net/openapi.json#fragment"}}),
            content_type="application/json",
        ),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert _by_url(inventory)[schema].observation.status == "advertised"
    assert schema not in fetcher.calls


def test_explicit_port_change_is_cross_origin_and_not_retrieved():
    manifest = "https://example.com:8443/.well-known/ai-plugin.json"
    schema = "https://example.com:9443/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": schema}}), content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com:8443", fetcher=fetcher)
    assert _by_url(inventory)[schema].observation.status == "advertised"
    assert schema not in fetcher.calls


def test_same_explicit_port_resource_is_retrieved():
    manifest = "https://example.com:8443/.well-known/ai-plugin.json"
    schema = "https://example.com:8443/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": schema}}), content_type="application/json"),
        schema: _outcome(schema, body="{}", content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com:8443", fetcher=fetcher)
    assert _by_url(inventory)[schema].observation.status == "retrieved"


def test_redirect_metadata_and_content_type_are_preserved():
    llms = "https://example.com/llms.txt"
    final = "https://cdn.example.net/llms.txt"
    fetcher = FakeFetcher({
        llms: _outcome(
            llms,
            body="# llms",
            final_url=final,
            content_type="text/markdown; charset=utf-8",
            chain=[{"url": llms, "status": 302}, {"url": final, "status": 200}],
            truncated=True,
        ),
    })
    entry = _by_url(discover_inventory("https://example.com", fetcher=fetcher))[llms]
    assert entry.observation.final_url == final
    assert entry.observation.cross_origin_redirect is True
    assert entry.observation.content_type == "text/markdown; charset=utf-8"
    assert entry.observation.truncated is True


def test_cross_origin_redirect_does_not_authorize_declared_follow_up():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    redirected = "https://cdn.example.net/plugin.json"
    schema = "https://example.com/openapi.json"
    fetcher = FakeFetcher({
        manifest: _outcome(
            manifest,
            final_url=redirected,
            body=json.dumps({"api": {"url": schema}}),
            content_type="application/json",
            chain=[{"url": manifest, "status": 302}, {"url": redirected, "status": 200}],
        ),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[schema]
    assert entry.observation.status == "advertised"
    assert entry.discovery == (DiscoveryRecord("manifest_declaration", redirected),)
    assert schema not in fetcher.calls


@pytest.mark.parametrize("status,blocked,error,expected", [
    (404, None, None, "not_found"),
    (0, "private address", "blocked: private address", "blocked"),
    (503, None, None, "failed"),
    (0, None, "timeout", "failed"),
])
def test_retrieval_statuses(status, blocked, error, expected):
    robots = "https://example.com/robots.txt"
    fetcher = FakeFetcher({
        robots: _outcome(robots, status=status, blocked_reason=blocked, error=error),
    })
    entry = _by_url(discover_inventory("https://example.com", fetcher=fetcher))[robots]
    assert entry.observation.status == expected
    assert entry.observation.blocked_reason == blocked
    assert entry.observation.error == error


def test_malformed_manifest_is_observed_without_children():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body="{bad", content_type="application/json"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    entry = _by_url(inventory)[manifest]
    assert entry.observation.status == "retrieved"
    assert "parse_error" in entry.metadata
    assert len(inventory.entries) == 4


def test_malformed_sitemap_is_observed_without_children():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    fetcher = FakeFetcher({
        robots: _outcome(robots, body=f"Sitemap: {sitemap}"),
        sitemap: _outcome(sitemap, body="<urlset><loc>", content_type="application/xml"),
    })
    entry = _by_url(discover_inventory("https://example.com", fetcher=fetcher))[sitemap]
    assert "parse_error" in entry.metadata


def test_yaml_schema_is_inventoried_without_interpretation():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    schema = "https://example.com/openapi.yaml"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"api": {"url": schema}}), content_type="application/json"),
        schema: _outcome(schema, body="openapi: 3.1.0", content_type="application/yaml"),
    })
    entry = _by_url(discover_inventory("https://example.com", fetcher=fetcher))[schema]
    assert entry.observation.status == "retrieved"
    assert entry.metadata == {"parser": "not_available_for_yaml"}


def test_duplicate_declarations_fetch_resource_once():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    fetcher = FakeFetcher({robots: _outcome(robots, body=f"Sitemap: {sitemap}\nSitemap: {sitemap}")})
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert [entry.resource_url for entry in inventory.entries].count(sitemap) == 1
    assert fetcher.calls.count(sitemap) == 1


def test_trailing_dot_and_dot_segment_aliases_do_not_expand_work():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    fetcher = FakeFetcher({
        robots: _outcome(
            robots,
            body="\n".join([
                "Sitemap: https://example.com./a/../sitemap.xml#one",
                "Sitemap: https://EXAMPLE.com/sitemap.xml#two",
            ]),
        ),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert [entry.resource_url for entry in inventory.entries].count(sitemap) == 1
    assert fetcher.calls.count(sitemap) == 1


def test_cycle_terminates_and_fetches_each_resource_once():
    robots = "https://example.com/robots.txt"
    sitemap = "https://example.com/sitemap.xml"
    xml = f"<sitemapindex><sitemap><loc>{sitemap}</loc></sitemap></sitemapindex>"
    fetcher = FakeFetcher({
        robots: _outcome(robots, body=f"Sitemap: {sitemap}"),
        sitemap: _outcome(sitemap, body=xml, content_type="application/xml"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert fetcher.calls.count(sitemap) == 1
    assert len(_by_url(inventory)[sitemap].discovery) == 2


def test_inventory_cap_is_enforced_and_reported():
    robots = "https://example.com/robots.txt"
    sitemap_urls = [f"https://example.com/sitemap-{i}.xml" for i in range(16)]
    responses = {robots: _outcome(robots, body="\n".join(f"Sitemap: {url}" for url in sitemap_urls))}
    child_urls = [f"https://example.com/.well-known/agent.json?source={i}" for i in range(16)]
    for sitemap in sitemap_urls:
        xml = "<urlset>" + "".join(f"<url><loc>{url}</loc></url>" for url in child_urls) + "</urlset>"
        responses[sitemap] = _outcome(sitemap, body=xml, content_type="application/xml")
    inventory = discover_inventory("https://example.com", fetcher=FakeFetcher(responses))
    assert len(inventory.entries) == MAX_INVENTORY_ENTRIES
    assert inventory.truncated is True


def test_max_depth_stops_recursive_declarations():
    robots = "https://example.com/robots.txt"
    first = "https://example.com/sitemap-1.xml"
    second = "https://example.com/sitemap-2.xml"
    third = "https://example.com/sitemap-3.xml"
    fetcher = FakeFetcher({
        robots: _outcome(robots, body=f"Sitemap: {first}"),
        first: _outcome(first, body=f"<sitemapindex><loc>{second}</loc></sitemapindex>", content_type="application/xml"),
        second: _outcome(second, body=f"<sitemapindex><loc>{third}</loc></sitemapindex>", content_type="application/xml"),
    })
    inventory = discover_inventory("https://example.com", fetcher=fetcher)
    assert second in _by_url(inventory)
    assert third not in _by_url(inventory)
    assert fetcher.calls.count(second) == 1


def test_serialization_order_is_deterministic():
    inventory = discover_inventory("https://example.com", fetcher=FakeFetcher({}))
    assert serialize_inventory(inventory) == serialize_inventory(inventory)
    urls = [entry["resource_url"] for entry in json.loads(serialize_inventory(inventory))["entries"]]
    assert urls == sorted(urls)


def test_equivalent_declaration_orders_serialize_identically():
    robots = "https://example.com/robots.txt"
    first = "https://example.com/sitemap-a.xml"
    second = "https://example.com/sitemap-b.xml"
    responses = {
        first: _outcome(first, body="<urlset/>", content_type="application/xml"),
        second: _outcome(second, body="<urlset/>", content_type="application/xml"),
    }
    forward = FakeFetcher({
        **responses,
        robots: _outcome(robots, body=f"Sitemap: {first}\nSitemap: {second}"),
    })
    reverse = FakeFetcher({
        **responses,
        robots: _outcome(robots, body=f"Sitemap: {second}\nSitemap: {first}"),
    })
    assert serialize_inventory(discover_inventory("https://example.com", fetcher=forward)) == (
        serialize_inventory(discover_inventory("https://example.com", fetcher=reverse))
    )


def test_fetch_and_serialized_mutations_do_not_alias_inventory():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    endpoint = "https://example.com/mcp"
    outcome = _outcome(
        manifest,
        body=json.dumps({"name_for_model": "agent", "endpoint": endpoint}),
        content_type="application/json",
    )
    inventory = discover_inventory("https://example.com", fetcher=FakeFetcher({manifest: outcome}))
    manifest_entry = _by_url(inventory)[manifest]
    endpoint_entry = _by_url(inventory)[endpoint]

    outcome.redirect_chain[0]["url"] = "https://mutated.example/"
    assert manifest_entry.observation.redirect_chain[0]["url"] == manifest

    payload = inventory_as_dict(inventory)
    serialized_manifest = next(entry for entry in payload["entries"] if entry["resource_url"] == manifest)
    serialized_endpoint = next(entry for entry in payload["entries"] if entry["resource_url"] == endpoint)
    serialized_manifest["metadata"]["name_for_model"] = "mutated"
    serialized_endpoint["relationships"][0]["resource_url"] = "https://mutated.example/"
    serialized_manifest["observation"]["redirect_chain"][0]["url"] = "https://mutated.example/"

    assert manifest_entry.metadata == {"name_for_model": "agent"}
    assert endpoint_entry.relationships[0].resource_url == manifest
    assert manifest_entry.observation.redirect_chain[0]["url"] == manifest


def test_empty_inventory_is_valid_and_deterministic():
    inventory = SurfaceInventory("https://example.com", ())
    validate_inventory(inventory)
    assert json.loads(serialize_inventory(inventory))["entries"] == []


def test_inventory_schema_is_independent_of_finding_schema():
    inventory = discover_inventory("https://example.com", fetcher=FakeFetcher({}))
    payload = inventory_as_dict(inventory)
    assert payload["inventory_schema_version"] == INVENTORY_SCHEMA_VERSION == "0.1"
    assert FINDING_SCHEMA_VERSION == "0.1"
    assert "finding_type" not in payload
    assert "findings" not in payload
    assert "overall_risk" not in payload


def test_validation_rejects_unexpected_and_missing_fields():
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=FakeFetcher({})))
    payload["risk"] = "low"
    with pytest.raises(InventoryValidationError, match="unexpected field"):
        validate_inventory(payload)
    del payload["risk"]
    del payload["truncated"]
    with pytest.raises(InventoryValidationError, match="missing required"):
        validate_inventory(payload)


def test_validation_rejects_unsupported_version_and_malformed_nested_shape():
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=FakeFetcher({})))
    payload["inventory_schema_version"] = "0.2"
    with pytest.raises(InventoryValidationError, match="unsupported"):
        validate_inventory(payload)


@pytest.mark.parametrize("field,value,match", [
    ("http_status", "200", "non-negative integer"),
    ("cross_origin_redirect", "false", "must be a boolean"),
    ("redirect_chain", {}, "must be an array"),
])
def test_validation_rejects_malformed_observation_fields(field, value, match):
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=FakeFetcher({})))
    payload["entries"][0]["observation"][field] = value
    with pytest.raises(InventoryValidationError, match=match):
        validate_inventory(payload)


def test_validation_rejects_retrieval_fields_on_advertised_entry():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    endpoint = "https://api.example.net/v1"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"endpoint": endpoint}), content_type="application/json"),
    })
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=fetcher))
    advertised = next(entry for entry in payload["entries"] if entry["resource_url"] == endpoint)
    advertised["observation"]["http_status"] = 200
    with pytest.raises(InventoryValidationError, match="cannot contain retrieval fields"):
        validate_inventory(payload)
    payload["inventory_schema_version"] = "0.1"
    payload["entries"][0]["discovery"] = {}
    with pytest.raises(InventoryValidationError, match="non-empty array"):
        validate_inventory(payload)


def test_validation_rejects_noncanonical_nested_urls():
    manifest = "https://example.com/.well-known/ai-plugin.json"
    endpoint = "https://api.example.net/v1"
    fetcher = FakeFetcher({
        manifest: _outcome(manifest, body=json.dumps({"endpoint": endpoint}), content_type="application/json"),
    })
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=fetcher))
    retrieved = next(entry for entry in payload["entries"] if entry["resource_url"] == manifest)
    retrieved["observation"]["redirect_chain"][0]["url"] = "HTTP://example.com/bad"
    with pytest.raises(InventoryValidationError, match="redirect_chain.*url is invalid"):
        validate_inventory(payload)

    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=fetcher))
    advertised = next(entry for entry in payload["entries"] if entry["resource_url"] == endpoint)
    advertised["relationships"][0]["resource_url"] = "https://EXAMPLE.com/source"
    with pytest.raises(InventoryValidationError, match="relationships.*resource_url must be canonical"):
        validate_inventory(payload)


def test_inventory_does_not_create_findings_or_risk():
    payload = inventory_as_dict(discover_inventory("https://example.com", fetcher=FakeFetcher({})))
    encoded = json.dumps(payload)
    assert "finding" not in encoded
    assert "overall_risk" not in encoded
    assert "severity" not in encoded


def test_cli_inventory_is_explicit_additive_json_path(monkeypatch, capsys):
    inventory = SurfaceInventory("https://example.com", ())
    monkeypatch.setattr("scanner.cli.discover_inventory", lambda _url: inventory)
    code = cmd_inventory(argparse.Namespace(url="https://example.com"))
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["inventory_schema_version"] == "0.1"
    assert "no crawling" in captured.err
