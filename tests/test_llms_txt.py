"""
Tests for the llms.txt adapter (scanner/llms_txt.py).

Offline: the fetcher is faked to serve fixture bytes, package/domain state
comes from the mock registry snapshot.
"""

from pathlib import Path

import pytest

from scanner.llms_txt import audit_llms_txt, candidate_urls
from scanner.registry import RegistryClient
from scanner.remote_fetch import FetchOutcome

FIX = Path(__file__).parent / "fixtures" / "llms_txt"
MOCK_REGISTRY = FIX / "mock_registry.json"
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _fetch_serving(fixture_file: Path, served_path: str = "llms.txt"):
    body = fixture_file.read_bytes()

    def _fetch(url: str) -> FetchOutcome:
        if url.rstrip("/").endswith("/" + served_path):
            return FetchOutcome(
                requested_url=url, final_url=url, status=200, content_type="text/markdown",
                body=body, sha256="sha-" + str(len(body)), fetched_at="2026-08-27T00:00:00Z",
            )
        return FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="HTTP 404")

    return _fetch


def _audit(fixture_rel: str, domain: str, served_path: str = "llms.txt") -> dict:
    return audit_llms_txt(
        domain,
        registry=RegistryClient.from_fixture(MOCK_REGISTRY),
        fetch=_fetch_serving(FIX / fixture_rel, served_path),
    )


def _types(result):
    return {f["finding_type"] for f in result["findings"]}


def test_candidate_urls():
    assert candidate_urls("example.com") == [
        "https://example.com/llms.txt", "https://example.com/llms-full.txt"
    ]
    assert candidate_urls("https://example.com/llms-full.txt") == ["https://example.com/llms-full.txt"]


def test_benign_first_party_is_low_and_clean():
    r = _audit("benign/first-party-sdk-llms.txt", "sdk.example.com")
    assert r["overall_risk"] == "low"
    # one low finding recording origin_aligned; nothing dangling / higher
    assert all(f["risk"] == "low" for f in r["findings"])
    states = {f["provenance_state"] for f in r["findings"]}
    assert states <= {"origin_aligned", None}
    assert "dangling_package" not in _types(r)


def test_benign_third_party_docs_is_low_risk():
    # references well-known packages from a site that doesn't own them:
    # recorded as low-risk 'unverified', overall still low.
    r = _audit("benign/docs-site-llms.txt", "docs.example.com")
    assert r["overall_risk"] == "low"
    assert all(f["risk"] == "low" for f in r["findings"])
    assert "dangling_package" not in _types(r) and "dangling_domain" not in _types(r)


def test_suspicious_newly_registered_is_medium():
    r = _audit("suspicious/agent-tooling-llms.txt", "aitools.example")
    assert r["overall_risk"] == "medium"
    assert "unverified_package_provenance" in _types(r)


def test_malicious_onboarding_is_critical():
    r = _audit("malicious/onboarding-llms-full.txt", "acme.example", served_path="llms-full.txt")
    assert r["overall_risk"] == "critical"
    t = _types(r)
    assert "dangling_package" in t          # unregistered acme-agent-sdk
    assert "dangling_domain" in t           # setup.acme.dev does not resolve
    assert "index_url_override" in t        # --extra-index-url to a dead host
    assert "pipe_to_shell" in t             # curl | sh
    # every registry/dns-backed finding carries an observation timestamp
    for f in r["findings"]:
        assert f["observed_at"]
        if f["finding_type"] in ("dangling_package", "dangling_domain", "index_url_override"):
            assert f["analysis_method"] == "fixture"


def test_malicious_typosquat_is_high():
    r = _audit("malicious/typosquat-llms.txt", "pkgs.example")
    assert RISK_ORDER[r["overall_risk"]] >= RISK_ORDER["high"]
    assert any(f["detail"].get("resembles") for f in r["findings"])


def test_registered_after_dangling_not_downgraded():
    r = _audit("malicious/registered-after-dangling-llms.txt", "acme.example")
    assert RISK_ORDER[r["overall_risk"]] >= RISK_ORDER["high"]
    prov = [f for f in r["findings"] if f["finding_type"] == "unverified_package_provenance"]
    assert prov and prov[0]["provenance_state"] in ("unverified", "conflicting")


def test_no_llms_txt_served_is_safe():
    r = audit_llms_txt(
        "nothing.example",
        registry=RegistryClient.from_fixture(MOCK_REGISTRY),
        fetch=lambda url: FetchOutcome(url, None, 404, None, b"", None, "2026-08-27T00:00:00Z", error="404"),
    )
    assert r["overall_risk"] == "low" and r["findings"] == []
    assert "note" in r


def test_ssrf_block_is_reported_not_crashed():
    def _blocked(url: str) -> FetchOutcome:
        return FetchOutcome(url, None, 0, None, b"", None, "2026-08-27T00:00:00Z",
                            blocked_reason="resolves to 10.0.0.1: private address",
                            error="blocked: private address")

    r = audit_llms_txt("internal.example", registry=RegistryClient.from_fixture(MOCK_REGISTRY), fetch=_blocked)
    assert r["overall_risk"] == "low"
    assert "SSRF" in r["note"] or "blocked" in r["note"]


def test_documents_carry_provenance():
    r = _audit("malicious/onboarding-llms-full.txt", "acme.example", served_path="llms-full.txt")
    served = [d for d in r["documents"] if d["status"] == 200]
    assert served and served[0]["sha256"] and served[0]["fetched_at"].endswith("Z")
