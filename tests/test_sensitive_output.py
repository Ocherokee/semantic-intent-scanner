"""Credential-disclosure regression tests; entirely synthetic."""
import json
import pytest

from scanner.sensitive_output import (
    REDACTED, DisclosureBlocked, safe_json_response, sanitize_json,
)

POLICY = frozenset({("status",), ("region",), ("items", "*", "name"),
                    ("items", "*", "status"), ("metadata", "version")})


def test_nested_credentials_and_arrays_are_redacted():
    source = {
        "status": "healthy", "region": "us-west-2", "unknown": "do not disclose",
        "credentials": {"accessKeyId": "FAKE_A", "secretAccessKey": "FAKE_B"},
        "items": [{"name": "worker", "status": "ok", "sessionToken": "FAKE_C"}],
    }
    before = json.dumps(source)
    result = sanitize_json(source, allowed_paths=POLICY)
    assert result["status"] == "healthy"
    assert result["region"] == "us-west-2"
    assert result["unknown"] == REDACTED
    assert set(result["credentials"].values()) == {REDACTED}
    assert result["items"][0] == {"name": "worker", "status": "ok", "sessionToken": REDACTED}
    assert json.dumps(source) == before
    assert all(secret not in json.dumps(result) for secret in ("FAKE_A", "FAKE_B", "FAKE_C"))


def test_sensitive_parent_overrides_child_allowlist():
    policy = frozenset({("credentials", "status")})
    assert sanitize_json({"credentials": {"status": "fake-secret"}}, allowed_paths=policy) == {
        "credentials": {"status": REDACTED}}


def test_bearer_token_in_approved_field_is_redacted():
    value = {"status": "Bearer abcdefghijklmnopqrstuvwxyz"}
    assert sanitize_json(value, allowed_paths=POLICY)["status"] == REDACTED


def test_unknown_field_is_not_released_and_json_is_well_formed():
    result = safe_json_response('{"status":"ok","extra":"hidden","metadata":{"version":2}}',
                                allowed_paths=POLICY)
    assert json.loads(result) == {
        "status": "ok", "extra": REDACTED, "metadata": {"version": 2}}


@pytest.mark.parametrize("payload", ["{bad", '{"value": NaN}', "[1,2] trailing", 42, None])
def test_invalid_json_fails_closed(payload):
    with pytest.raises(DisclosureBlocked):
        sanitize_json(payload, allowed_paths=POLICY)


def test_untrusted_or_missing_policy_fails_closed():
    with pytest.raises(DisclosureBlocked):
        sanitize_json({"status": "ok"}, allowed_paths=None)
    with pytest.raises(DisclosureBlocked):
        sanitize_json({"status": "ok"}, allowed_paths={("status",)})


def test_too_deep_and_too_large_fail_closed():
    value = {"x": 1}
    for _ in range(40):
        value = {"nest": value}
    with pytest.raises(DisclosureBlocked):
        sanitize_json(value, allowed_paths=POLICY)
    with pytest.raises(DisclosureBlocked):
        sanitize_json('{"x":"' + ("a" * 600000) + '"}', allowed_paths=POLICY)


def test_private_key_string_in_approved_field_is_redacted():
    value = {"status": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"}
    assert sanitize_json(value, allowed_paths=POLICY)["status"] == REDACTED


def test_empty_policy_redacts_every_leaf():
    assert sanitize_json({"okay": True, "arr": [1, "x"]},
                         allowed_paths=frozenset()) == {
        "okay": REDACTED, "arr": [REDACTED, REDACTED]}
