import hashlib
import json
from scanner.conditional_execution import (
    inspect_python, inspect_javascript, inspect_npm_manifest,
    unchanged_approved_artifact,
)

def test_date_triggered_credential_transmission_high():
    source = """
from datetime import datetime
if datetime.now().year >= 2031:
    credentials = load_credentials()
    requests.post(endpoint, json=credentials)
"""
    assert any(f.concern == "high" and f.rule == "CE-05" for f in inspect_python(source))

def test_debugger_suppresses_hidden_execution_elevated():
    source = """
if not debugger_present():
    subprocess.Popen(hidden_task)
"""
    assert any(f.concern == "elevated" for f in inspect_python(source))

def test_ordinary_scheduled_backup_informational():
    source = """
if datetime.now().hour == 2:
    backup_documents()
"""
    assert all(f.concern in ("informational", "review") for f in inspect_python(source))

def test_legitimate_timeout_retry_informational():
    source = """
while time.monotonic() < deadline:
    retry_connection()
"""
    assert all(f.concern in ("informational", "review") for f in inspect_python(source))

def test_delayed_npm_install_process_high():
    manifest = {"scripts":{"postinstall":"node -e 'setTimeout(() => require(\"child_process\").spawn(\"worker\", [], {detached:true}), 60000)'"}}
    assert any(f.concern == "high" for f in inspect_npm_manifest(json.dumps(manifest)))

def test_dynamic_execution_incomplete():
    source = "execute = eval(user_source)"
    assert any(f.concern == "incomplete" for f in inspect_python(source))

def test_unchanged_approved_artifact_no_new_finding():
    data = b"routine self-check"
    digest = hashlib.sha256(data).hexdigest()
    assert unchanged_approved_artifact(data, approved_sha256=digest,
                                       policy_version="1", approved_policy_version="1")
    assert not unchanged_approved_artifact(data+b"changed", approved_sha256=digest,
                                           policy_version="1", approved_policy_version="1")
    assert not unchanged_approved_artifact(data, approved_sha256=digest,
                                           policy_version="2", approved_policy_version="1")

def test_javascript_time_gate_signal():
    assert any(f.rule == "CE-01" for f in inspect_javascript(
        "if (Date.now() > threshold) { do_work(); }"))

def test_invalid_or_unsupported_inputs():
    import pytest
    with pytest.raises(ValueError):
        inspect_python("if:")
    with pytest.raises(ValueError):
        inspect_npm_manifest("{broken")
