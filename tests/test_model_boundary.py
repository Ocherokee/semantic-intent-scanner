"""
The deterministic / model-backed boundary (docs/model-boundary.md).

These tests are themselves deterministic and credential-free. They pin the
structural facts the boundary rests on:

* exactly two modules may touch the Anthropic SDK;
* the model identifiers are single-sourced in scanner.model_config;
* importing the package needs no credential;
* the judge fails closed (no key -> unavailable, deterministic result intact).
"""

import ast
import importlib
import os
import pkgutil
from pathlib import Path

import pytest

import scanner
from scanner.model_config import JUDGE_MODEL, SEMANTIC_EVALUATOR_MODEL

SCANNER_DIR = Path(scanner.__file__).parent

# The only modules permitted to import/construct the Anthropic client.
_MODEL_MODULES = {"evaluator.py", "remote_judge.py"}


def _module_files():
    return sorted(p for p in SCANNER_DIR.glob("*.py") if p.name != "__init__.py")


def test_only_the_two_model_modules_touch_anthropic():
    offenders = {}
    for path in _module_files():
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        imports_anthropic = any(
            (isinstance(node, ast.Import) and any(a.name == "anthropic" or a.name.startswith("anthropic.")
                                                  for a in node.names))
            or (isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "anthropic")
            for node in ast.walk(tree)
        )
        mentions_client = "anthropic.Anthropic" in path.read_text("utf-8")
        if (imports_anthropic or mentions_client) and path.name not in _MODEL_MODULES:
            offenders[path.name] = {"import": imports_anthropic, "client": mentions_client}
    assert not offenders, (
        f"only {sorted(_MODEL_MODULES)} may touch the Anthropic SDK; "
        f"these also do: {offenders}"
    )


def test_model_ids_are_single_sourced():
    assert isinstance(SEMANTIC_EVALUATOR_MODEL, str) and SEMANTIC_EVALUATOR_MODEL
    assert isinstance(JUDGE_MODEL, str) and JUDGE_MODEL

    from scanner import remote_judge

    assert remote_judge.DEFAULT_JUDGE_MODEL is JUDGE_MODEL

    evaluator_src = (SCANNER_DIR / "evaluator.py").read_text("utf-8")
    assert "SEMANTIC_EVALUATOR_MODEL" in evaluator_src
    assert 'model="claude' not in evaluator_src  # no inline literal
    judge_src = (SCANNER_DIR / "remote_judge.py").read_text("utf-8")
    assert 'model="claude' not in judge_src


def test_importing_every_scanner_module_needs_no_credential(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    for mod in pkgutil.iter_modules([str(SCANNER_DIR)]):
        importlib.import_module(f"scanner.{mod.name}")
    # a re-import of the package itself, too
    importlib.reload(importlib.import_module("scanner.model_config"))


def test_judge_without_credential_fails_closed(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from scanner.remote_audit import RemoteDocument
    from scanner.remote_judge import judge_document

    doc = RemoteDocument(
        origin_url="https://example.com/llms.txt", final_url="https://example.com/llms.txt",
        body="hello", sha256="0" * 64, fetched_at="2026-01-01T00:00:00Z",
    )
    result = judge_document(doc, [])
    assert result.status == "unavailable:no_api_key"
    assert result.findings == []
    assert result.calls == 0


def test_deterministic_lanes_do_not_require_a_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from scanner.mcp_adapter import audit_mcp_tools
    from scanner.registry import RegistryClient

    mock = Path(__file__).parent / "fixtures" / "llms_txt" / "mock_registry.json"
    f = tmp_path / "tools.json"
    f.write_text('{"tools": [{"name": "t", "description": "harmless"}]}', encoding="utf-8")
    r = audit_mcp_tools(str(f), registry=RegistryClient.from_fixture(mock))
    assert r["overall_risk"] == "low"
    assert "judge_status" not in r  # no judge attempted
