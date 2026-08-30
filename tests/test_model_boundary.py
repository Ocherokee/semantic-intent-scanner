"""
The deterministic / model-backed boundary (docs/model-boundary.md).

These tests are themselves deterministic and credential-free. They pin the two
structural facts the boundary rests on:

* exactly two modules may touch the Anthropic SDK;
* importing any scanner module needs no credential.
"""

import ast
import importlib
import pkgutil
from pathlib import Path

import scanner

SCANNER_DIR = Path(scanner.__file__).parent

# The only modules permitted to import/construct the Anthropic client.
_MODEL_MODULES = {"evaluator.py", "remote_judge.py"}


def _module_files():
    return sorted(p for p in SCANNER_DIR.glob("*.py") if p.name != "__init__.py")


def test_only_the_two_model_modules_touch_anthropic():
    offenders = {}
    for path in _module_files():
        source = path.read_text("utf-8")
        tree = ast.parse(source, filename=str(path))
        imports_anthropic = any(
            (isinstance(node, ast.Import) and any(a.name == "anthropic" or a.name.startswith("anthropic.")
                                                  for a in node.names))
            or (isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "anthropic")
            for node in ast.walk(tree)
        )
        mentions_client = "anthropic.Anthropic" in source
        if (imports_anthropic or mentions_client) and path.name not in _MODEL_MODULES:
            offenders[path.name] = {"import": imports_anthropic, "client": mentions_client}
    assert not offenders, (
        f"only {sorted(_MODEL_MODULES)} may touch the Anthropic SDK; "
        f"these also do: {offenders}"
    )


def test_importing_every_scanner_module_needs_no_credential(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    for mod in pkgutil.iter_modules([str(SCANNER_DIR)]):
        importlib.import_module(f"scanner.{mod.name}")
