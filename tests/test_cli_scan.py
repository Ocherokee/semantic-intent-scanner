"""Focused tests for local ``semantic-intent scan`` CLI behavior."""

import argparse

import scanner.cli as cli


def _args(path, *, api_key=None, directory=False):
    return argparse.Namespace(
        path=str(path), dir=directory, json=False, no_color=True, api_key=api_key,
    )


def test_file_scan_without_api_key_is_handled_operational_failure(
    tmp_path, monkeypatch, capsys,
):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# Example skill\n", encoding="utf-8")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        cli, "evaluate_skill",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("model called")),
    )

    code = cli.cmd_scan(_args(skill))

    captured = capsys.readouterr()
    assert code == 3
    assert captured.out == ""
    assert captured.err == (
        "Error: Anthropic API key required; use --api-key or set "
        "ANTHROPIC_API_KEY\n"
    )
    assert "Traceback" not in captured.err


def test_directory_scan_without_api_key_is_handled_when_candidate_found(
    tmp_path, monkeypatch, capsys,
):
    (tmp_path / "README.md").write_text("# Example skill\n", encoding="utf-8")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        cli, "evaluate_skill",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("model called")),
    )

    code = cli.cmd_scan(_args(tmp_path))

    captured = capsys.readouterr()
    assert code == 3
    assert captured.out == ""
    assert captured.err.endswith(
        "Error: Anthropic API key required; use --api-key or set "
        "ANTHROPIC_API_KEY\n"
    )
    assert "Traceback" not in captured.err


def test_directory_scan_without_candidate_stays_credential_free(
    tmp_path, monkeypatch,
):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        cli, "evaluate_skill",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("model called")),
    )
    monkeypatch.setattr(cli, "render_directory_report", lambda *args, **kwargs: "report")

    assert cli.cmd_scan(_args(tmp_path)) == 0


def test_file_scan_with_explicit_api_key_still_runs_evaluator(
    tmp_path, monkeypatch, capsys,
):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# Example skill\n", encoding="utf-8")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    calls = []
    monkeypatch.setattr(
        cli, "evaluate_skill",
        lambda text, api_key: calls.append((text, api_key)) or {"overall_risk": "low"},
    )
    monkeypatch.setattr(cli, "render_terminal_report", lambda *args, **kwargs: "report")

    code = cli.cmd_scan(_args(skill, api_key="explicit-key"))

    captured = capsys.readouterr()
    assert code == 0
    assert calls == [("# Example skill\n", "explicit-key")]
    assert captured.out == "report\n"


def test_file_scan_with_environment_api_key_still_runs_evaluator(
    tmp_path, monkeypatch,
):
    skill = tmp_path / "SKILL.md"
    skill.write_text("# Example skill\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "environment-key")
    calls = []
    monkeypatch.setattr(
        cli, "evaluate_skill",
        lambda text, api_key: calls.append((text, api_key)) or {"overall_risk": "low"},
    )
    monkeypatch.setattr(cli, "render_terminal_report", lambda *args, **kwargs: "report")

    assert cli.cmd_scan(_args(skill)) == 0
    assert calls == [("# Example skill\n", None)]
