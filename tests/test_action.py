"""GitHub composite action tests. No real secrets are used."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.github_action import ActionConfigError, argv_from_env, main

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_action_yml_is_composite_and_masks_in_logs() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert ACTION.is_file()
    assert "using: composite" in text
    assert "cli/github_action.py" in text
    assert "github.action_path" in text
    assert 'run: python "$SECRET_SCANNER_ROOT/cli/github_action.py"' in text
    assert "SECRET_SCANNER_PATH: ${{ inputs.path }}" in text
    assert "--update-baseline" not in text
    assert "--dashboard" not in text
    assert "--install-hook" not in text
    assert "--staged" not in text
    assert "0.0.0.0" not in text
    assert "pull_request_target" not in text
    assert "actions/setup-python" in text


def test_action_run_line_does_not_interpolate_path_into_shell() -> None:
    text = ACTION.read_text(encoding="utf-8")
    run_line = next(
        line for line in text.splitlines() if line.strip().startswith("run:")
    )
    assert "${{ inputs.path }}" not in run_line
    assert "${{ inputs.severity }}" not in run_line
    assert "${{ inputs.include-hidden }}" not in run_line


def test_product_ci_uses_local_action() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "uses: ./" in text
    assert "include-hidden:" in text
    assert "python -m pytest" in text
    assert "persist-credentials: false" in text
    assert "contents: read" in text
    assert "--update-baseline" not in text


def test_argv_always_disables_color_and_never_adds_git_flags() -> None:
    argv = argv_from_env({"SECRET_SCANNER_PATH": ".", "SECRET_SCANNER_INCLUDE_HIDDEN": "true"})
    assert argv[0] == "--no-color"
    assert "--include-hidden" in argv
    assert "--severity" in argv
    assert "." in argv
    for banned in (
        "--update-baseline",
        "--dashboard",
        "--install-hook",
        "--staged",
        "--changed",
        "--history",
        "--since",
        "--stdin",
    ):
        assert banned not in argv


def test_argv_rejects_flag_like_path() -> None:
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_PATH": "--staged"})
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_PATH": ""})
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_PATH": "src\n--update-baseline"})


def test_argv_rejects_unknown_severity_and_hidden() -> None:
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_SEVERITY": "EXTREME"})
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_INCLUDE_HIDDEN": "maybe"})


def test_action_clean_tree_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_INCLUDE_HIDDEN": "false",
            "SECRET_SCANNER_SEVERITY": "LOW",
        },
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_action_finding_exits_one_and_masks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    log_file = tmp_path / "scan.log"
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_INCLUDE_HIDDEN": "false",
        },
        reports_dir=tmp_path,
        log_file=log_file,
    )
    captured = capsys.readouterr()
    assert code == 1
    assert aws not in captured.out
    assert aws not in captured.err
    assert aws not in log_file.read_text(encoding="utf-8")


def test_action_invalid_path_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert main({"SECRET_SCANNER_PATH": "--help"}) == 2
    assert "CLI flag" in capsys.readouterr().err
