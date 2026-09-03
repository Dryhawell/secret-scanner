"""GitHub composite action tests. No real secrets are used."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.github_action import ActionConfigError, argv_from_env, main
from scanner.file_handler import MIB

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
    assert "SECRET_SCANNER_SEVERITY: ${{ inputs.severity }}" in text
    assert "SECRET_SCANNER_FAIL_ON_SEVERITY: ${{ inputs.fail-on-severity }}" in text
    assert "SECRET_SCANNER_MAX_FILE_SIZE: ${{ inputs.max-file-size }}" in text
    assert "SECRET_SCANNER_MIN_CONFIDENCE: ${{ inputs.min-confidence }}" in text
    assert "SECRET_SCANNER_QUIET: ${{ inputs.quiet }}" in text
    assert "SECRET_SCANNER_SARIF: ${{ inputs.sarif }}" in text
    assert "SECRET_SCANNER_SARIF_FILE: ${{ inputs.sarif-file }}" in text
    assert "github/codeql-action/upload-sarif@v3" in text
    assert "always()" in text
    assert "permissions:" not in text
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
    assert "${{ inputs.fail-on-severity }}" not in run_line
    assert "${{ inputs.max-file-size }}" not in run_line
    assert "${{ inputs.min-confidence }}" not in run_line
    assert "${{ inputs.include-hidden }}" not in run_line
    assert "${{ inputs.quiet }}" not in run_line
    assert "${{ inputs.sarif }}" not in run_line
    assert "${{ inputs.sarif-file }}" not in run_line


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


def test_argv_quiet_is_opt_in() -> None:
    argv = argv_from_env({"SECRET_SCANNER_PATH": ".", "SECRET_SCANNER_QUIET": "true"})
    assert "--quiet" in argv
    assert "--quiet" not in argv_from_env({"SECRET_SCANNER_PATH": "."})


def test_argv_sarif_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SARIF": "true",
        }
    )
    assert argv[argv.index("--sarif-file") + 1] == "secret-scanner.sarif"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--sarif-file" not in without


def test_argv_sarif_custom_file() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SARIF": "true",
            "SECRET_SCANNER_SARIF_FILE": "reports/scan.sarif",
        }
    )
    assert argv[argv.index("--sarif-file") + 1] == "reports/scan.sarif"


def test_argv_rejects_unsafe_sarif_file() -> None:
    with pytest.raises(ActionConfigError):
        argv_from_env(
            {
                "SECRET_SCANNER_SARIF": "true",
                "SECRET_SCANNER_SARIF_FILE": "../out.sarif",
            }
        )
    with pytest.raises(ActionConfigError):
        argv_from_env(
            {
                "SECRET_SCANNER_SARIF": "true",
                "SECRET_SCANNER_SARIF_FILE": "/tmp/out.sarif",
            }
        )
    with pytest.raises(ActionConfigError):
        argv_from_env(
            {
                "SECRET_SCANNER_SARIF": "true",
                "SECRET_SCANNER_SARIF_FILE": "out.json",
            }
        )
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_SARIF": "maybe"})


def test_argv_rejects_unknown_quiet() -> None:
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_QUIET": "maybe"})


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


def test_argv_fail_on_severity_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FAIL_ON_SEVERITY": "HIGH",
        }
    )
    assert argv[argv.index("--fail-on-severity") + 1] == "HIGH"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--fail-on-severity" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FAIL_ON_SEVERITY": "",
        }
    )
    assert "--fail-on-severity" not in empty


def test_argv_rejects_unknown_fail_on_severity() -> None:
    with pytest.raises(ActionConfigError, match="fail-on-severity"):
        argv_from_env({"SECRET_SCANNER_FAIL_ON_SEVERITY": "EXTREME"})


def test_argv_max_file_size_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MAX_FILE_SIZE": "10",
        }
    )
    assert argv[argv.index("--max-file-size") + 1] == "10"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--max-file-size" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MAX_FILE_SIZE": "",
        }
    )
    assert "--max-file-size" not in empty
    unlimited = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MAX_FILE_SIZE": "0",
        }
    )
    assert unlimited[unlimited.index("--max-file-size") + 1] == "0"


def test_argv_rejects_invalid_max_file_size() -> None:
    with pytest.raises(ActionConfigError, match="max-file-size"):
        argv_from_env({"SECRET_SCANNER_MAX_FILE_SIZE": "abc"})
    with pytest.raises(ActionConfigError, match="max-file-size"):
        argv_from_env({"SECRET_SCANNER_MAX_FILE_SIZE": "-1"})
    with pytest.raises(ActionConfigError, match="max-file-size"):
        argv_from_env({"SECRET_SCANNER_MAX_FILE_SIZE": "1025"})
    with pytest.raises(ActionConfigError, match="max-file-size"):
        argv_from_env({"SECRET_SCANNER_MAX_FILE_SIZE": "10\n2"})
    assert main({"SECRET_SCANNER_MAX_FILE_SIZE": "abc"}) == 2


def test_action_max_file_size_skips_oversized(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    aws = "AKIA" + "ABCDEFGHIJ012345"
    payload = f"AWS_ACCESS_KEY_ID = '{aws}'\n" + ("x" * (2 * MIB))
    (src / "dump.py").write_text(payload, encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(src),
            "SECRET_SCANNER_MAX_FILE_SIZE": "1",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_action_max_file_size_zero_scans_large_file(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    aws = "AKIA" + "ABCDEFGHIJ012345"
    payload = f"AWS_ACCESS_KEY_ID = '{aws}'\n" + ("x" * (2 * MIB))
    (src / "dump.py").write_text(payload, encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(src),
            "SECRET_SCANNER_MAX_FILE_SIZE": "0",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 1


def test_argv_min_confidence_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MIN_CONFIDENCE": "80",
        }
    )
    assert argv[argv.index("--min-confidence") + 1] == "80"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--min-confidence" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MIN_CONFIDENCE": "",
        }
    )
    assert "--min-confidence" not in empty
    zero = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_MIN_CONFIDENCE": "0",
        }
    )
    assert zero[zero.index("--min-confidence") + 1] == "0"


def test_argv_rejects_invalid_min_confidence() -> None:
    with pytest.raises(ActionConfigError, match="min-confidence"):
        argv_from_env({"SECRET_SCANNER_MIN_CONFIDENCE": "abc"})
    with pytest.raises(ActionConfigError, match="min-confidence"):
        argv_from_env({"SECRET_SCANNER_MIN_CONFIDENCE": "-1"})
    with pytest.raises(ActionConfigError, match="min-confidence"):
        argv_from_env({"SECRET_SCANNER_MIN_CONFIDENCE": "100"})
    with pytest.raises(ActionConfigError, match="min-confidence"):
        argv_from_env({"SECRET_SCANNER_MIN_CONFIDENCE": "80\n1"})
    assert main({"SECRET_SCANNER_MIN_CONFIDENCE": "abc"}) == 2


def test_action_min_confidence_hides_contextual(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_MIN_CONFIDENCE": "80",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_action_min_confidence_still_fails_on_aws(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_MIN_CONFIDENCE": "80",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 1


def test_action_fail_on_high_exits_zero_on_contextual(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_FAIL_ON_SEVERITY": "HIGH",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


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
