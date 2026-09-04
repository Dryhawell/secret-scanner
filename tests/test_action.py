"""GitHub composite action tests. No real secrets are used."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from cli.github_action import ActionConfigError, argv_from_env, main
from scanner.config_file import MAX_SKIP_PATTERNS
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
    assert "SECRET_SCANNER_SKIP_PATTERN: ${{ inputs.skip-pattern }}" in text
    assert "SECRET_SCANNER_ONLY_PATTERN: ${{ inputs.only-pattern }}" in text
    assert "SECRET_SCANNER_GLOB: ${{ inputs.glob }}" in text
    assert "SECRET_SCANNER_SKIP_GLOB: ${{ inputs.skip-glob }}" in text
    assert "SECRET_SCANNER_EXCLUDE: ${{ inputs.exclude }}" in text
    assert "SECRET_SCANNER_JOBS: ${{ inputs.jobs }}" in text
    assert "SECRET_SCANNER_QUIET: ${{ inputs.quiet }}" in text
    assert "SECRET_SCANNER_VERBOSE: ${{ inputs.verbose }}" in text
    assert "SECRET_SCANNER_FORMAT: ${{ inputs.format }}" in text
    assert "SECRET_SCANNER_OUTPUT: ${{ inputs.output }}" in text
    assert "SECRET_SCANNER_CONFIG: ${{ inputs.config }}" in text
    assert "SECRET_SCANNER_IGNORE_FILE: ${{ inputs.ignore-file }}" in text
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
    assert "${{ inputs.skip-pattern }}" not in run_line
    assert "${{ inputs.only-pattern }}" not in run_line
    assert "${{ inputs.glob }}" not in run_line
    assert "${{ inputs.skip-glob }}" not in run_line
    assert "${{ inputs.exclude }}" not in run_line
    assert "${{ inputs.jobs }}" not in run_line
    assert "${{ inputs.include-hidden }}" not in run_line
    assert "${{ inputs.quiet }}" not in run_line
    assert "${{ inputs.verbose }}" not in run_line
    assert "${{ inputs.format }}" not in run_line
    assert "${{ inputs.output }}" not in run_line
    assert "${{ inputs.config }}" not in run_line
    assert "${{ inputs.ignore-file }}" not in run_line
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
        "--baseline",
    ):
        assert banned not in argv


def test_argv_quiet_is_opt_in() -> None:
    argv = argv_from_env({"SECRET_SCANNER_PATH": ".", "SECRET_SCANNER_QUIET": "true"})
    assert "--quiet" in argv
    assert "--quiet" not in argv_from_env({"SECRET_SCANNER_PATH": "."})


def test_argv_verbose_is_opt_in() -> None:
    argv = argv_from_env(
        {"SECRET_SCANNER_PATH": ".", "SECRET_SCANNER_VERBOSE": "true"}
    )
    assert "--verbose" in argv
    assert "--verbose" not in argv_from_env({"SECRET_SCANNER_PATH": "."})
    empty = argv_from_env(
        {"SECRET_SCANNER_PATH": ".", "SECRET_SCANNER_VERBOSE": "false"}
    )
    assert "--verbose" not in empty


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


def test_argv_format_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FORMAT": "json",
        }
    )
    assert argv[argv.index("--format") + 1] == "json"
    assert argv[argv.index("--output") + 1] == "secret-scanner.json"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--format" not in without
    assert "--output" not in without
    text = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FORMAT": "text",
        }
    )
    assert "--format" not in text
    assert "--output" not in text


def test_argv_format_custom_output() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FORMAT": "html",
            "SECRET_SCANNER_OUTPUT": "reports/scan.html",
        }
    )
    assert argv[argv.index("--format") + 1] == "html"
    assert argv[argv.index("--output") + 1] == "reports/scan.html"


def test_argv_rejects_output_without_format() -> None:
    with pytest.raises(ActionConfigError, match="output requires format"):
        argv_from_env({"SECRET_SCANNER_OUTPUT": "secret-scanner.json"})


def test_argv_rejects_invalid_format_and_output() -> None:
    with pytest.raises(ActionConfigError, match="format"):
        argv_from_env({"SECRET_SCANNER_FORMAT": "xml"})
    with pytest.raises(ActionConfigError, match="output"):
        argv_from_env(
            {
                "SECRET_SCANNER_FORMAT": "json",
                "SECRET_SCANNER_OUTPUT": "-",
            }
        )
    with pytest.raises(ActionConfigError, match="output"):
        argv_from_env(
            {
                "SECRET_SCANNER_FORMAT": "json",
                "SECRET_SCANNER_OUTPUT": "../out.json",
            }
        )
    with pytest.raises(ActionConfigError, match="output"):
        argv_from_env(
            {
                "SECRET_SCANNER_FORMAT": "json",
                "SECRET_SCANNER_OUTPUT": "out.html",
            }
        )
    assert main({"SECRET_SCANNER_FORMAT": "xml"}) == 2


def test_action_format_json_writes_masked_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_FORMAT": "json",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    report = tmp_path / "secret-scanner.json"
    text = report.read_text(encoding="utf-8")
    assert code == 1
    assert report.is_file()
    assert aws not in text
    assert "AWS Access Key ID" in text
    assert "masked_value" in text


def test_argv_config_and_ignore_file_are_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_CONFIG": "policy.json",
            "SECRET_SCANNER_IGNORE_FILE": "allow.txt",
        }
    )
    assert argv[argv.index("--config") + 1] == "policy.json"
    assert argv[argv.index("--ignore-file") + 1] == "allow.txt"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--config" not in without
    assert "--ignore-file" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_CONFIG": "",
            "SECRET_SCANNER_IGNORE_FILE": "",
        }
    )
    assert "--config" not in empty
    assert "--ignore-file" not in empty


def test_argv_rejects_unsafe_config_and_ignore_file() -> None:
    with pytest.raises(ActionConfigError, match="config"):
        argv_from_env({"SECRET_SCANNER_CONFIG": "../policy.json"})
    with pytest.raises(ActionConfigError, match="config"):
        argv_from_env({"SECRET_SCANNER_CONFIG": "policy.txt"})
    with pytest.raises(ActionConfigError, match="ignore-file"):
        argv_from_env({"SECRET_SCANNER_IGNORE_FILE": "--update-baseline"})
    yaml_ok = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_CONFIG": "policy.yml",
        }
    )
    assert yaml_ok[yaml_ok.index("--config") + 1] == "policy.yml"


def test_action_config_skips_contextual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    (tmp_path / "policy.json").write_text(
        '{"skip_patterns": ["Contextual Secret"]}\n',
        encoding="utf-8",
    )
    skipped = main(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_CONFIG": "policy.json",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert skipped == 0
    hit = main(
        {
            "SECRET_SCANNER_PATH": ".",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert hit == 1


def test_action_ignore_file_allows_leaky_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "leaky.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "allow.txt").write_text("leaky.py\n", encoding="utf-8")
    skipped = main(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_IGNORE_FILE": "allow.txt",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert skipped == 0
    hit = main(
        {
            "SECRET_SCANNER_PATH": ".",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert hit == 1


def test_argv_rejects_unknown_quiet() -> None:
    with pytest.raises(ActionConfigError):
        argv_from_env({"SECRET_SCANNER_QUIET": "maybe"})


def test_argv_rejects_unknown_verbose() -> None:
    with pytest.raises(ActionConfigError, match="verbose"):
        argv_from_env({"SECRET_SCANNER_VERBOSE": "maybe"})


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


def test_argv_skip_pattern_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret",
        }
    )
    assert argv[argv.index("--skip-pattern") + 1] == "Contextual Secret"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--skip-pattern" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SKIP_PATTERN": "",
        }
    )
    assert "--skip-pattern" not in empty


def test_argv_skip_pattern_splits_comma_and_newline() -> None:
    comma = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret, Generic Password",
        }
    )
    names = [
        comma[i + 1]
        for i, item in enumerate(comma)
        if item == "--skip-pattern"
    ]
    assert names == ["Contextual Secret", "Generic Password"]
    newline = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret\nGeneric Password\n",
        }
    )
    names = [
        newline[i + 1]
        for i, item in enumerate(newline)
        if item == "--skip-pattern"
    ]
    assert names == ["Contextual Secret", "Generic Password"]


def test_argv_rejects_flag_like_skip_pattern() -> None:
    with pytest.raises(ActionConfigError, match="skip-pattern"):
        argv_from_env({"SECRET_SCANNER_SKIP_PATTERN": "--update-baseline"})
    with pytest.raises(ActionConfigError, match="skip-pattern"):
        argv_from_env(
            {"SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret,--staged"}
        )
    too_many = ", ".join(["AWS Access Key ID"] * (MAX_SKIP_PATTERNS + 1))
    with pytest.raises(ActionConfigError, match="skip-pattern"):
        argv_from_env({"SECRET_SCANNER_SKIP_PATTERN": too_many})


def test_action_skip_pattern_hides_contextual(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_action_skip_pattern_still_fails_on_aws(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_SKIP_PATTERN": "Contextual Secret",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 1


def test_action_unknown_skip_pattern_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_SKIP_PATTERN": "Not A Real Rule",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "--list-patterns" in capsys.readouterr().err


def test_argv_only_pattern_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_ONLY_PATTERN": "AWS Access Key ID",
        }
    )
    assert argv[argv.index("--only-pattern") + 1] == "AWS Access Key ID"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--only-pattern" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_ONLY_PATTERN": "",
        }
    )
    assert "--only-pattern" not in empty


def test_argv_only_pattern_splits_comma_and_newline() -> None:
    comma = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_ONLY_PATTERN": "AWS Access Key ID, GitHub Token",
        }
    )
    names = [
        comma[i + 1]
        for i, item in enumerate(comma)
        if item == "--only-pattern"
    ]
    assert names == ["AWS Access Key ID", "GitHub Token"]
    newline = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_ONLY_PATTERN": "AWS Access Key ID\nGitHub Token\n",
        }
    )
    names = [
        newline[i + 1]
        for i, item in enumerate(newline)
        if item == "--only-pattern"
    ]
    assert names == ["AWS Access Key ID", "GitHub Token"]


def test_argv_rejects_flag_like_only_pattern() -> None:
    with pytest.raises(ActionConfigError, match="only-pattern"):
        argv_from_env({"SECRET_SCANNER_ONLY_PATTERN": "--update-baseline"})


def test_action_only_pattern_keeps_aws_hides_contextual(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "mix.py").write_text(
        'token = "LocalDevTokenValue1"\n'
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_ONLY_PATTERN": "AWS Access Key ID",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 1


def test_action_only_pattern_hides_aws_when_not_allowlisted(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "keys.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_ONLY_PATTERN": "GitHub Token",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_action_only_plus_skip_empty_set_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_ONLY_PATTERN": "AWS Access Key ID",
            "SECRET_SCANNER_SKIP_PATTERN": "AWS Access Key ID",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "all detection rules were skipped" in capsys.readouterr().err


def test_action_unknown_only_pattern_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_ONLY_PATTERN": "Not A Real Rule",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "--list-patterns" in capsys.readouterr().err


def test_argv_glob_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_GLOB": "*.env",
        }
    )
    assert argv[argv.index("--glob") + 1] == "*.env"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--glob" not in without
    assert "--skip-glob" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_GLOB": "",
            "SECRET_SCANNER_SKIP_GLOB": "",
        }
    )
    assert "--glob" not in empty
    assert "--skip-glob" not in empty


def test_argv_glob_splits_comma_and_newline() -> None:
    comma = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_GLOB": "*.env, *.py",
        }
    )
    patterns = [comma[i + 1] for i, item in enumerate(comma) if item == "--glob"]
    assert patterns == ["*.env", "*.py"]
    newline = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_SKIP_GLOB": "*.md\n*.txt\n",
        }
    )
    patterns = [
        newline[i + 1] for i, item in enumerate(newline) if item == "--skip-glob"
    ]
    assert patterns == ["*.md", "*.txt"]


def test_argv_rejects_flag_like_glob() -> None:
    with pytest.raises(ActionConfigError, match="glob"):
        argv_from_env({"SECRET_SCANNER_GLOB": "--staged"})
    with pytest.raises(ActionConfigError, match="skip-glob"):
        argv_from_env({"SECRET_SCANNER_SKIP_GLOB": "--update-baseline"})


def test_action_glob_hides_non_matching_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("EXAMPLE=placeholder\n", encoding="utf-8")
    missed = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_GLOB": "*.env",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert missed == 0
    hit = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_GLOB": "*.py",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert hit == 1


def test_action_skip_glob_skips_leaky_file(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_SKIP_GLOB": "*.py",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_argv_exclude_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_EXCLUDE": "vendor",
        }
    )
    assert argv[argv.index("--exclude") + 1] == "vendor"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--exclude" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_EXCLUDE": "",
        }
    )
    assert "--exclude" not in empty


def test_argv_exclude_splits_comma_and_newline() -> None:
    comma = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_EXCLUDE": "vendor, dist",
        }
    )
    names = [comma[i + 1] for i, item in enumerate(comma) if item == "--exclude"]
    assert names == ["vendor", "dist"]
    newline = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_EXCLUDE": "vendor\ndist\n",
        }
    )
    names = [
        newline[i + 1] for i, item in enumerate(newline) if item == "--exclude"
    ]
    assert names == ["vendor", "dist"]


def test_argv_rejects_flag_like_exclude() -> None:
    with pytest.raises(ActionConfigError, match="exclude"):
        argv_from_env({"SECRET_SCANNER_EXCLUDE": "--update-baseline"})
    with pytest.raises(ActionConfigError, match="exclude"):
        argv_from_env({"SECRET_SCANNER_EXCLUDE": "vendor/lib"})
    with pytest.raises(ActionConfigError, match="exclude"):
        argv_from_env({"SECRET_SCANNER_EXCLUDE": r"vendor\lib"})
    too_many = ", ".join(["vendor"] * (MAX_SKIP_PATTERNS + 1))
    with pytest.raises(ActionConfigError, match="exclude"):
        argv_from_env({"SECRET_SCANNER_EXCLUDE": too_many})


def test_action_exclude_skips_leaky_dir(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    vendor = tmp_path / "Vendor"
    vendor.mkdir()
    (vendor / "keys.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    skipped = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_EXCLUDE": "vendor",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert skipped == 0
    hit = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert hit == 1


def test_action_exclude_still_finds_outside_dir(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "keys.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_EXCLUDE": "vendor",
        },
        reports_dir=tmp_path / "reports",
        log_file=tmp_path / "scan.log",
    )
    assert code == 1


def test_argv_jobs_is_opt_in() -> None:
    argv = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_JOBS": "4",
        }
    )
    assert argv[argv.index("--jobs") + 1] == "4"
    without = argv_from_env({"SECRET_SCANNER_PATH": "."})
    assert "--jobs" not in without
    empty = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_JOBS": "",
        }
    )
    assert "--jobs" not in empty
    auto = argv_from_env(
        {
            "SECRET_SCANNER_PATH": ".",
            "SECRET_SCANNER_JOBS": "0",
        }
    )
    assert auto[auto.index("--jobs") + 1] == "0"


def test_argv_rejects_invalid_jobs() -> None:
    with pytest.raises(ActionConfigError, match="jobs"):
        argv_from_env({"SECRET_SCANNER_JOBS": "abc"})
    with pytest.raises(ActionConfigError, match="jobs"):
        argv_from_env({"SECRET_SCANNER_JOBS": "-1"})
    with pytest.raises(ActionConfigError, match="jobs"):
        argv_from_env({"SECRET_SCANNER_JOBS": "33"})
    assert main({"SECRET_SCANNER_JOBS": "abc"}) == 2


def test_action_jobs_still_finds_aws(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "a.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_JOBS": "4",
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


def test_action_verbose_logs_path_not_secret(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    verbose_log = tmp_path / "verbose.log"
    code = main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
            "SECRET_SCANNER_VERBOSE": "true",
        },
        reports_dir=tmp_path / "reports",
        log_file=verbose_log,
    )
    for handler in logging.getLogger("secret_scanner").handlers:
        handler.flush()
    text = verbose_log.read_text(encoding="utf-8")
    assert code == 1
    assert "Scanning file" in text
    assert aws not in text
    quiet_log = tmp_path / "info.log"
    main(
        {
            "SECRET_SCANNER_PATH": str(tmp_path),
        },
        reports_dir=tmp_path / "reports",
        log_file=quiet_log,
    )
    for handler in logging.getLogger("secret_scanner").handlers:
        handler.flush()
    assert "Scanning file" not in quiet_log.read_text(encoding="utf-8")


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
