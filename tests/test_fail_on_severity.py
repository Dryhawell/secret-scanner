"""Fail-on-severity exit gate. No real secrets are used."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.interface import build_parser, resolve_fail_on_severity, run
from scanner.config_file import ConfigError, FileSettings, settings_from_mapping
from scanner.models import Severity


def test_fail_on_defaults_to_report_severity() -> None:
    namespace = build_parser().parse_args(["."])
    assert (
        resolve_fail_on_severity(namespace, FileSettings(), Severity.LOW)
        == Severity.LOW
    )
    namespace = build_parser().parse_args([".", "--fail-on-severity", "HIGH"])
    assert (
        resolve_fail_on_severity(namespace, FileSettings(), Severity.LOW)
        == Severity.HIGH
    )


def test_fail_on_high_keeps_contextual_visible_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--fail-on-severity", "HIGH", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Contextual Secret" in captured.out
    assert "Fail-on severity: HIGH" in captured.out
    assert "exiting 0" in captured.out


def test_fail_on_high_still_fails_on_aws(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "keys.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--fail-on-severity", "HIGH", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_fail_on_does_not_change_default_exit(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_config_fail_on_severity(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text('{"fail_on_severity": "HIGH"}\n', encoding="utf-8")
    assert (
        run(
            ["--no-color", "--config", str(config), str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )


def test_cli_fail_on_overrides_config(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text('{"fail_on_severity": "CRITICAL"}\n', encoding="utf-8")
    assert (
        run(
            [
                "--no-color",
                "--config",
                str(config),
                "--fail-on-severity",
                "LOW",
                str(tmp_path),
            ],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_config_fail_on_invalid() -> None:
    with pytest.raises(ConfigError, match="fail_on_severity"):
        settings_from_mapping({"fail_on_severity": "EXTREME"}, base=Path("."))
