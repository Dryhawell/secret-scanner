"""Quiet CLI tests. No real secrets are used."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli.interface import run
from scanner.config_file import settings_from_mapping


def test_quiet_finding_exits_one_without_text_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--quiet", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert aws not in captured.err
    assert "Potential secrets found" not in captured.out


def test_quiet_clean_exits_zero_without_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "-q", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    assert "Scan completed" not in captured.out


def test_quiet_still_prints_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = run(
        ["--no-color", "--quiet", str(tmp_path / "missing")],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
    assert "does not exist" in capsys.readouterr().err


def test_quiet_json_file_omits_report_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "out.json"
    code = run(
        [
            "--no-color",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(report),
            str(tmp_path),
        ],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Report written" not in captured.out
    assert report.is_file()
    json.loads(report.read_text(encoding="utf-8"))


def test_quiet_json_stdout_still_emits_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--quiet", "--format", "json", "-o", "-", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["findings_count"] == 0


def test_quiet_and_dashboard_exit_two(tmp_path: Path) -> None:
    assert (
        run(
            ["--dashboard", "--quiet", "--no-browser", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 2
    )


def test_config_quiet_key() -> None:
    settings = settings_from_mapping({"quiet": True}, base=Path("."))
    assert settings.quiet is True
