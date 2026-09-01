"""Allowlist --only-pattern tests. No real secrets are used."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli.interface import run
from scanner.context import CONTEXTUAL_PATTERN_NAME


def test_only_pattern_keeps_aws_hides_contextual(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "mix.py").write_text(
        'token = "LocalDevTokenValue1"\n'
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = run(
        [
            "--no-color",
            "--only-pattern",
            "AWS Access Key ID",
            "--format",
            "json",
            "-o",
            "-",
            str(tmp_path),
        ],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    captured = capsys.readouterr()
    assert code == 1
    payload = json.loads(captured.out)
    names = {item["pattern_name"] for item in payload["findings"]}
    assert names == {"AWS Access Key ID"}
    assert CONTEXTUAL_PATTERN_NAME not in names


def test_only_pattern_is_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--only-pattern", "aws access key id", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )


def test_unknown_only_pattern_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--only-pattern", "Not A Real Rule", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
    assert "--list-patterns" in capsys.readouterr().err


def test_only_plus_skip_empty_set_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        [
            "--no-color",
            "--only-pattern",
            "AWS Access Key ID",
            "--skip-pattern",
            "AWS Access Key ID",
            str(tmp_path),
        ],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
    assert "all detection rules were skipped" in capsys.readouterr().err


def test_config_only_patterns(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text(
        '{"only_patterns": ["AWS Access Key ID"]}\n',
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--config", str(config), str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )
