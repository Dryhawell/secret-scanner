"""Pattern catalog and skip-pattern tests. No real secrets are used."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.interface import run
from scanner.context import CONTEXTUAL_PATTERN_NAME
from scanner.detector import Detector
from scanner.patterns import PatternEngine


def test_list_patterns_prints_names_not_regexes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = run(["--list-patterns", "--no-color"])
    captured = capsys.readouterr()
    assert code == 0
    assert "AWS Access Key ID" in captured.out
    assert CONTEXTUAL_PATTERN_NAME in captured.out
    assert "format-locked" in captured.out
    assert "entropy-gated" in captured.out
    assert "AKIA[0-9" not in captured.out
    assert r"(?<!" not in captured.out


def test_list_patterns_does_not_need_a_target(tmp_path: Path) -> None:
    missing = tmp_path / "missing-dir"
    assert run(["--list-patterns", "--no-color", str(missing)]) == 0


def test_skip_contextual_keeps_aws(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--skip-pattern", CONTEXTUAL_PATTERN_NAME, str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "keys.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--skip-pattern", CONTEXTUAL_PATTERN_NAME, str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_skip_pattern_is_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--skip-pattern", "contextual secret", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_unknown_skip_pattern_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--skip-pattern", "Not A Real Rule", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
    assert "--list-patterns" in capsys.readouterr().err


def test_config_skip_patterns(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text(
        '{"skip_patterns": ["Contextual Secret"]}\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--config", str(config), str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_list_patterns_prints_under_quiet(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = run(["--list-patterns", "--quiet", "--no-color"])
    captured = capsys.readouterr()
    assert code == 0
    assert "AWS Access Key ID" in captured.out
    assert CONTEXTUAL_PATTERN_NAME in captured.out


def test_skip_all_rules_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    argv: list[str] = ["--no-color"]
    for pattern in PatternEngine().patterns:
        argv.extend(["--skip-pattern", pattern.name])
    argv.extend(["--skip-pattern", CONTEXTUAL_PATTERN_NAME, str(tmp_path)])
    code = run(
        argv,
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
    assert "all detection rules were skipped" in capsys.readouterr().err


def test_detector_skip_patterns_unit() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    detector = Detector(skip_patterns={"AWS Access Key ID"})
    findings, _, _ = detector.scan_line(
        f"AWS_ACCESS_KEY_ID = '{aws}'",
        Path("a.py"),
        1,
    )
    names = {item.pattern_name for item in findings}
    assert "AWS Access Key ID" not in names
    assert CONTEXTUAL_PATTERN_NAME in names
