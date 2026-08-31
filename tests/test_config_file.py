"""Project config file tests. No real secrets are used."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from cli.interface import run
from scanner.config_file import (
    ConfigError,
    load_config_file,
    parse_json_text,
    parse_yaml_text,
    settings_from_mapping,
)
from scanner.file_handler import ScanConfig, iter_scan_files, should_scan_file


def test_parse_json_object() -> None:
    data = parse_json_text('{"severity": "HIGH", "exclude": ["dist"]}')
    settings = settings_from_mapping(data, base=Path("."))
    assert settings.severity == "HIGH"
    assert settings.exclude == ("dist",)


def test_parse_yaml_subset_with_list_and_comment() -> None:
    data = parse_yaml_text(
        dedent(
            """
            # project defaults
            severity: HIGH
            include_hidden: true
            exclude:
              - dist
              - build
            """
        )
    )
    settings = settings_from_mapping(data, base=Path("."))
    assert settings.severity == "HIGH"
    assert settings.include_hidden is True
    assert settings.exclude == ("dist", "build")


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown config key"):
        settings_from_mapping({"nope": 1}, base=Path("."))


def test_empty_patterns_list_is_allowed() -> None:
    settings = settings_from_mapping({"patterns": []}, base=Path("."))
    assert settings.patterns == ()


def test_invalid_severity_is_rejected() -> None:
    with pytest.raises(ConfigError, match="Invalid severity"):
        settings_from_mapping({"severity": "URGENT"}, base=Path("."))


def test_skips_default_config_filenames(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / ".secret-scanner.json").write_text(
        '{"severity": "LOW"}\n',
        encoding="utf-8",
    )
    found = list(iter_scan_files(tmp_path, ScanConfig()))
    assert {path.name for path in found} == {"app.py"}
    assert not should_scan_file(tmp_path / ".secret-scanner.json", ScanConfig())


def test_cli_config_severity_hides_medium(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text('{"severity": "CRITICAL"}\n', encoding="utf-8")
    code = run(
        ["--no-color", "--config", str(config), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_cli_flag_overrides_config_severity(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / ".secret-scanner.json"
    config.write_text('{"severity": "CRITICAL"}\n', encoding="utf-8")
    code = run(
        ["--no-color", "--severity", "MEDIUM", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1


def test_cli_yaml_exclude(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    vendor = tmp_path / "dist"
    vendor.mkdir()
    (vendor / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / ".secret-scanner.yml"
    config.write_text("exclude:\n  - dist\n", encoding="utf-8")
    code = run(
        ["--no-color", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_missing_config_flag_exits_two(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--config", str(tmp_path / "missing.json"), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_invalid_json_config_exits_two(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / "broken.json"
    config.write_text("{not json\n", encoding="utf-8")
    code = run(
        ["--no-color", "--config", str(config), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_load_config_resolves_relative_ignore_file(tmp_path: Path) -> None:
    ignore = tmp_path / ".secret-scanner-ignore"
    ignore.write_text("tests/\n", encoding="utf-8")
    config = tmp_path / ".secret-scanner.json"
    config.write_text('{"ignore_file": ".secret-scanner-ignore"}\n', encoding="utf-8")
    settings = load_config_file(config)
    assert settings.ignore_file == ignore
