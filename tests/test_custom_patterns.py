"""Custom config-pattern tests. Values are fake placeholders, never real secrets."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from cli.interface import run
from scanner.config_file import ConfigError, parse_yaml_text, settings_from_mapping
from scanner.patterns import default_patterns, merged_engine


def test_yaml_pattern_object_list() -> None:
    data = parse_yaml_text(
        dedent(
            """
            patterns:
              - name: Internal Token
                regex: intok_[A-Za-z0-9]{16}
                severity: HIGH
                description: Company-internal token prefix
            """
        )
    )
    settings = settings_from_mapping(data, base=Path("."))
    assert len(settings.patterns) == 1
    assert settings.patterns[0].name == "Internal Token"
    assert settings.patterns[0].severity.value == "HIGH"


def test_custom_pattern_detects_fake_token(tmp_path: Path) -> None:
    token = "intok_" + "ABCDEFGH12345678"
    (tmp_path / "app.py").write_text(f"value = '{token}'\n", encoding="utf-8")
    config = tmp_path / ".secret-scanner.json"
    config.write_text(
        '{"patterns": [{"name": "Internal Token", '
        '"regex": "intok_[A-Za-z0-9]{16}", "severity": "HIGH"}]}\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1


def test_custom_pattern_does_not_remove_builtins() -> None:
    extra = settings_from_mapping(
        {
            "patterns": [
                {
                    "name": "Internal Token",
                    "regex": r"intok_[A-Za-z0-9]{16}",
                    "severity": "HIGH",
                }
            ]
        },
        base=Path("."),
    ).patterns
    engine = merged_engine(extra)
    names = {pattern.name for pattern in engine.patterns}
    assert "Internal Token" in names
    assert {item.name for item in default_patterns()} <= names
    aws = "AKIA" + "ABCDEFGHIJ012345"
    assert any(
        item.pattern_name == "AWS Access Key ID"
        for item in engine.find_in_text(aws)
    )


def test_builtin_name_cannot_be_overridden() -> None:
    with pytest.raises(ConfigError, match="already exists"):
        settings_from_mapping(
            {
                "patterns": [
                    {
                        "name": "AWS Access Key ID",
                        "regex": r"AKIA[0-9A-Z]{16}",
                        "severity": "LOW",
                    }
                ]
            },
            base=Path("."),
        )


def test_invalid_regex_is_rejected() -> None:
    with pytest.raises(ConfigError, match="Invalid regex"):
        settings_from_mapping(
            {
                "patterns": [
                    {"name": "Broken", "regex": "[", "severity": "HIGH"}
                ]
            },
            base=Path("."),
        )


def test_empty_matching_regex_is_rejected() -> None:
    with pytest.raises(ConfigError, match="empty string"):
        settings_from_mapping(
            {
                "patterns": [
                    {"name": "Too Broad", "regex": ".*", "severity": "HIGH"}
                ]
            },
            base=Path("."),
        )


def test_invalid_custom_pattern_exits_two(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / "scan.json"
    config.write_text(
        '{"patterns": [{"name": "Broken", "regex": "[", "severity": "HIGH"}]}\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--config", str(config), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_ignore_rule_can_drop_custom_pattern(tmp_path: Path) -> None:
    token = "intok_" + "ABCDEFGH12345678"
    (tmp_path / "app.py").write_text(f"value = '{token}'\n", encoding="utf-8")
    (tmp_path / ".secret-scanner-ignore").write_text(
        "app.py | Internal Token\n",
        encoding="utf-8",
    )
    config = tmp_path / ".secret-scanner.json"
    config.write_text(
        '{"patterns": [{"name": "Internal Token", '
        '"regex": "intok_[A-Za-z0-9]{16}", "severity": "HIGH"}]}\n',
        encoding="utf-8",
    )
    code = run(
        ["--no-color", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
