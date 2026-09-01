"""Minimum-confidence reporting filter. No real secrets are used."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.interface import build_parser, filter_findings, resolve_min_confidence, run
from scanner.config_file import ConfigError, settings_from_mapping
from scanner.models import SecretFinding, Severity


def test_filter_findings_applies_confidence_floor() -> None:
    strong = SecretFinding(
        file_path=Path("a.py"),
        line_number=1,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        masked_value="****",
        description="t",
        pattern_name="AWS Access Key ID",
        confidence=90,
    )
    weak = SecretFinding(
        file_path=Path("b.py"),
        line_number=2,
        secret_type="Contextual Secret",
        severity=Severity.MEDIUM,
        masked_value="****",
        description="t",
        pattern_name="Contextual Secret",
        confidence=52,
    )
    kept = filter_findings((strong, weak), Severity.LOW, min_confidence=80)
    assert kept == [strong]


def test_min_confidence_hides_contextual_keeps_aws(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--min-confidence", "80", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", "--min-confidence", "80", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_min_confidence_out_of_range_is_rejected() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--min-confidence", "100"])


def test_config_min_confidence(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    config = tmp_path / "scan.json"
    config.write_text('{"min_confidence": 80}\n', encoding="utf-8")
    code = run(
        ["--no-color", "--config", str(config), str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_config_min_confidence_rejects_invalid() -> None:
    with pytest.raises(ConfigError, match="0 and 99"):
        settings_from_mapping({"min_confidence": 100}, base=Path("."))


def test_cli_overrides_config_min_confidence() -> None:
    namespace = build_parser().parse_args([".", "--min-confidence", "10"])
    settings = settings_from_mapping({"min_confidence": 80}, base=Path("."))
    assert resolve_min_confidence(namespace, settings) == 10
    bare = build_parser().parse_args(["."])
    assert resolve_min_confidence(bare, settings) == 80
    assert resolve_min_confidence(bare, None) == 0
