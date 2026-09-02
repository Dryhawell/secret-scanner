"""Configurable file-size cap tests. No real secrets are used."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from cli.interface import build_parser, build_scan_config, run
from scanner.config_file import ConfigError, load_config_file, settings_from_mapping
from scanner.file_handler import (
    DEFAULT_MAX_FILE_SIZE,
    MAX_FILE_SIZE_MIB,
    MIB,
    bytes_for_mib,
)


def test_bytes_for_mib_zero_is_unlimited() -> None:
    assert bytes_for_mib(0) is None
    assert bytes_for_mib(1) == MIB


def test_default_scan_config_is_five_mib() -> None:
    namespace = build_parser().parse_args(["."])
    config = build_scan_config(namespace)
    assert config.max_file_size_bytes == DEFAULT_MAX_FILE_SIZE


def test_max_file_size_zero_is_unlimited() -> None:
    namespace = build_parser().parse_args([".", "--max-file-size", "0"])
    config = build_scan_config(namespace)
    assert config.max_file_size_bytes is None


def test_max_file_size_out_of_range() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--max-file-size", "-1"])
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--max-file-size", str(MAX_FILE_SIZE_MIB + 1)])


def test_cli_skips_file_above_cap(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    payload = f"AWS_ACCESS_KEY_ID = '{aws}'\n" + ("x" * (2 * MIB))
    (tmp_path / "dump.py").write_text(payload, encoding="utf-8")
    assert (
        run(
            ["--no-color", "--max-file-size", "1", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )
    assert (
        run(
            ["--no-color", "--max-file-size", "0", str(tmp_path)],
            log_file=tmp_path / "scan.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_cli_overrides_config_max_file_size(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / ".secret-scanner.json"
    config.write_text('{"max_file_size": 1}\n', encoding="utf-8")
    namespace = build_parser().parse_args(
        ["--max-file-size", "8", str(tmp_path)]
    )
    settings = load_config_file(config)
    built = build_scan_config(namespace, settings)
    assert built.max_file_size_bytes == 8 * MIB


def test_config_max_file_size_json() -> None:
    settings = settings_from_mapping({"max_file_size": 8}, base=Path("."))
    assert settings.max_file_size == 8


def test_config_max_file_size_out_of_range() -> None:
    with pytest.raises(ConfigError, match="max_file_size"):
        settings_from_mapping({"max_file_size": 4096}, base=Path("."))


def test_stdin_respects_max_file_size(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    huge = "a" * (MIB + 1)
    code = run(
        ["--no-color", "--stdin", "--max-file-size", "1"],
        stdin=StringIO(huge),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "1 MiB" in capsys.readouterr().err


def test_stdin_unlimited_allows_default_cap(tmp_path: Path) -> None:
    huge = "a" * (DEFAULT_MAX_FILE_SIZE + 1)
    assert (
        run(
            ["--no-color", "--stdin", "--max-file-size", "0"],
            stdin=StringIO(huge),
            reports_dir=tmp_path,
            log_file=tmp_path / "scan.log",
        )
        == 0
    )
