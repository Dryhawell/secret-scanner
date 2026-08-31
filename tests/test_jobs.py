"""Parallel file-scan tests. No real secrets."""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.interface import build_parser, build_scan_config, run
from scanner.config_file import ConfigError, load_config_file, settings_from_mapping
from scanner.file_handler import MAX_JOBS, ScanConfig, resolve_jobs
from scanner.scanner import Scanner


def test_resolve_jobs_auto_is_in_range() -> None:
    count = resolve_jobs(0)
    assert 1 <= count <= MAX_JOBS


def test_resolve_jobs_caps_at_max() -> None:
    assert resolve_jobs(MAX_JOBS) == MAX_JOBS


def test_parallel_findings_match_sequential(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    for index in range(6):
        (tmp_path / f"leak_{index}.py").write_text(
            f"AWS_ACCESS_KEY_ID = '{aws}'\n",
            encoding="utf-8",
        )
    sequential = Scanner(config=ScanConfig(jobs=1)).scan(tmp_path)
    parallel = Scanner(config=ScanConfig(jobs=4)).scan(tmp_path)
    assert sequential.findings_count == parallel.findings_count == 6
    seq_keys = [
        (item.display_path(tmp_path), item.line_number, item.pattern_name)
        for item in sequential.findings
    ]
    par_keys = [
        (item.display_path(tmp_path), item.line_number, item.pattern_name)
        for item in parallel.findings
    ]
    assert seq_keys == par_keys
    assert aws not in parallel.findings[0].masked_value


def test_cli_jobs_finds_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "a.py").write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    code = run(
        ["--no-color", "--jobs", "4", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1


def test_cli_jobs_zero_is_auto(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--jobs", "0", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_cli_jobs_out_of_range() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--jobs", "-1"])
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--jobs", str(MAX_JOBS + 1)])


def test_cli_jobs_overrides_config(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / ".secret-scanner.json"
    config.write_text('{"jobs": 1}\n', encoding="utf-8")
    namespace = build_parser().parse_args(["--jobs", "4", str(tmp_path)])
    settings = load_config_file(config)
    built = build_scan_config(namespace, settings)
    assert built.jobs == 4


def test_config_jobs_json() -> None:
    settings = settings_from_mapping({"jobs": 4}, base=Path("."))
    assert settings.jobs == 4


def test_config_jobs_out_of_range() -> None:
    with pytest.raises(ConfigError, match="jobs"):
        settings_from_mapping({"jobs": 99}, base=Path("."))
