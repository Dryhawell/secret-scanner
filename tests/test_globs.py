"""CLI glob filter tests. No real secrets are used."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from cli.interface import build_parser, run


def test_glob_hides_non_matching_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("EXAMPLE=placeholder\n", encoding="utf-8")
    log_file = tmp_path / "scan.log"
    reports = tmp_path / "reports"
    assert (
        run(
            ["--no-color", "--glob", "*.env", str(tmp_path)],
            log_file=log_file,
            reports_dir=reports,
        )
        == 0
    )
    assert (
        run(
            ["--no-color", "--glob", "*.py", str(tmp_path)],
            log_file=log_file,
            reports_dir=reports,
        )
        == 1
    )


def test_skip_glob_skips_leaky_file(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--skip-glob", "*.py", str(tmp_path)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_glob_flag_like_pattern_is_rejected() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--glob", "--staged"])


def test_stdin_respects_glob_on_virtual_name(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    buffer = StringIO(f"AWS_ACCESS_KEY_ID = '{aws}'\n")
    skipped = run(
        ["--no-color", "--stdin", "notes.md", "--glob", "*.py"],
        stdin=buffer,
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert skipped == 0
    buffer = StringIO(f"AWS_ACCESS_KEY_ID = '{aws}'\n")
    hit = run(
        ["--no-color", "--stdin", "leak.py", "--glob", "*.py"],
        stdin=buffer,
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert hit == 1
