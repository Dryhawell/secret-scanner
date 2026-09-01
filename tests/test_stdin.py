"""Stdin scanning tests. No real secrets are used."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from cli.interface import build_parser, run, stdin_virtual_path
from scanner.file_handler import DEFAULT_MAX_FILE_SIZE
from scanner.scanner import Scanner


class _TTY:
    def isatty(self) -> bool:
        return True

    def read(self) -> str:
        raise AssertionError("TTY stdin must not be read")


def test_stdin_virtual_path_defaults_to_stdin() -> None:
    namespace = build_parser().parse_args(["--stdin"])
    assert stdin_virtual_path(namespace) == Path("stdin")
    dotted = build_parser().parse_args([".", "--stdin"])
    assert stdin_virtual_path(dotted) == Path("stdin")
    named = build_parser().parse_args(["leak.py", "--stdin"])
    assert stdin_virtual_path(named) == Path("leak.py")


def test_stdin_finding_exits_one_and_masks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    buffer = StringIO(
        "print('ok')\n"
        "print('ok')\n"
        f"AWS_ACCESS_KEY_ID = '{aws}'\n"
    )
    log_file = tmp_path / "scan.log"
    code = run(
        ["--no-color", "--stdin"],
        stdin=buffer,
        reports_dir=tmp_path,
        log_file=log_file,
    )
    captured = capsys.readouterr()
    assert code == 1
    assert aws not in captured.out
    assert aws not in captured.err
    assert "stdin:3" in captured.out
    assert aws not in log_file.read_text(encoding="utf-8")


def test_stdin_clean_exits_zero(tmp_path: Path) -> None:
    code = run(
        ["--no-color", "--stdin"],
        stdin=StringIO("print('ok')\n"),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_stdin_missing_path_label_is_not_an_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.py"
    code = run(
        ["--no-color", "--stdin", str(missing)],
        stdin=StringIO("print('ok')\n"),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_stdin_and_staged_exit_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = run(
        ["--no-color", "--stdin", "--staged", str(tmp_path)],
        stdin=StringIO("print('ok')\n"),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "Git scan flags" in capsys.readouterr().err


def test_stdin_and_dashboard_exit_two(tmp_path: Path) -> None:
    code = run(
        ["--dashboard", "--stdin", "--no-browser"],
        stdin=StringIO("print('ok')\n"),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 2


def test_stdin_tty_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = run(
        ["--no-color", "--stdin"],
        stdin=_TTY(),  # type: ignore[arg-type]
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 2
    assert "piped input" in capsys.readouterr().err


def test_stdin_oversize_exits_two(tmp_path: Path) -> None:
    huge = "a" * (DEFAULT_MAX_FILE_SIZE + 1)
    code = run(
        ["--no-color", "--stdin"],
        stdin=StringIO(huge),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 2


def test_stdin_inline_ignore_is_allowlisted(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    buffer = StringIO(
        f"AWS_ACCESS_KEY_ID = '{aws}'  # secret-scanner:ignore\n"
    )
    code = run(
        ["--no-color", "--stdin"],
        stdin=buffer,
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 0


def test_stdin_json_masks_and_uses_virtual_path(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    report = tmp_path / "out.json"
    code = run(
        [
            "--no-color",
            "--stdin",
            "leak.py",
            "--format",
            "json",
            "--output",
            str(report),
        ],
        stdin=StringIO(f"AWS_ACCESS_KEY_ID = '{aws}'\n"),
        reports_dir=tmp_path,
        log_file=tmp_path / "scan.log",
    )
    assert code == 1
    payload = json.loads(report.read_text(encoding="utf-8"))
    body = json.dumps(payload)
    assert aws not in body
    finding = payload["findings"][0]
    assert finding["file_path"] == "leak.py"
    assert finding["line_number"] == 1
    assert finding["masked_value"] != aws


def test_scan_text_does_not_write_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    before = {path.name for path in tmp_path.iterdir()}
    result = Scanner().scan_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        virtual_path=Path("stdin"),
        target=tmp_path,
    )
    after = {path.name for path in tmp_path.iterdir()}
    assert after == before
    assert len(result.findings) == 1
    assert result.files_scanned == 1
    assert aws not in result.findings[0].masked_value
