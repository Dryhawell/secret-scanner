"""Logging tests. Secret values must never appear in the log file."""

import logging
from pathlib import Path

from scanner.scanner import Scanner
from utils.logger import setup_logging


def _flush_logs() -> None:
    for handler in logging.getLogger("secret_scanner").handlers:
        handler.flush()


def test_log_contains_scan_lifecycle_not_secret_payload(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "secret_scanner.log"
    setup_logging(log_file=log_path, verbose=True)

    Scanner().scan(tmp_path)
    _flush_logs()
    text = log_path.read_text(encoding="utf-8")

    assert "Scan started" in text
    assert "Scanning file" in text
    assert "Scan completed" in text
    assert "Potential secret detected" in text
    assert "AWS Access Key ID" in text
    assert aws not in text
    assert "ABCDEFGHIJ012345" not in text


def test_verbose_records_per_file_debug(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    log_path = tmp_path / "scan.log"
    setup_logging(log_file=log_path, verbose=False)
    Scanner().scan(tmp_path)
    quiet = log_path.read_text(encoding="utf-8")
    assert "Scanning file" not in quiet

    setup_logging(log_file=log_path, verbose=True)
    Scanner().scan(tmp_path)
    verbose = log_path.read_text(encoding="utf-8")
    assert "Scanning file" in verbose
