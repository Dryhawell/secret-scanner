"""Scanner discovery and scan-orchestration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli.interface import run
from scanner import ScanConfig, Scanner


def test_scanner_discovers_files_via_facade(tmp_path: Path) -> None:
    nested = tmp_path / "src"
    nested.mkdir()
    (nested / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8")

    scanner = Scanner()
    found = scanner.discover_files(tmp_path)

    assert [path.name for path in found] == ["app.py"]


def test_scanner_uses_custom_config(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    extra = tmp_path / "vendor"
    extra.mkdir()
    (extra / "lib.py").write_text("ignored\n", encoding="utf-8")

    config = ScanConfig()
    config.exclude_dir("vendor")
    scanner = Scanner(config=config)

    found = scanner.discover_files(tmp_path)

    assert [path.name for path in found] == ["app.py"]


def test_scanner_skips_binary_and_reports_valid_secret(tmp_path: Path) -> None:
    nested = tmp_path / "src"
    nested.mkdir()
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (nested / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff")
    result = Scanner().scan(tmp_path)
    assert result.files_scanned == 1
    assert result.files_skipped_binary == 0
    assert result.findings_count >= 1
    assert aws not in result.findings[0].masked_value


def test_scanner_counts_nul_sniffed_binary_skips(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "blob.dat").write_bytes(b"hello\x00world")
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff")
    result = Scanner().scan(tmp_path)
    assert result.files_scanned == 1
    assert result.files_skipped_binary == 1
    assert result.files_skipped_oversized == 0
    assert result.findings_count == 0


def test_binary_skip_is_counted_in_text_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (src / "blob.dat").write_bytes(b"hello\x00world")
    (src / "photo.jpg").write_bytes(b"\xff\xd8\xff")
    text_code = run(
        ["--no-color", str(src)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    text_out = capsys.readouterr().out
    assert text_code == 0
    assert "Files skipped (binary): 1" in text_out
    json_code = run(
        ["--no-color", "--format", "json", "-o", "-", str(src)],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    payload_json = json.loads(capsys.readouterr().out)
    assert json_code == 0
    assert payload_json["files_skipped_binary"] == 1
    assert payload_json["files_skipped_oversized"] == 0
    assert payload_json["files_scanned"] == 1
    html_code = run(
        [
            "--no-color",
            "--format",
            "html",
            "--output",
            str(tmp_path / "out.html"),
            str(src),
        ],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert html_code == 0
    html = (tmp_path / "out.html").read_text(encoding="utf-8")
    assert "Binary skipped" in html
    sarif_code = run(
        [
            "--no-color",
            "--format",
            "sarif",
            "--output",
            str(tmp_path / "out.sarif"),
            str(src),
        ],
        log_file=tmp_path / "scan.log",
        reports_dir=tmp_path / "reports",
    )
    assert sarif_code == 0
    sarif = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["filesSkippedBinary"] == 1


def test_discover_files_deduplicates_resolved_paths(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    scanner = Scanner()
    found = scanner.discover_files(tmp_path)
    assert found.count(target.resolve()) == 1

