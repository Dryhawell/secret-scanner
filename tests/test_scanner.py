"""Scanner discovery and scan-orchestration tests."""

from pathlib import Path

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
    assert result.findings_count >= 1
    assert aws not in result.findings[0].masked_value


def test_discover_files_deduplicates_resolved_paths(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('ok')\n", encoding="utf-8")
    scanner = Scanner()
    found = scanner.discover_files(tmp_path)
    assert found.count(target.resolve()) == 1

