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
    config.excluded_dirs.add("vendor")
    scanner = Scanner(config=config)

    found = scanner.discover_files(tmp_path)

    assert [path.name for path in found] == ["app.py"]
