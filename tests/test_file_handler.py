"""Tests for directory/file discovery. No real secrets are used here."""

from pathlib import Path

from scanner.file_handler import ScanConfig, iter_scan_files, should_scan_file


def _names(paths: list[Path]) -> set[str]:
    return {path.name for path in paths}


def test_discovers_nested_text_files_and_dotenv(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (src / "config.py").write_text("DEBUG = True\n", encoding="utf-8")
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "database.py").write_text("ENGINE = 'sqlite'\n", encoding="utf-8")
    (tmp_path / ".env").write_text("EXAMPLE=placeholder\n", encoding="utf-8")

    found = list(iter_scan_files(tmp_path, ScanConfig()))

    assert _names(found) == {"main.py", "config.py", "database.py", ".env"}


def test_skips_default_excluded_directories(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git internals\n", encoding="utf-8")

    vendor = tmp_path / "node_modules" / "some-pkg"
    vendor.mkdir(parents=True)
    (vendor / "index.js").write_text("module.exports = {}\n", encoding="utf-8")

    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"\x00\x01")

    venv_dir = tmp_path / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "site.py").write_text("ignored\n", encoding="utf-8")

    found = list(iter_scan_files(tmp_path, ScanConfig()))

    assert _names(found) == {"app.py"}


def test_skips_binary_extensions(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "photo.PNG").write_bytes(b"not a real image")
    (tmp_path / "archive.zip").write_bytes(b"PK")
    (tmp_path / "notes.pdf").write_bytes(b"%PDF")

    found = list(iter_scan_files(tmp_path, ScanConfig()))

    assert _names(found) == {"app.py"}


def test_skips_files_with_nul_bytes(tmp_path: Path) -> None:
    (tmp_path / "readme.txt").write_text("plain text\n", encoding="utf-8")
    (tmp_path / "weird.txt").write_bytes(b"hello\x00world")

    found = list(iter_scan_files(tmp_path, ScanConfig()))

    assert _names(found) == {"readme.txt"}


def test_single_file_target(tmp_path: Path) -> None:
    target = tmp_path / "only.py"
    target.write_text("print('ok')\n", encoding="utf-8")

    found = list(iter_scan_files(target, ScanConfig()))

    assert found == [target.resolve()]


def test_excluded_extension_can_be_configured(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "skip.md").write_text("# notes\n", encoding="utf-8")

    config = ScanConfig()
    config.excluded_extensions.add(".md")

    found = list(iter_scan_files(tmp_path, config))

    assert _names(found) == {"keep.py"}
    assert not should_scan_file(tmp_path / "skip.md", config)


def test_missing_target_raises_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    try:
        list(iter_scan_files(missing, ScanConfig()))
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")
