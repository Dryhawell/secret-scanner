"""Tests for directory/file discovery. No real secrets are used here."""

from pathlib import Path

import pytest

from scanner.file_handler import (
    ScanConfig,
    SkipStats,
    iter_scan_files,
    looks_like_binary,
    matches_glob,
    normalize_glob,
    should_scan_file,
)


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
    (tmp_path / "tool.exe").write_bytes(b"MZ")
    (tmp_path / "lib.dll").write_bytes(b"MZ")

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


def test_exclude_dir_is_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    vendor = tmp_path / "Vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("ignored\n", encoding="utf-8")

    config = ScanConfig()
    config.exclude_dir("VENDOR")
    found = list(iter_scan_files(tmp_path, config))

    assert _names(found) == {"app.py"}


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
    with pytest.raises(FileNotFoundError):
        list(iter_scan_files(missing, ScanConfig()))


def test_skips_hidden_directories_but_still_scans_dotenv(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / ".env").write_text("EXAMPLE=placeholder\n", encoding="utf-8")
    hidden = tmp_path / ".github"
    hidden.mkdir()
    (hidden / "workflow.yml").write_text("name: ci\n", encoding="utf-8")

    found = list(iter_scan_files(tmp_path, ScanConfig()))
    assert _names(found) == {"app.py", ".env"}


def test_include_hidden_scans_dot_directories(tmp_path: Path) -> None:
    hidden = tmp_path / ".github"
    hidden.mkdir()
    (hidden / "workflow.yml").write_text("name: ci\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    config = ScanConfig(include_hidden=True)
    found = list(iter_scan_files(tmp_path, config))
    assert _names(found) == {"app.py", "workflow.yml"}


def test_looks_like_binary_detects_nul_bytes(tmp_path: Path) -> None:
    binary = tmp_path / "blob.dat"
    text = tmp_path / "ok.txt"
    binary.write_bytes(b"hello\x00world")
    text.write_text("plain\n", encoding="utf-8")
    assert looks_like_binary(binary)
    assert not looks_like_binary(text)


def test_skips_oversized_text_files(tmp_path: Path) -> None:
    small = tmp_path / "ok.py"
    huge = tmp_path / "dump.txt"
    small.write_text("print('ok')\n", encoding="utf-8")
    huge.write_bytes(b"A" * 200)

    config = ScanConfig(max_file_size_bytes=50)
    found = list(iter_scan_files(tmp_path, config))

    assert _names(found) == {"ok.py"}
    assert not should_scan_file(huge, config)
    assert should_scan_file(small, config)


def test_skip_stats_counts_oversized_not_glob_excluded(tmp_path: Path) -> None:
    small = tmp_path / "ok.py"
    huge = tmp_path / "dump.txt"
    skipped = tmp_path / "noise.md"
    small.write_text("print('ok')\n", encoding="utf-8")
    huge.write_bytes(b"A" * 200)
    skipped.write_bytes(b"B" * 200)
    config = ScanConfig(max_file_size_bytes=50, skip_globs=["*.md"])
    stats = SkipStats()
    found = list(iter_scan_files(tmp_path, config, stats=stats))
    assert _names(found) == {"ok.py"}
    assert stats.oversized == 1


def test_unlimited_size_when_max_file_size_is_none(tmp_path: Path) -> None:
    huge = tmp_path / "dump.txt"
    huge.write_bytes(b"A" * 200)
    config = ScanConfig(max_file_size_bytes=None)
    assert should_scan_file(huge, config)


def test_name_glob_matches_any_folder(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / ".env").write_text("EXAMPLE=placeholder\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("ok\n", encoding="utf-8")
    config = ScanConfig(include_globs=["*.env"])
    found = list(iter_scan_files(tmp_path, config))
    assert _names(found) == {".env"}


def test_skip_glob_drops_matching_names(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "readme.md").write_text("ok\n", encoding="utf-8")
    config = ScanConfig(skip_globs=["*.md"])
    found = list(iter_scan_files(tmp_path, config))
    assert _names(found) == {"app.py"}


def test_path_glob_is_relative_to_scan_root(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "root.py").write_text("print('ok')\n", encoding="utf-8")
    config = ScanConfig(include_globs=["src/*.py"])
    found = list(iter_scan_files(tmp_path, config))
    assert _names(found) == {"app.py"}


def test_glob_match_is_case_insensitive(tmp_path: Path) -> None:
    assert matches_glob(tmp_path / "App.PY", "*.py")
    assert matches_glob(tmp_path / ".ENV", "*.env")


def test_normalize_glob_rejects_flag_like_pattern() -> None:
    from scanner.file_handler import GlobError

    with pytest.raises(GlobError):
        normalize_glob("--staged")
    with pytest.raises(GlobError):
        normalize_glob("")


