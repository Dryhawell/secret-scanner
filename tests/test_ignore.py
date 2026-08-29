"""Allowlist / ignore-file tests. No real secrets are used."""

from pathlib import Path

from cli.interface import run
from scanner.file_handler import ScanConfig
from scanner.ignore import (
    is_ignored_finding,
    is_ignored_path,
    matches_path,
    parse_ignore_text,
)
from scanner.scanner import Scanner


def test_parse_ignore_skips_comments_and_blank_lines() -> None:
    rules = parse_ignore_text(
        """
        # comment
        tests/

        scanner/detector.py | Contextual Secret
        """
    )
    assert rules.paths == ("tests/",)
    assert rules.findings == (("scanner/detector.py", "Contextual Secret"),)


def test_directory_prefix_matches_nested_file() -> None:
    assert matches_path("tests/test_cli.py", "tests/")
    assert matches_path("tests/nested/a.py", "tests/")
    assert not matches_path("scanner/detector.py", "tests/")


def test_is_ignored_path_skips_tests_tree(tmp_path: Path) -> None:
    leaked = tmp_path / "tests" / "leak.py"
    leaked.parent.mkdir()
    leaked.write_text("x\n", encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    assert is_ignored_path(leaked, tmp_path, ["tests/"])
    assert not is_ignored_path(app, tmp_path, ["tests/"])


def test_finding_rule_is_pattern_specific(tmp_path: Path) -> None:
    path = tmp_path / "scanner" / "detector.py"
    path.parent.mkdir()
    path.write_text("x\n", encoding="utf-8")
    rules = (("scanner/detector.py", "Contextual Secret"),)
    assert is_ignored_finding(path, "Contextual Secret", tmp_path, rules)
    assert not is_ignored_finding(path, "AWS Access Key ID", tmp_path, rules)


def test_scanner_skips_allowlisted_directory(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    config = ScanConfig(ignore_paths=["tests/"])
    result = Scanner(config=config).scan(tmp_path)
    assert result.findings_count == 0
    assert {path.name for path in Scanner(config=config).discover_files(tmp_path)} == {
        "ok.py"
    }


def test_cli_ignore_file_drops_fixture_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    ignore = tmp_path / ".secret-scanner-ignore"
    ignore.write_text("tests/\n", encoding="utf-8")
    assert (
        run(
            ["--no-color", "--ignore-file", str(ignore), str(tmp_path)],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )


def test_missing_explicit_ignore_file_exits_two(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    assert (
        run(
            [
                "--no-color",
                "--ignore-file",
                str(tmp_path / "missing.ignore"),
                str(tmp_path),
            ],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 2
    )
