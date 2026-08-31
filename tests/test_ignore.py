"""Allowlist / ignore-file tests. No real secrets are used."""

from pathlib import Path

from cli.interface import run
from scanner.file_handler import ScanConfig
from scanner.ignore import (
    INLINE_ALL,
    inline_ignore_spec,
    is_ignored_finding,
    is_ignored_path,
    is_inline_ignored,
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


def test_inline_ignore_spec_all_and_typed() -> None:
    assert inline_ignore_spec("print('ok')") is None
    assert inline_ignore_spec("x = 1  # secret-scanner:ignore") == INLINE_ALL
    assert (
        inline_ignore_spec("x = 1  # secret-scanner:ignore AWS Access Key ID")
        == "AWS Access Key ID"
    )
    assert is_inline_ignored("x  # secret-scanner:ignore", "AWS Access Key ID")
    assert is_inline_ignored(
        "x  # secret-scanner:ignore AWS Access Key ID", "AWS Access Key ID"
    )
    assert not is_inline_ignored(
        "x  # secret-scanner:ignore AWS Access Key ID", "GitHub Token"
    )


def test_inline_ignore_counts_as_allowlist(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'  # secret-scanner:ignore\n",
        encoding="utf-8",
    )
    result = Scanner().scan(tmp_path)
    assert result.findings_count == 0
    assert result.allowlist_ignored >= 1


def test_cli_inline_ignore_drops_same_line_only(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'  # secret-scanner:ignore\n"
        "print('ok')\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", str(tmp_path)],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 0
    )


def test_cli_typed_inline_ignore_keeps_other_types(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'  # secret-scanner:ignore Generic Password\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", str(tmp_path)],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )


def test_inline_ignore_does_not_affect_next_line(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "app.py").write_text(
        "# secret-scanner:ignore\n"
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    assert (
        run(
            ["--no-color", str(tmp_path)],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 1
    )
