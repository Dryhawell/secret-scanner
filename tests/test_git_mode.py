"""Git staged/changed file listing tests. Requires git on PATH."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.git_mode import (
    GitError,
    list_changed_files,
    list_staged_files,
    repo_root,
    restrict_to_target,
)
from cli.interface import run
from scanner.scanner import Scanner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(root: Path, *args: str) -> None:
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _init_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    return tmp_path


def test_repo_root_and_staged_only(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    leaked = tmp_path / "leak.py"
    clean = tmp_path / "ok.py"
    leaked.write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    clean.write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "leak.py")

    root = repo_root(tmp_path)
    staged = list_staged_files(root)
    assert leaked.resolve() in staged
    assert clean.resolve() not in staged

    result = Scanner().scan_paths(staged, target=tmp_path)
    assert result.findings_count >= 1
    assert aws not in result.findings[0].masked_value


def test_cli_staged_ignores_unstaged_leak(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "ok.py")
    code = run(
        ["--no-color", "--staged", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_changed_includes_untracked(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    untracked = tmp_path / "new.py"
    untracked.write_text("print('ok')\n", encoding="utf-8")
    changed = list_changed_files(repo_root(tmp_path))
    assert untracked.resolve() in changed


def test_restrict_to_target_keeps_nested_only(tmp_path: Path) -> None:
    nested = tmp_path / "src"
    nested.mkdir()
    inside = nested / "a.py"
    outside = tmp_path / "b.py"
    inside.write_text("x\n", encoding="utf-8")
    outside.write_text("y\n", encoding="utf-8")
    kept = restrict_to_target([inside, outside], nested)
    assert kept == [inside.resolve()]


def test_repo_root_raises_outside_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(GitError):
        repo_root(tmp_path)


def test_cli_staged_outside_repo_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--staged", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_cli_changed_scans_untracked_leak(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    code = run(
        ["--no-color", "--changed", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1
