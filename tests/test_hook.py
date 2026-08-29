"""Pre-commit hook installer tests. Requires git on PATH."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cli.interface import run
from scanner.hook import HookError, hook_template_path, install_pre_commit_hook
from scanner.git_mode import repo_root

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


def test_hook_template_scans_staged_files() -> None:
    text = hook_template_path().read_text(encoding="utf-8")
    assert "--staged" in text
    assert "--no-color" in text
    assert "main.py" in text


def test_install_hook_writes_pre_commit(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    dest = install_pre_commit_hook(repo_root(tmp_path))
    assert dest.is_file()
    text = dest.read_text(encoding="utf-8")
    assert "--staged" in text
    with pytest.raises(HookError):
        install_pre_commit_hook(repo_root(tmp_path))
    again = install_pre_commit_hook(repo_root(tmp_path), force=True)
    assert again == dest


def test_cli_install_hook_exits_zero(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    code = run(
        ["--no-color", "--install-hook", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert hook.is_file()
    assert "--staged" in hook.read_text(encoding="utf-8")


def test_cli_install_hook_without_repo_exits_2(tmp_path: Path) -> None:
    code = run(
        ["--no-color", "--install-hook", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2

