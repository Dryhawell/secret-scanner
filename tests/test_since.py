"""Git --since (REF...HEAD) tests. Requires git on PATH. No real secrets."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cli.interface import run
from scanner.git_mode import GitError, list_since_files, repo_root, validate_since_ref

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


def _commit(root: Path, message: str) -> None:
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )


def test_validate_since_ref_rejects_ranges_and_flags() -> None:
    assert validate_since_ref(" origin/main ") == "origin/main"
    with pytest.raises(GitError):
        validate_since_ref("")
    with pytest.raises(GitError):
        validate_since_ref("main..HEAD")
    with pytest.raises(GitError):
        validate_since_ref("-u")


def test_since_scans_files_in_latest_commit(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    _git(tmp_path, "init")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "ok.py")
    _commit(tmp_path, "ok")
    leaked = tmp_path / "leak.py"
    leaked.write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    _git(tmp_path, "add", "leak.py")
    _commit(tmp_path, "add leak")

    paths = list_since_files(repo_root(tmp_path), "HEAD~1")
    assert leaked.resolve() in paths
    assert (tmp_path / "ok.py").resolve() not in paths

    code = run(
        ["--no-color", "--since", "HEAD~1", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1


def test_since_skips_untouched_old_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    _git(tmp_path, "init")
    (tmp_path / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "leak.py")
    _commit(tmp_path, "old leak")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "ok.py")
    _commit(tmp_path, "docs")
    code = run(
        ["--no-color", "--since", "HEAD~1", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_since_unknown_ref_exits_two(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "ok.py")
    _commit(tmp_path, "ok")
    code = run(
        ["--no-color", "--since", "no-such-ref-zzzz", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_since_outside_repo_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--since", "HEAD", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
