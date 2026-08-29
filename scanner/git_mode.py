"""Git-aware file lists (staged / changed). No hooks are installed here.

Uses the ``git`` executable via subprocess, not a Git library. Paths are
relative to the repository root and then resolved. Deleted files are omitted
(``--diff-filter`` keeps Added / Copied / Modified / Renamed).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from utils.logger import get_logger

_LOG = get_logger()

_DIFF_FILTER = "ACMR"


class GitError(Exception):
    """Raised when git is missing or the target is not a repository."""


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError(
            "git executable not found. Install Git and ensure it is on PATH."
        ) from exc


def repo_root(start: Path) -> Path:
    """Return the repository toplevel that contains ``start``."""
    start = start.expanduser().resolve()
    cwd = start if start.is_dir() else start.parent
    result = _run_git(cwd, ["rev-parse", "--show-toplevel"])
    if result.returncode != 0:
        raise GitError("Not a git repository (or any of the parent directories).")
    return Path(result.stdout.strip())


def _split_nul(raw: str, root: Path) -> list[Path]:
    names = [item for item in raw.split("\0") if item]
    paths: list[Path] = []
    for name in names:
        candidate = (root / name).resolve()
        if candidate.is_file():
            paths.append(candidate)
    return paths


def list_staged_files(root: Path) -> list[Path]:
    """Files in the index (what the next commit would include)."""
    result = _run_git(
        root,
        ["diff", "--cached", "--name-only", "-z", f"--diff-filter={_DIFF_FILTER}"],
    )
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or "git diff --cached failed")
    paths = _split_nul(result.stdout, root)
    _LOG.info("Git staged files: %s", len(paths))
    return paths


def _has_head(root: Path) -> bool:
    return _run_git(root, ["rev-parse", "--verify", "HEAD"]).returncode == 0


def list_untracked_files(root: Path) -> list[Path]:
    result = _run_git(root, ["ls-files", "-o", "--exclude-standard", "-z"])
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or "git ls-files failed")
    return _split_nul(result.stdout, root)


def list_changed_files(root: Path) -> list[Path]:
    """Working tree vs HEAD, plus untracked files.

    If the repo has no commits yet, this is staged + untracked (first commit).
    """
    if _has_head(root):
        result = _run_git(
            root,
            ["diff", "--name-only", "-z", f"--diff-filter={_DIFF_FILTER}", "HEAD"],
        )
        if result.returncode != 0:
            raise GitError(result.stderr.strip() or "git diff HEAD failed")
        paths = _split_nul(result.stdout, root)
    else:
        paths = list_staged_files(root)
    paths.extend(list_untracked_files(root))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    _LOG.info("Git changed files: %s", len(unique))
    return unique


def restrict_to_target(paths: list[Path], target: Path) -> list[Path]:
    """Keep paths that are ``target`` or live under it."""
    target = target.expanduser().resolve()
    kept: list[Path] = []
    for path in paths:
        try:
            path.resolve().relative_to(target)
        except ValueError:
            continue
        kept.append(path.resolve())
    return kept
