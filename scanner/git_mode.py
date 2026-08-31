"""Git-aware file lists (staged / changed) and history patches.

Uses the ``git`` executable via subprocess, not a Git library. Paths are
relative to the repository root and then resolved. Deleted files are omitted
from staged/changed lists (``--diff-filter`` keeps Added / Copied / Modified /
Renamed). History mode still sees the commit that *introduced* a secret.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from utils.logger import get_logger

_LOG = get_logger()

_DIFF_FILTER = "ACMR"
_GIT_TIMEOUT_SECONDS = 30


class GitError(Exception):
    """Raised when git is missing or the target is not a repository."""


def _run_git(
    root: Path, args: list[str], *, timeout: int | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout or _GIT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise GitError(
            "git executable not found. Install Git and ensure it is on PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git command timed out.") from exc


def git_dir(root: Path) -> Path:
    """Return the ``.git`` directory (handles worktrees where ``.git`` is a file)."""
    result = _run_git(root, ["rev-parse", "--git-dir"])
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or "git rev-parse --git-dir failed")
    raw = Path(result.stdout.strip())
    if not raw.is_absolute():
        raw = (root / raw).resolve()
    return raw


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


def validate_since_ref(ref: str) -> str:
    """Return a single git ref, or raise GitError.

    A range (``..``) is rejected so the caller always forms ``REF...HEAD``.
    Leading dashes are rejected so the value cannot be parsed as a git flag.
    """
    text = ref.strip()
    if not text or "\x00" in text:
        raise GitError("--since requires a git ref (branch, tag, or SHA)")
    if text.startswith("-"):
        raise GitError("--since ref must not start with '-'")
    if ".." in text:
        raise GitError("--since expects a single ref, not a range (use origin/main, not a..b)")
    return text


def list_since_files(root: Path, ref: str) -> list[Path]:
    """Files changed from the merge-base of ``ref`` and HEAD (``REF...HEAD``).

    Untracked files are not included. A secret that already existed on ``ref``
    and was not touched is a false negative by design — use a full tree scan
    or ``--history`` for that.
    """
    spec = f"{validate_since_ref(ref)}...HEAD"
    result = _run_git(
        root,
        ["diff", "--name-only", "-z", f"--diff-filter={_DIFF_FILTER}", spec],
    )
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git diff {spec} failed")
    paths = _split_nul(result.stdout, root)
    _LOG.info("Git since files: %s (range=%s)", len(paths), spec)
    return paths


_HISTORY_GIT_TIMEOUT_SECONDS = 120
_COMMIT_PRETTY = "===COMMIT %H==="


def git_history_patch(root: Path, max_count: int) -> str:
    """Return ``git log -p`` text for the most recent ``max_count`` commits."""
    result = _run_git(
        root,
        [
            "log",
            "--all",
            f"--max-count={max_count}",
            f"--diff-filter={_DIFF_FILTER}",
            f"--pretty=tformat:{_COMMIT_PRETTY}",
            "--patch",
            "--no-color",
            "--text",
        ],
        timeout=_HISTORY_GIT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or "git log failed")
    _LOG.info("Git history patch bytes: %s (max-count=%s)", len(result.stdout), max_count)
    return result.stdout


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
