"""Parse ``git log -p`` output into added lines for history scanning.

Only ``+`` lines (not ``+++`` headers) are scanned. That is where a secret
is *introduced*. A later commit that deletes the file still leaves the
introduction in history.

This module does not rewrite Git history.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from scanner.git_mode import GitError, git_history_patch

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_COMMIT = re.compile(r"^===COMMIT ([0-9a-f]{40})===\s*$")


@dataclass(frozen=True)
class HistoryLine:
    """One added line from a commit patch. ``text`` is not logged."""

    commit: str
    relative_path: str
    line_number: int
    text: str


def list_history_lines(root: Path, max_count: int) -> list[HistoryLine]:
    """Return added lines from the most recent ``max_count`` commits."""
    if max_count < 1 or max_count > 5000:
        raise GitError("history depth must be between 1 and 5000")
    patch = git_history_patch(root, max_count)
    return parse_history_patch(patch)


def parse_history_patch(patch: str) -> list[HistoryLine]:
    """Parse a ``git log --pretty=format:===COMMIT %H=== -p`` dump."""
    lines: list[HistoryLine] = []
    commit = ""
    rel_path = ""
    skip = False
    new_line = 0
    for raw in patch.splitlines():
        marked = _COMMIT.match(raw)
        if marked:
            commit = marked.group(1)
            rel_path = ""
            skip = False
            continue
        if not commit:
            continue
        if raw.startswith("diff --git "):
            rel_path = ""
            skip = False
            continue
        if raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            skip = True
            rel_path = ""
            continue
        if raw.startswith("+++ "):
            rel_path = _plus_path(raw)
            skip = not rel_path
            continue
        if skip or not rel_path:
            continue
        hunk = _HUNK.match(raw)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.append(
                HistoryLine(
                    commit=commit,
                    relative_path=rel_path,
                    line_number=new_line,
                    text=raw[1:],
                )
            )
            new_line += 1
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            continue
        if raw.startswith(" "):
            new_line += 1
    return lines


def _plus_path(header: str) -> str:
    """Return the path from ``+++ b/foo`` or empty for ``/dev/null``."""
    payload = header[4:].strip()
    if payload == "/dev/null":
        return ""
    if payload.startswith("b/"):
        payload = payload[2:]
    if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in {'"', "'"}:
        payload = payload[1:-1]
    payload = payload.replace("\\", "/").lstrip("./")
    if payload.startswith(".git/"):
        return ""
    return payload


def path_in_target(relative_path: str, repo: Path, target: Path) -> bool:
    """True if ``relative_path`` is the scan target or lives under it."""
    candidate = (repo / relative_path).resolve()
    base = target.expanduser().resolve()
    if candidate == base:
        return True
    try:
        candidate.relative_to(base)
    except ValueError:
        return False
    return True
