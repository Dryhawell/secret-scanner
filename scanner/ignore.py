"""Path and finding allowlist (``.secret-scanner-ignore``).

Ignoring a path means leaks in that file are never reported. Use this for
test fixtures and known false positives — not to hide a live credential.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from utils.logger import get_logger

_LOG = get_logger()

DEFAULT_IGNORE_NAME = ".secret-scanner-ignore"
_FINDING_SEP = " | "


class IgnoreError(Exception):
    """Raised when an explicit ignore file cannot be read."""


@dataclass(frozen=True)
class IgnoreRules:
    """Path skips and per-file finding suppressions."""

    paths: tuple[str, ...] = ()
    findings: tuple[tuple[str, str], ...] = ()


def parse_ignore_text(text: str) -> IgnoreRules:
    """Parse ignore-file contents. ``#`` starts a comment."""
    paths: list[str] = []
    findings: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if _FINDING_SEP in line:
            location, pattern = line.split(_FINDING_SEP, 1)
            location = location.strip()
            pattern = pattern.strip()
            if location and pattern:
                findings.append((location, pattern))
            continue
        paths.append(line)
    return IgnoreRules(paths=tuple(paths), findings=tuple(findings))


def load_ignore_file(path: Path) -> IgnoreRules:
    """Read and parse ``path``. Missing files raise ``IgnoreError``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IgnoreError(f"Unable to read ignore file: {path}") from exc
    rules = parse_ignore_text(text)
    _LOG.info(
        "Loaded ignore file %s (%s path(s), %s finding rule(s))",
        path,
        len(rules.paths),
        len(rules.findings),
    )
    return rules


def default_ignore_file(target: Path) -> Path | None:
    """Return ``.secret-scanner-ignore`` next to ``target``, else at cwd if it is a parent."""
    search = target if target.is_dir() else target.parent
    here = search / DEFAULT_IGNORE_NAME
    if here.is_file():
        return here
    cwd = Path.cwd().resolve()
    try:
        search.expanduser().resolve().relative_to(cwd)
    except ValueError:
        return None
    cwd_file = cwd / DEFAULT_IGNORE_NAME
    if cwd_file.is_file():
        return cwd_file
    return None


def ignore_root(target: Path) -> Path:
    """Directory used as the allowlist root (the target, or its parent if a file)."""
    path = target.expanduser()
    if path.exists():
        path = path.resolve()
    return path if path.is_dir() else path.parent


def relative_posix(path: Path, root: Path) -> str:
    """Return ``path`` relative to ``root`` using forward slashes."""
    resolved = path.expanduser().resolve()
    base = root.expanduser()
    base = base.resolve() if base.exists() else base
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return resolved.as_posix()


def matches_path(relative_posix: str, pattern: str) -> bool:
    """Return True if ``relative_posix`` is covered by ``pattern``."""
    rel = relative_posix.replace("\\", "/").lstrip("./")
    pat = pattern.replace("\\", "/").strip()
    if not pat:
        return False
    rel_cf = rel.casefold()
    pat_cf = pat.casefold()
    if pat.endswith("/**"):
        prefix = pat[:-3].rstrip("/")
        return _under_prefix(rel_cf, prefix.casefold())
    if pat.endswith("/"):
        return _under_prefix(rel_cf, pat_cf.rstrip("/"))
    if "/" not in pat:
        name = rel.rsplit("/", 1)[-1]
        if fnmatch.fnmatch(name.casefold(), pat_cf):
            return True
        return any(fnmatch.fnmatch(part.casefold(), pat_cf) for part in rel.split("/"))
    return fnmatch.fnmatch(rel_cf, pat_cf) or rel_cf == pat_cf


def _under_prefix(rel_cf: str, prefix_cf: str) -> bool:
    if not prefix_cf:
        return True
    return rel_cf == prefix_cf or rel_cf.startswith(prefix_cf + "/")


def is_ignored_path(path: Path, root: Path, patterns: tuple[str, ...] | list[str]) -> bool:
    """True if this file should not be scanned."""
    relative = relative_posix(path, root)
    return any(matches_path(relative, pattern) for pattern in patterns)


def is_ignored_finding(
    path: Path,
    pattern_name: str,
    root: Path,
    rules: tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> bool:
    """True if this finding type is allowlisted for ``path``."""
    relative = relative_posix(path, root)
    for location, name in rules:
        if name != pattern_name:
            continue
        if matches_path(relative, location):
            return True
    return False
