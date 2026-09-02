"""File selection helpers for directory scanning.

This module decides *which* paths are scan candidates. It does not look
for secrets. Size and binary checks keep large dumps out of the regex loop.

Why this split exists:
    Walking the filesystem and matching regexes are different jobs. File
    discovery must stay cheap, predictable, and easy to test on its own.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterator

from utils.logger import get_logger

_LOG = get_logger()

# Directory names skipped anywhere in the tree (not only at the repo root).
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
    }
)

# Extensions treated as binary / archive / non-text. Compared case-insensitively.
DEFAULT_EXCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".exe",
        ".dll",
        ".zip",
        ".rar",
        ".7z",
        ".pdf",
        ".pyc",
        ".so",
        ".dylib",
        ".woff",
        ".woff2",
        ".ico",
        ".webp",
        ".mp3",
        ".mp4",
        ".class",
        ".jar",
        ".gz",
        ".tar",
        ".bz2",
        ".xz",
    }
)

# How many leading bytes we read to sniff for NUL characters.
BINARY_SNIFF_BYTES = 8192

# Skip files larger than this. A 500 MB .log or misnamed dump would freeze
# line-by-line regex. Source trees rarely need more than a few megabytes.
# CLI/config use mebibytes; 0 means unlimited (None on ScanConfig).
MIB = 1024 * 1024
DEFAULT_MAX_FILE_SIZE_MIB = 5
DEFAULT_MAX_FILE_SIZE = DEFAULT_MAX_FILE_SIZE_MIB * MIB
MAX_FILE_SIZE_MIB = 1024

# Thread pool size for file scans. 0 on the CLI means "use CPU count".
MAX_JOBS = 32
MAX_GLOBS = 32
MAX_GLOB_LENGTH = 256

# Hashed baseline JSON uses the key "fingerprint"; still skip the default
# filename so a committed baseline is never scanned as source.
_SKIP_FILENAMES = frozenset(
    {
        ".secret-scanner-baseline.json",
        ".secret-scanner.json",
        ".secret-scanner.yml",
        ".secret-scanner.yaml",
    }
)


@dataclass
class ScanConfig:
    """Runtime knobs for file discovery.

    Change these on an instance rather than editing module constants::

        config = ScanConfig()
        config.exclude_dir("dist")
        config.excluded_extensions.add(".bin")
    """

    excluded_dirs: set[str] = field(
        default_factory=lambda: set(DEFAULT_EXCLUDED_DIRS)
    )
    excluded_extensions: set[str] = field(
        default_factory=lambda: set(DEFAULT_EXCLUDED_EXTENSIONS)
    )
    skip_symlinks: bool = True
    sniff_binary: bool = True
    binary_sniff_bytes: int = BINARY_SNIFF_BYTES
    include_hidden: bool = False
    max_file_size_bytes: int | None = DEFAULT_MAX_FILE_SIZE
    ignore_paths: list[str] = field(default_factory=list)
    ignore_findings: list[tuple[str, str]] = field(default_factory=list)
    baseline_keys: set[tuple[str, str]] = field(default_factory=set)
    jobs: int = 1
    include_globs: list[str] = field(default_factory=list)
    skip_globs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Normalize names so Windows and Linux behave the same."""
        self.excluded_dirs = {name.casefold() for name in self.excluded_dirs}
        normalized_exts: set[str] = set()
        for ext in self.excluded_extensions:
            ext = ext.casefold()
            if not ext.startswith("."):
                ext = f".{ext}"
            normalized_exts.add(ext)
        self.excluded_extensions = normalized_exts

    def exclude_dir(self, name: str) -> None:
        """Skip directories named ``name`` (compared case-insensitively)."""
        self.excluded_dirs.add(name.casefold())


class GlobError(ValueError):
    """Invalid include/skip glob pattern."""


def normalize_glob(pattern: str) -> str:
    """Strip, posix-ify slashes, and reject empty / flag-like / oversized patterns."""
    value = pattern.strip().replace("\\", "/")
    if not value or "\n" in pattern or "\r" in pattern:
        raise GlobError("glob must be a single non-empty pattern")
    if value.startswith("-"):
        raise GlobError("glob must not look like a CLI flag")
    if len(value) > MAX_GLOB_LENGTH:
        raise GlobError("glob is too long")
    return value


def matches_glob(path: Path, pattern: str, *, root: Path | None = None) -> bool:
    """True if ``path`` matches a shell-style glob (case-insensitive).

    A pattern without ``/`` matches the file name only (``*.env`` → ``.env``
    in any folder). A pattern with ``/`` matches the path relative to
    ``root``. ``fnmatch`` is not gitignore: ``*`` in a path pattern can
    match across directories.
    """
    folded = pattern.replace("\\", "/").casefold()
    if "/" not in folded:
        return fnmatch.fnmatch(path.name.casefold(), folded)
    relative = _relative_posix(path, root)
    return fnmatch.fnmatch(relative, folded)


def _relative_posix(path: Path, root: Path | None) -> str:
    posix = path.as_posix().casefold()
    if root is None:
        return posix
    try:
        return path.expanduser().resolve().relative_to(
            root.expanduser().resolve()
        ).as_posix().casefold()
    except ValueError:
        return posix


def passes_glob_filters(
    path: Path, config: ScanConfig, *, root: Path | None = None
) -> bool:
    """Apply skip globs first, then optional include globs."""
    if config.skip_globs and any(
        matches_glob(path, pattern, root=root) for pattern in config.skip_globs
    ):
        return False
    if config.include_globs:
        return any(
            matches_glob(path, pattern, root=root) for pattern in config.include_globs
        )
    return True


def resolve_jobs(requested: int) -> int:
    """Return a worker count in ``1..MAX_JOBS``. ``0`` means CPU count."""
    if requested == 0:
        return min(MAX_JOBS, os.cpu_count() or 1)
    return min(MAX_JOBS, max(1, requested))


def is_excluded_directory(path: Path, config: ScanConfig) -> bool:
    """Return True if this directory name is on the exclude list."""
    return path.name.casefold() in config.excluded_dirs


def _skip_hidden_directory(path: Path, config: ScanConfig) -> bool:
    """Skip ``.github`` / ``.vscode`` unless ``--include-hidden`` is set.

    Hidden *files* such as ``.env`` are still scanned; they are not directories.
    ``.git`` and ``.venv`` remain excluded via ``excluded_dirs`` either way.
    """
    if config.include_hidden:
        return False
    name = path.name
    return name.startswith(".") and name not in {".", ".."}


def has_excluded_extension(path: Path, config: ScanConfig) -> bool:
    """Return True if the file suffix is a known binary/archive type."""
    return path.suffix.casefold() in config.excluded_extensions


def looks_like_binary(path: Path, sniff_bytes: int = BINARY_SNIFF_BYTES) -> bool:
    """Heuristic: a NUL byte in the first chunk usually means binary data.

    This is not perfect. UTF-16 text contains NUL bytes and may be skipped.
    That trade-off is acceptable for a first version: we avoid dumping
    images and object files into a text scanner.
    """
    try:
        with path.open("rb") as handle:
            chunk = handle.read(sniff_bytes)
    except OSError:
        # Unreadable files are not scan candidates.
        return True
    return b"\x00" in chunk


def is_oversized_file(path: Path, config: ScanConfig) -> bool:
    """Return True if the file exceeds ``max_file_size_bytes`` (when set)."""
    limit = config.max_file_size_bytes
    if limit is None:
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return True
    return size > limit


def bytes_for_mib(mib: int) -> int | None:
    """Convert a mebibyte count to a byte limit. ``0`` means unlimited."""
    if mib == 0:
        return None
    return mib * MIB


@dataclass
class SkipStats:
    """Files that passed cheaper filters but were not scanned."""

    oversized: int = 0
    binary: int = 0


def should_scan_file(
    path: Path,
    config: ScanConfig,
    *,
    root: Path | None = None,
    stats: SkipStats | None = None,
) -> bool:
    """Return True if this file should be a scan candidate.

    Cheap checks run first (symlink, extension, size) so we do not open a
    multi-gigabyte dump just to sniff the first 8 KB.
    """
    if config.skip_symlinks and path.is_symlink():
        return False
    if not path.is_file():
        return False
    if path.name.casefold() in _SKIP_FILENAMES:
        return False
    if has_excluded_extension(path, config):
        return False
    if not passes_glob_filters(path, config, root=root):
        return False
    if is_oversized_file(path, config):
        _LOG.debug("Skipping oversized file %s", path)
        if stats is not None:
            stats.oversized += 1
        return False
    if config.sniff_binary and looks_like_binary(path, config.binary_sniff_bytes):
        _LOG.debug("Skipping binary file %s", path)
        if stats is not None:
            stats.binary += 1
        return False
    return True


def iter_scan_files(
    root: str | Path,
    config: ScanConfig | None = None,
    *,
    stats: SkipStats | None = None,
) -> Iterator[Path]:
    """Yield absolute paths of files that are eligible for later scanning.

    Directories on the exclude list are not descended into. That is cheaper
    and safer than visiting every file under ``node_modules`` or ``.git``.
    """
    config = config or ScanConfig()
    target = Path(root).expanduser()

    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    target = target.resolve()

    if target.is_file():
        parent = target.parent
        if should_scan_file(target, config, root=parent, stats=stats):
            yield target
        return

    if not target.is_dir():
        return

    # If the user points at an excluded directory, do not walk it.
    if is_excluded_directory(target, config):
        return

    yield from _walk_directory(target, config, root=target, stats=stats)


def _walk_directory(
    directory: Path,
    config: ScanConfig,
    *,
    root: Path,
    stats: SkipStats | None = None,
) -> Iterator[Path]:
    """Recursively walk one directory using pathlib, not os.walk."""
    try:
        children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
    except OSError as exc:
        _LOG.error("Unable to read directory %s: %s", directory, exc.strerror or exc)
        return

    for child in children:
        if config.skip_symlinks and child.is_symlink():
            continue

        try:
            is_dir = child.is_dir()
            is_file = child.is_file()
        except OSError as exc:
            _LOG.error("Unable to read path %s: %s", child, exc.strerror or exc)
            continue

        if is_dir:
            if is_excluded_directory(child, config):
                continue
            if _skip_hidden_directory(child, config):
                continue
            yield from _walk_directory(child, config, root=root, stats=stats)
        elif is_file:
            if should_scan_file(child, config, root=root, stats=stats):
                yield child.resolve()
