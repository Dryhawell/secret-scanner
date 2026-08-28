"""File selection helpers for directory scanning.

This module decides *which* paths are scan candidates. It does not look
for secrets. Secret detection is a later phase.

Why this split exists:
    Walking the filesystem and matching regexes are different jobs. File
    discovery must stay cheap, predictable, and easy to test on its own.
"""

from __future__ import annotations

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


@dataclass
class ScanConfig:
    """Runtime knobs for file discovery.

    Change these on an instance rather than editing module constants::

        config = ScanConfig()
        config.excluded_dirs.add("dist")
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


def should_scan_file(path: Path, config: ScanConfig) -> bool:
    """Return True if this file should be a scan candidate."""
    if config.skip_symlinks and path.is_symlink():
        return False
    if not path.is_file():
        return False
    if has_excluded_extension(path, config):
        return False
    if config.sniff_binary and looks_like_binary(path, config.binary_sniff_bytes):
        return False
    return True


def iter_scan_files(root: str | Path, config: ScanConfig | None = None) -> Iterator[Path]:
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
        if should_scan_file(target, config):
            yield target
        return

    if not target.is_dir():
        return

    # If the user points at an excluded directory, do not walk it.
    if is_excluded_directory(target, config):
        return

    yield from _walk_directory(target, config)


def _walk_directory(directory: Path, config: ScanConfig) -> Iterator[Path]:
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
            yield from _walk_directory(child, config)
        elif is_file:
            if should_scan_file(child, config):
                yield child.resolve()
