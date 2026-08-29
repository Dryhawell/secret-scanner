"""Install a local Git pre-commit hook. The hook is not committed; this template is."""

from __future__ import annotations

import os
from pathlib import Path

from scanner.git_mode import git_dir
from utils.logger import get_logger

_LOG = get_logger()

HOOK_NAME = "pre-commit"


class HookError(Exception):
    """Raised when the hook cannot be installed."""


def hook_template_path() -> Path:
    """Committed template: ``hooks/pre-commit`` next to ``main.py``."""
    return Path(__file__).resolve().parent.parent / "hooks" / HOOK_NAME


def install_pre_commit_hook(root: Path, *, force: bool = False) -> Path:
    """Copy the template into ``.git/hooks/pre-commit``. Does not scan."""
    template = hook_template_path()
    if not template.is_file():
        raise HookError(f"Hook template not found: {template}")
    destination = git_dir(root) / "hooks" / HOOK_NAME
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        raise HookError(
            f"Hook already exists: {destination}. Re-run with --force-hook to replace it."
        )
    destination.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        os.chmod(destination, 0o755)
    except OSError:
        pass
    _LOG.info("Installed pre-commit hook at %s", destination)
    return destination
