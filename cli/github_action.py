"""GitHub composite-action entry. Builds a fixed CLI argv from env vars.

Inputs are passed through environment variables (not interpolated into a
shell script) so a hostile ``path`` cannot add extra flags. This module never
enables ``--dashboard``, ``--update-baseline``, or Git scan modes.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cli.interface import run

_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_HIDDEN_TRUE = frozenset({"true", "1", "yes"})
_HIDDEN_FALSE = frozenset({"false", "0", "no", ""})
_DEFAULT_SARIF_FILE = "secret-scanner.sarif"
_MAX_SARIF_PATH = 256


class ActionConfigError(ValueError):
    """Invalid composite-action input (exit 2)."""


def _flag_from_env(env: Mapping[str, str], key: str, *, label: str) -> bool:
    raw = env.get(key, "false").strip().casefold()
    if raw not in _HIDDEN_TRUE | _HIDDEN_FALSE:
        raise ActionConfigError(f"{label} must be true or false")
    return raw in _HIDDEN_TRUE


def relative_sarif_path(raw: str) -> str:
    """Return a workspace-relative ``*.sarif`` path, or raise ActionConfigError."""
    text = raw.strip()
    if not text or "\n" in raw or "\r" in raw:
        raise ActionConfigError("sarif-file must be a single non-empty line")
    if len(text) > _MAX_SARIF_PATH:
        raise ActionConfigError("sarif-file path is too long")
    if text.startswith("-"):
        raise ActionConfigError("sarif-file must not look like a CLI flag")
    path = Path(text)
    if path.is_absolute() or bool(path.anchor):
        raise ActionConfigError("sarif-file must be a relative path")
    if any(part == ".." for part in path.parts):
        raise ActionConfigError("sarif-file must not contain ..")
    if path.suffix.casefold() != ".sarif":
        raise ActionConfigError("sarif-file must end with .sarif")
    return path.as_posix()


def argv_from_env(env: Mapping[str, str]) -> list[str]:
    """Translate action env into ``run()`` argv. Always includes ``--no-color``."""
    raw_path = env.get("SECRET_SCANNER_PATH", ".")
    target = raw_path.strip()
    if not target or "\n" in raw_path or "\r" in raw_path:
        raise ActionConfigError("path must be a single non-empty line")
    if target.startswith("-"):
        raise ActionConfigError("path must not look like a CLI flag")

    hidden = _flag_from_env(env, "SECRET_SCANNER_INCLUDE_HIDDEN", label="include-hidden")

    severity = (env.get("SECRET_SCANNER_SEVERITY") or "LOW").strip().upper()
    if severity not in _SEVERITIES:
        raise ActionConfigError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")

    argv = ["--no-color", "--severity", severity, target]
    fail_on = (env.get("SECRET_SCANNER_FAIL_ON_SEVERITY") or "").strip().upper()
    if fail_on:
        if fail_on not in _SEVERITIES:
            raise ActionConfigError(
                "fail-on-severity must be LOW, MEDIUM, HIGH, or CRITICAL"
            )
        argv.extend(["--fail-on-severity", fail_on])
    if hidden:
        argv.append("--include-hidden")
    if _flag_from_env(env, "SECRET_SCANNER_QUIET", label="quiet"):
        argv.append("--quiet")
    if _flag_from_env(env, "SECRET_SCANNER_SARIF", label="sarif"):
        sarif_file = relative_sarif_path(
            env.get("SECRET_SCANNER_SARIF_FILE", _DEFAULT_SARIF_FILE)
        )
        argv.extend(["--sarif-file", sarif_file])
    return argv


def main(
    env: Mapping[str, str] | None = None,
    *,
    reports_dir: Path | None = None,
    log_file: Path | None = None,
) -> int:
    """Validate env and run a working-tree scan. Returns the CLI exit code."""
    mapping = os.environ if env is None else env
    try:
        argv = argv_from_env(mapping)
    except ActionConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return run(argv, reports_dir=reports_dir, log_file=log_file)


if __name__ == "__main__":
    sys.exit(main())
