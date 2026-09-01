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


class ActionConfigError(ValueError):
    """Invalid composite-action input (exit 2)."""


def argv_from_env(env: Mapping[str, str]) -> list[str]:
    """Translate action env into ``run()`` argv. Always includes ``--no-color``."""
    raw_path = env.get("SECRET_SCANNER_PATH", ".")
    target = raw_path.strip()
    if not target or "\n" in raw_path or "\r" in raw_path:
        raise ActionConfigError("path must be a single non-empty line")
    if target.startswith("-"):
        raise ActionConfigError("path must not look like a CLI flag")

    hidden_raw = env.get("SECRET_SCANNER_INCLUDE_HIDDEN", "false").strip().casefold()
    if hidden_raw not in _HIDDEN_TRUE | _HIDDEN_FALSE:
        raise ActionConfigError("include-hidden must be true or false")

    severity = (env.get("SECRET_SCANNER_SEVERITY") or "LOW").strip().upper()
    if severity not in _SEVERITIES:
        raise ActionConfigError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")

    argv = ["--no-color", "--severity", severity, target]
    if hidden_raw in _HIDDEN_TRUE:
        argv.append("--include-hidden")
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
