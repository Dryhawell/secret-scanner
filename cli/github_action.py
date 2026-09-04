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
from scanner.confidence import MAX_CONFIDENCE
from scanner.config_file import MAX_SKIP_PATTERNS
from scanner.file_handler import (
    MAX_FILE_SIZE_MIB,
    MAX_GLOBS,
    MAX_JOBS,
    GlobError,
    normalize_glob,
)

_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_HIDDEN_TRUE = frozenset({"true", "1", "yes"})
_HIDDEN_FALSE = frozenset({"false", "0", "no", ""})
_FILE_FORMATS = frozenset({"json", "html", "sarif"})
_ALL_FORMATS = _FILE_FORMATS | {"text"}
_DEFAULT_OUTPUT = {
    "json": "secret-scanner.json",
    "html": "secret-scanner.html",
    "sarif": "secret-scanner.sarif",
}
_FORMAT_SUFFIX = {
    "json": ".json",
    "html": ".html",
    "sarif": ".sarif",
}
_DEFAULT_SARIF_FILE = "secret-scanner.sarif"
_MAX_REPORT_PATH = 256
_MAX_PATTERN_NAME = 128
_CONFIG_SUFFIXES = frozenset({".json", ".yml", ".yaml"})


class ActionConfigError(ValueError):
    """Invalid composite-action input (exit 2)."""


def _max_file_size_from_env(env: Mapping[str, str]) -> int | None:
    """Parse max-file-size mebibytes. Empty/missing means omit (CLI default 5)."""
    raw = env.get("SECRET_SCANNER_MAX_FILE_SIZE", "")
    text = raw.strip()
    if not text:
        return None
    if "\n" in raw or "\r" in raw:
        raise ActionConfigError("max-file-size must be a single line")
    try:
        value = int(text)
    except ValueError as exc:
        raise ActionConfigError("max-file-size must be an integer") from exc
    if value < 0 or value > MAX_FILE_SIZE_MIB:
        raise ActionConfigError(
            f"max-file-size must be between 0 and {MAX_FILE_SIZE_MIB} (0 = unlimited)"
        )
    return value


def _min_confidence_from_env(env: Mapping[str, str]) -> int | None:
    """Parse min-confidence. Empty/missing means omit (CLI default 0)."""
    raw = env.get("SECRET_SCANNER_MIN_CONFIDENCE", "")
    text = raw.strip()
    if not text:
        return None
    if "\n" in raw or "\r" in raw:
        raise ActionConfigError("min-confidence must be a single line")
    try:
        value = int(text)
    except ValueError as exc:
        raise ActionConfigError("min-confidence must be an integer") from exc
    if value < 0 or value > MAX_CONFIDENCE:
        raise ActionConfigError(
            f"min-confidence must be between 0 and {MAX_CONFIDENCE}"
        )
    return value


def _exclude_names_from_env(env: Mapping[str, str]) -> list[str]:
    """Parse directory names (comma or newline separated). Empty means omit."""
    raw = env.get("SECRET_SCANNER_EXCLUDE", "")
    if not raw.strip():
        return []
    names: list[str] = []
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    for line in normalized.split("\n"):
        for piece in line.split(","):
            name = piece.strip()
            if not name:
                continue
            if name.startswith("-"):
                raise ActionConfigError("exclude must not look like a CLI flag")
            if "/" in name or "\\" in name:
                raise ActionConfigError("exclude must be a directory name, not a path")
            if name in {".", ".."}:
                raise ActionConfigError("exclude must be a directory name")
            if len(name) > _MAX_PATTERN_NAME:
                raise ActionConfigError("exclude name is too long")
            names.append(name)
    if len(names) > MAX_SKIP_PATTERNS:
        raise ActionConfigError(
            f"at most {MAX_SKIP_PATTERNS} exclude names are allowed"
        )
    return names


def _jobs_from_env(env: Mapping[str, str]) -> int | None:
    """Parse jobs. Empty/missing means omit (CLI default 1). 0 means auto."""
    raw = env.get("SECRET_SCANNER_JOBS", "")
    text = raw.strip()
    if not text:
        return None
    if "\n" in raw or "\r" in raw:
        raise ActionConfigError("jobs must be a single line")
    try:
        value = int(text)
    except ValueError as exc:
        raise ActionConfigError("jobs must be an integer") from exc
    if value < 0 or value > MAX_JOBS:
        raise ActionConfigError(
            f"jobs must be between 0 and {MAX_JOBS} (0 = auto)"
        )
    return value


def _pattern_names_from_env(
    env: Mapping[str, str], key: str, *, label: str
) -> list[str]:
    """Parse rule names (comma or newline separated). Empty means omit."""
    raw = env.get(key, "")
    if not raw.strip():
        return []
    names: list[str] = []
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    for line in normalized.split("\n"):
        for piece in line.split(","):
            name = piece.strip()
            if not name:
                continue
            if name.startswith("-"):
                raise ActionConfigError(f"{label} must not look like a CLI flag")
            if len(name) > _MAX_PATTERN_NAME:
                raise ActionConfigError(f"{label} name is too long")
            names.append(name)
    if len(names) > MAX_SKIP_PATTERNS:
        raise ActionConfigError(
            f"at most {MAX_SKIP_PATTERNS} {label} names are allowed"
        )
    return names


def _globs_from_env(env: Mapping[str, str], key: str, *, label: str) -> list[str]:
    """Parse glob patterns (comma or newline separated). Empty means omit."""
    raw = env.get(key, "")
    if not raw.strip():
        return []
    patterns: list[str] = []
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    for line in normalized.split("\n"):
        for piece in line.split(","):
            item = piece.strip()
            if not item:
                continue
            try:
                patterns.append(normalize_glob(item))
            except GlobError as exc:
                raise ActionConfigError(f"{label}: {exc}") from exc
    if len(patterns) > MAX_GLOBS:
        raise ActionConfigError(f"at most {MAX_GLOBS} {label} patterns are allowed")
    return patterns


def _flag_from_env(env: Mapping[str, str], key: str, *, label: str) -> bool:
    raw = env.get(key, "false").strip().casefold()
    if raw not in _HIDDEN_TRUE | _HIDDEN_FALSE:
        raise ActionConfigError(f"{label} must be true or false")
    return raw in _HIDDEN_TRUE


def _relative_workspace_path(
    raw: str, *, label: str, suffixes: frozenset[str] | None = None
) -> str:
    """Return a workspace-relative path, or raise ActionConfigError."""
    text = raw.strip()
    if not text or "\n" in raw or "\r" in raw:
        raise ActionConfigError(f"{label} must be a single non-empty line")
    if len(text) > _MAX_REPORT_PATH:
        raise ActionConfigError(f"{label} path is too long")
    if text.startswith("-"):
        raise ActionConfigError(f"{label} must not look like a CLI flag")
    path = Path(text)
    if path.is_absolute() or bool(path.anchor):
        raise ActionConfigError(f"{label} must be a relative path")
    if any(part == ".." for part in path.parts):
        raise ActionConfigError(f"{label} must not contain ..")
    if suffixes is not None and path.suffix.casefold() not in suffixes:
        allowed = " or ".join(sorted(suffixes))
        raise ActionConfigError(f"{label} must end with {allowed}")
    return path.as_posix()


def _relative_report_path(raw: str, *, suffix: str, label: str) -> str:
    """Return a workspace-relative report path, or raise ActionConfigError."""
    return _relative_workspace_path(raw, label=label, suffixes=frozenset({suffix}))


def relative_sarif_path(raw: str) -> str:
    """Return a workspace-relative ``*.sarif`` path, or raise ActionConfigError."""
    return _relative_report_path(raw, suffix=".sarif", label="sarif-file")


def _optional_path_from_env(
    env: Mapping[str, str],
    key: str,
    *,
    label: str,
    suffixes: frozenset[str] | None = None,
) -> str | None:
    """Parse an optional relative path. Empty/missing means omit the flag."""
    raw = env.get(key, "")
    if not raw.strip():
        return None
    return _relative_workspace_path(raw, label=label, suffixes=suffixes)


def _format_from_env(env: Mapping[str, str]) -> str | None:
    """Parse format. Empty or text means omit (CLI default: text report)."""
    raw = env.get("SECRET_SCANNER_FORMAT", "")
    text = raw.strip().casefold()
    if not text:
        return None
    if "\n" in raw or "\r" in raw:
        raise ActionConfigError("format must be a single line")
    if text not in _ALL_FORMATS:
        raise ActionConfigError("format must be text, json, html, or sarif")
    if text == "text":
        return None
    return text


def _output_for_format(env: Mapping[str, str], format_name: str | None) -> str | None:
    """Pair a file format with a relative --output path."""
    raw = env.get("SECRET_SCANNER_OUTPUT", "")
    text = raw.strip()
    if not text:
        if format_name is None:
            return None
        return _DEFAULT_OUTPUT[format_name]
    if format_name is None:
        raise ActionConfigError("output requires format (json, html, or sarif)")
    if text == "-":
        raise ActionConfigError("output must be a file path, not stdout")
    return _relative_report_path(
        raw, suffix=_FORMAT_SUFFIX[format_name], label="output"
    )


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
    max_mib = _max_file_size_from_env(env)
    if max_mib is not None:
        argv.extend(["--max-file-size", str(max_mib)])
    min_conf = _min_confidence_from_env(env)
    if min_conf is not None:
        argv.extend(["--min-confidence", str(min_conf)])
    jobs = _jobs_from_env(env)
    if jobs is not None:
        argv.extend(["--jobs", str(jobs)])
    for name in _pattern_names_from_env(
        env, "SECRET_SCANNER_ONLY_PATTERN", label="only-pattern"
    ):
        argv.extend(["--only-pattern", name])
    for name in _pattern_names_from_env(
        env, "SECRET_SCANNER_SKIP_PATTERN", label="skip-pattern"
    ):
        argv.extend(["--skip-pattern", name])
    for pattern in _globs_from_env(env, "SECRET_SCANNER_GLOB", label="glob"):
        argv.extend(["--glob", pattern])
    for pattern in _globs_from_env(
        env, "SECRET_SCANNER_SKIP_GLOB", label="skip-glob"
    ):
        argv.extend(["--skip-glob", pattern])
    for name in _exclude_names_from_env(env):
        argv.extend(["--exclude", name])
    if hidden:
        argv.append("--include-hidden")
    if _flag_from_env(env, "SECRET_SCANNER_QUIET", label="quiet"):
        argv.append("--quiet")
    if _flag_from_env(env, "SECRET_SCANNER_VERBOSE", label="verbose"):
        argv.append("--verbose")
    format_name = _format_from_env(env)
    output_path = _output_for_format(env, format_name)
    if format_name is not None:
        argv.extend(["--format", format_name, "--output", output_path])
    config_path = _optional_path_from_env(
        env,
        "SECRET_SCANNER_CONFIG",
        label="config",
        suffixes=_CONFIG_SUFFIXES,
    )
    if config_path is not None:
        argv.extend(["--config", config_path])
    ignore_path = _optional_path_from_env(
        env, "SECRET_SCANNER_IGNORE_FILE", label="ignore-file"
    )
    if ignore_path is not None:
        argv.extend(["--ignore-file", ignore_path])
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
