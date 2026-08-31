"""Project config file (``.secret-scanner.json`` / ``.yml``).

Runtime stays the standard library: JSON via ``json``, YAML via a
documented subset (no anchors, no tags, no PyYAML). CLI flags override
file values. Custom regexes are not part of this schema yet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scanner.ignore import default_sidecar
from scanner.models import Severity
from utils.logger import get_logger

_LOG = get_logger()

DEFAULT_CONFIG_JSON = ".secret-scanner.json"
DEFAULT_CONFIG_YAML = ".secret-scanner.yml"
DEFAULT_CONFIG_YAML_ALT = ".secret-scanner.yaml"
DEFAULT_CONFIG_NAMES: tuple[str, ...] = (
    DEFAULT_CONFIG_JSON,
    DEFAULT_CONFIG_YAML,
    DEFAULT_CONFIG_YAML_ALT,
)

_ALLOWED_KEYS = frozenset(
    {
        "severity",
        "exclude",
        "include_hidden",
        "no_color",
        "verbose",
        "format",
        "ignore_file",
        "baseline",
    }
)
_FORMATS = frozenset({"text", "json"})
_TRUE = frozenset({"true", "yes", "on"})
_FALSE = frozenset({"false", "no", "off"})


class ConfigError(Exception):
    """Raised when a config file is missing, unreadable, or invalid."""


@dataclass(frozen=True)
class FileSettings:
    """Values loaded from a config file. ``None`` means the key was omitted."""

    severity: str | None = None
    exclude: tuple[str, ...] = ()
    include_hidden: bool | None = None
    no_color: bool | None = None
    verbose: bool | None = None
    format: str | None = None
    ignore_file: Path | None = None
    baseline: Path | None = None


def default_config_file(target: Path) -> Path | None:
    """Return the first default config next to ``target`` (JSON, then YAML)."""
    for name in DEFAULT_CONFIG_NAMES:
        found = default_sidecar(target, name)
        if found is not None:
            return found
    return None


def load_config_file(path: Path) -> FileSettings:
    """Read ``path`` and return settings. Paths inside are relative to the file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Unable to read config file: {path}") from exc
    suffix = path.suffix.casefold()
    try:
        if suffix == ".json":
            mapping = parse_json_text(text)
        elif suffix in {".yml", ".yaml"}:
            mapping = parse_yaml_text(text)
        else:
            mapping = _parse_unknown_suffix(text)
    except ConfigError:
        raise
    settings = settings_from_mapping(mapping, base=path.parent)
    _LOG.info("Loaded config file %s", path)
    return settings


def _parse_unknown_suffix(text: str) -> dict[str, object]:
    try:
        return parse_json_text(text)
    except ConfigError:
        return parse_yaml_text(text)


def parse_json_text(text: str) -> dict[str, object]:
    """Parse a JSON object. Root must be a mapping."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON config: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("Config root must be an object.")
    return payload


def parse_yaml_text(text: str) -> dict[str, object]:
    """Parse a restricted YAML mapping used by this tool only.

    Supported: ``key: value``, booleans, quoted strings, ``#`` comments,
    and a dash list under a key. Not supported: anchors, tags, nested maps,
    flow collections, multiline scalars.
    """
    mapping: dict[str, object] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            index += 1
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if "\t" in raw.split("#", 1)[0]:
            raise ConfigError("Config YAML must not use tabs.")
        if indent != 0:
            raise ConfigError(f"Unexpected indented line in config: {stripped.strip()}")
        if ":" not in stripped:
            raise ConfigError(f"Expected 'key: value' in config: {stripped.strip()}")
        key, rest = stripped.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if not key:
            raise ConfigError("Config key is empty.")
        if key in mapping:
            raise ConfigError(f"Duplicate config key: {key}")
        if rest:
            mapping[key] = _parse_scalar(rest)
            index += 1
            continue
        items, index = _parse_dash_list(lines, index + 1)
        mapping[key] = items
    return mapping


def _parse_dash_list(lines: list[str], index: int) -> tuple[list[str], int]:
    items: list[str] = []
    while index < len(lines):
        raw = lines[index]
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            index += 1
            continue
        if "\t" in raw.split("#", 1)[0]:
            raise ConfigError("Config YAML must not use tabs.")
        indent = len(stripped) - len(stripped.lstrip(" "))
        body = stripped.lstrip(" ")
        if indent == 0:
            break
        if not body.startswith("- "):
            raise ConfigError(f"Expected list item '- value': {body}")
        value = _parse_scalar(body[2:].strip())
        if not isinstance(value, str):
            raise ConfigError("Config list items must be strings.")
        items.append(value)
        index += 1
    return items, index


def _strip_comment(line: str) -> str:
    """Remove an unquoted ``#`` comment."""
    in_single = False
    in_double = False
    chars: list[str] = []
    for char in line:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            break
        chars.append(char)
    return "".join(chars)


def _parse_scalar(raw: str) -> str | bool:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        return raw[1:-1]
    folded = raw.casefold()
    if folded in _TRUE:
        return True
    if folded in _FALSE:
        return False
    return raw


def settings_from_mapping(data: dict[str, object], *, base: Path) -> FileSettings:
    """Validate a mapping and resolve relative paths against ``base``."""
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(
            "Unknown config key(s): "
            + ", ".join(unknown)
            + ". Allowed: "
            + ", ".join(sorted(_ALLOWED_KEYS))
        )
    severity = _optional_string(data, "severity")
    if severity is not None:
        allowed = {item.value for item in Severity}
        if severity not in allowed:
            raise ConfigError(
                f"Invalid severity {severity!r}. Expected one of: "
                + ", ".join(item.value for item in Severity)
            )
    format_name = _optional_string(data, "format")
    if format_name is not None:
        folded = format_name.casefold()
        if folded not in _FORMATS:
            raise ConfigError("Config format must be 'text' or 'json'.")
        format_name = folded
    exclude = _string_list(data, "exclude")
    return FileSettings(
        severity=severity,
        exclude=tuple(exclude),
        include_hidden=_optional_bool(data, "include_hidden"),
        no_color=_optional_bool(data, "no_color"),
        verbose=_optional_bool(data, "verbose"),
        format=format_name,
        ignore_file=_optional_path(data, "ignore_file", base),
        baseline=_optional_path(data, "baseline", base),
    )


def _optional_string(data: dict[str, object], key: str) -> str | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"Config {key} must be a non-empty string.")
    return value.strip()


def _optional_bool(data: dict[str, object], key: str) -> bool | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, bool):
        raise ConfigError(f"Config {key} must be a boolean.")
    return value


def _string_list(data: dict[str, object], key: str) -> list[str]:
    if key not in data or data[key] is None:
        return []
    value = data[key]
    if not isinstance(value, list):
        raise ConfigError(f"Config {key} must be a list of strings.")
    values: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"Config {key} items must be non-empty strings.")
        values.append(item.strip())
    return values


def _optional_path(data: dict[str, object], key: str, base: Path) -> Path | None:
    raw = _optional_string(data, key)
    if raw is None:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    return path


def resolve_config_path(explicit: str | None, target: Path) -> Path | None:
    """Return ``--config`` path, else a default sidecar, else ``None``."""
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"Config file does not exist: {path}")
        return path
    return default_config_file(target)
