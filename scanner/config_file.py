"""Project config file (``.secret-scanner.json`` / ``.yml``).

Runtime stays the standard library: JSON via ``json``, YAML via a
documented subset (no anchors, no tags, no PyYAML). CLI flags override
file values. Custom regexes extend the built-in catalog; they do not
replace it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from scanner.file_handler import MAX_GLOBS, MAX_GLOB_LENGTH, MAX_JOBS, GlobError, normalize_glob
from scanner.ignore import default_sidecar
from scanner.models import SecretPattern, Severity
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
        "glob",
        "skip_glob",
        "include_hidden",
        "no_color",
        "verbose",
        "quiet",
        "min_confidence",
        "format",
        "ignore_file",
        "baseline",
        "patterns",
        "skip_patterns",
        "jobs",
    }
)
_PATTERN_KEYS = frozenset(
    {
        "name",
        "regex",
        "severity",
        "description",
        "ignore_case",
        "value_group",
    }
)
_FORMATS = frozenset({"text", "json", "sarif", "html"})
MAX_CUSTOM_PATTERNS = 32
MAX_CUSTOM_REGEX_LENGTH = 512
MAX_CUSTOM_NAME_LENGTH = 64
MAX_SKIP_PATTERNS = 32
_TRUE = frozenset({"true", "yes", "on"})
_FALSE = frozenset({"false", "no", "off"})


class ConfigError(Exception):
    """Raised when a config file is missing, unreadable, or invalid."""


@dataclass(frozen=True)
class FileSettings:
    """Values loaded from a config file. ``None`` means the key was omitted."""

    severity: str | None = None
    exclude: tuple[str, ...] = ()
    glob: tuple[str, ...] = ()
    skip_glob: tuple[str, ...] = ()
    include_hidden: bool | None = None
    no_color: bool | None = None
    verbose: bool | None = None
    quiet: bool | None = None
    min_confidence: int | None = None
    format: str | None = None
    ignore_file: Path | None = None
    baseline: Path | None = None
    patterns: tuple[SecretPattern, ...] = ()
    skip_patterns: tuple[str, ...] = ()
    jobs: int | None = None


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
    dash lists of strings, and dash lists of flat mappings (custom patterns).
    Not supported: anchors, tags, nested maps beyond one object level,
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


def _parse_dash_list(lines: list[str], index: int) -> tuple[list[object], int]:
    items: list[object] = []
    list_indent: int | None = None
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
        if indent == 0 and not body.startswith("- "):
            break
        if not body.startswith("- "):
            raise ConfigError(f"Expected list item '- value': {body}")
        if list_indent is None:
            list_indent = indent
        if indent != list_indent:
            raise ConfigError("List items must share the same indent.")
        payload = body[2:].strip()
        if not payload:
            raise ConfigError("Empty list item.")
        if _looks_like_mapping_entry(payload):
            key, _, rest = payload.partition(":")
            key = key.strip()
            rest = rest.strip()
            if not key:
                raise ConfigError("Config key is empty.")
            if not rest:
                raise ConfigError(f"Empty value for {key}")
            mapping: dict[str, object] = {key: _parse_scalar(rest)}
            nested, index = _parse_indented_mapping(
                lines, index + 1, parent_indent=indent
            )
            overlap = set(mapping) & set(nested)
            if overlap:
                raise ConfigError(f"Duplicate config key: {sorted(overlap)[0]}")
            mapping.update(nested)
            items.append(mapping)
        else:
            value = _parse_scalar(payload)
            if not isinstance(value, str):
                raise ConfigError("Config list items must be strings.")
            items.append(value)
            index += 1
    return items, index


def _looks_like_mapping_entry(payload: str) -> bool:
    if payload.startswith(("'", '"')):
        return False
    return ":" in payload


def _parse_indented_mapping(
    lines: list[str], index: int, *, parent_indent: int
) -> tuple[dict[str, object], int]:
    mapping: dict[str, object] = {}
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
        if indent <= parent_indent:
            break
        if body.startswith("- "):
            raise ConfigError("Nested lists inside objects are not supported.")
        if ":" not in body:
            raise ConfigError(f"Expected 'key: value' in config: {body}")
        key, rest = body.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        if not key:
            raise ConfigError("Config key is empty.")
        if key in mapping:
            raise ConfigError(f"Duplicate config key: {key}")
        if not rest:
            raise ConfigError(f"Empty value for {key}")
        mapping[key] = _parse_scalar(rest)
        index += 1
    return mapping, index


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
            raise ConfigError("Config format must be 'text', 'json', 'sarif', or 'html'.")
        format_name = folded
    exclude = _string_list(data, "exclude")
    glob_patterns = _glob_list(data, "glob")
    skip_glob = _glob_list(data, "skip_glob")
    return FileSettings(
        severity=severity,
        exclude=tuple(exclude),
        glob=tuple(glob_patterns),
        skip_glob=tuple(skip_glob),
        include_hidden=_optional_bool(data, "include_hidden"),
        no_color=_optional_bool(data, "no_color"),
        verbose=_optional_bool(data, "verbose"),
        quiet=_optional_bool(data, "quiet"),
        min_confidence=_optional_min_confidence(data, "min_confidence"),
        format=format_name,
        ignore_file=_optional_path(data, "ignore_file", base),
        baseline=_optional_path(data, "baseline", base),
        patterns=_custom_patterns(data),
        skip_patterns=tuple(_skip_pattern_list(data)),
        jobs=_optional_jobs(data, "jobs"),
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


def _glob_list(data: dict[str, object], key: str) -> list[str]:
    values = _string_list(data, key)
    if len(values) > MAX_GLOBS:
        raise ConfigError(f"Config {key} accepts at most {MAX_GLOBS} patterns.")
    normalized: list[str] = []
    for item in values:
        if len(item) > MAX_GLOB_LENGTH:
            raise ConfigError(f"Config {key} pattern is too long.")
        try:
            normalized.append(normalize_glob(item))
        except GlobError as exc:
            raise ConfigError(f"Config {key}: {exc}") from exc
    return normalized


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


def _skip_pattern_list(data: dict[str, object]) -> list[str]:
    values = _string_list(data, "skip_patterns")
    if len(values) > MAX_SKIP_PATTERNS:
        raise ConfigError(
            f"Config skip_patterns accepts at most {MAX_SKIP_PATTERNS} names."
        )
    return values


def _optional_path(data: dict[str, object], key: str, base: Path) -> Path | None:
    raw = _optional_string(data, key)
    if raw is None:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    return path


def _custom_patterns(data: dict[str, object]) -> tuple[SecretPattern, ...]:
    if "patterns" not in data or data["patterns"] is None:
        return ()
    raw = data["patterns"]
    if not isinstance(raw, list):
        raise ConfigError("Config patterns must be a list of objects.")
    if len(raw) > MAX_CUSTOM_PATTERNS:
        raise ConfigError(
            f"Config patterns is limited to {MAX_CUSTOM_PATTERNS} entries."
        )
    reserved = _reserved_pattern_names()
    seen: set[str] = set()
    patterns: list[SecretPattern] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError("Config patterns must be a list of objects.")
        pattern = _custom_pattern_from_mapping(item, reserved | seen, index=index)
        seen.add(pattern.name)
        patterns.append(pattern)
    return tuple(patterns)


def _reserved_pattern_names() -> set[str]:
    from scanner.context import CONTEXTUAL_PATTERN_NAME
    from scanner.patterns import default_patterns

    return {item.name for item in default_patterns()} | {CONTEXTUAL_PATTERN_NAME}


def _custom_pattern_from_mapping(
    data: dict[str, object], taken: set[str], *, index: int
) -> SecretPattern:
    unknown = sorted(set(data) - _PATTERN_KEYS)
    if unknown:
        raise ConfigError(
            "Unknown pattern key(s): "
            + ", ".join(unknown)
            + ". Allowed: "
            + ", ".join(sorted(_PATTERN_KEYS))
        )
    name = _required_string(data, "name")
    if "|" in name or "\n" in name:
        raise ConfigError("Pattern name must not contain '|' or newlines.")
    if len(name) > MAX_CUSTOM_NAME_LENGTH:
        raise ConfigError(
            f"Pattern name must be at most {MAX_CUSTOM_NAME_LENGTH} characters."
        )
    if name in taken:
        raise ConfigError(f"Pattern name already exists: {name}")
    regex = _required_string(data, "regex")
    if len(regex) > MAX_CUSTOM_REGEX_LENGTH:
        raise ConfigError(
            f"Pattern regex must be at most {MAX_CUSTOM_REGEX_LENGTH} characters."
        )
    severity_name = _required_string(data, "severity")
    allowed = {item.value for item in Severity}
    if severity_name not in allowed:
        raise ConfigError(
            f"Invalid pattern severity {severity_name!r}. Expected one of: "
            + ", ".join(item.value for item in Severity)
        )
    description = _optional_string(data, "description") or f"Custom pattern '{name}'"
    ignore_case = _optional_bool(data, "ignore_case") or False
    value_group = _optional_int(data, "value_group")
    flags = re.IGNORECASE if ignore_case else 0
    try:
        compiled = re.compile(regex, flags)
    except re.error as exc:
        raise ConfigError(f"Invalid regex for pattern {name!r}: {exc}") from exc
    if compiled.search(""):
        raise ConfigError(
            f"Pattern {name!r} matches the empty string. "
            "Tighten the regex so it cannot match every line."
        )
    if value_group is not None and value_group > compiled.groups:
        raise ConfigError(
            f"Pattern {name!r} value_group {value_group} is larger than "
            f"the regex group count ({compiled.groups})."
        )
    _LOG.info("Loaded custom pattern %s (index %s)", name, index)
    return SecretPattern(
        name=name,
        regex=regex,
        severity=Severity(severity_name),
        description=description,
        flags=flags,
        value_group=value_group,
    )


def _required_string(data: dict[str, object], key: str) -> str:
    value = _optional_string(data, key)
    if value is None:
        raise ConfigError(f"Pattern is missing {key}.")
    return value


def _optional_min_confidence(data: dict[str, object], key: str) -> int | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"Config {key} must be an integer 0-99.")
    if value < 0 or value > 99:
        raise ConfigError(f"Config {key} must be between 0 and 99.")
    return value


def _optional_jobs(data: dict[str, object], key: str) -> int | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"Config {key} must be an integer 0-{MAX_JOBS}.")
    if value < 0 or value > MAX_JOBS:
        raise ConfigError(
            f"Config {key} must be between 0 and {MAX_JOBS} (0 = auto)."
        )
    return value


def _optional_int(data: dict[str, object], key: str) -> int | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"Config {key} must be a positive integer.")
    if value < 1:
        raise ConfigError(f"Config {key} must be a positive integer.")
    return value


def resolve_config_path(explicit: str | None, target: Path) -> Path | None:
    """Return ``--config`` path, else a default sidecar, else ``None``."""
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"Config file does not exist: {path}")
        return path
    return default_config_file(target)
