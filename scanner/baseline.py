"""Hashed finding baseline. Records never include plaintext secrets.

A baseline answers: "we already triaged this exact value in this file."
A new secret in the same file, or the same value copied to another file,
is still reported. Path allowlist (``.secret-scanner-ignore``) is separate:
it skips whole files and will hide *new* keys in those paths.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanner.ignore import default_sidecar, relative_posix
from scanner.models import SecretFinding
from utils.logger import get_logger

_LOG = get_logger()

DEFAULT_BASELINE_NAME = ".secret-scanner-baseline.json"
BASELINE_VERSION = 1


class BaselineError(Exception):
    """Raised when a baseline file is missing or invalid."""


def default_baseline_file(target: Path) -> Path | None:
    """Return ``.secret-scanner-baseline.json`` next to ``target`` if present."""
    return default_sidecar(target, DEFAULT_BASELINE_NAME)


def load_baseline(path: Path) -> set[tuple[str, str]]:
    """Return ``{(relative_path, fingerprint), ...}``. Paths are casefolded."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"Unable to read baseline file: {path}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Baseline file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise BaselineError(f"Baseline file must be a JSON object: {path}")
    records = payload.get("records", [])
    if not isinstance(records, list):
        raise BaselineError(f"Baseline 'records' must be a list: {path}")
    keys: set[tuple[str, str]] = set()
    for item in records:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("path", "")).replace("\\", "/").strip()
        digest = str(item.get("fingerprint", "")).strip()
        if rel and digest:
            keys.add((rel.casefold(), digest))
    _LOG.info("Loaded baseline %s (%s record(s))", path, len(keys))
    return keys


def finding_key(finding: SecretFinding, root: Path) -> tuple[str, str]:
    """Return the baseline lookup key for ``finding``."""
    rel = relative_posix(finding.file_path, root).casefold()
    return (rel, finding.fingerprint)


def is_baselined(
    finding: SecretFinding, root: Path, keys: set[tuple[str, str]]
) -> bool:
    """True if this file + hashed secret is already triaged."""
    if not finding.fingerprint or not keys:
        return False
    return finding_key(finding, root) in keys


def records_from_findings(
    findings: list[SecretFinding] | tuple[SecretFinding, ...],
    root: Path,
) -> list[dict[str, str]]:
    """Build JSON records. ``fingerprint`` is a hash, never the secret."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        if not finding.fingerprint:
            continue
        key = finding_key(finding, root)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "path": relative_posix(finding.file_path, root),
                "pattern_name": finding.pattern_name,
                "fingerprint": finding.fingerprint,
                "masked_value": finding.masked_value,
            }
        )
    rows.sort(key=lambda item: (item["path"].casefold(), item["pattern_name"]))
    return rows


def merge_records(
    existing: list[dict[str, str]], incoming: list[dict[str, str]]
) -> list[dict[str, str]]:
    """Union by (path, fingerprint); incoming wins on masked_value/pattern."""
    by_key: dict[tuple[str, str], dict[str, str]] = {}
    for item in existing + incoming:
        rel = str(item.get("path", "")).replace("\\", "/").strip()
        secret = str(item.get("fingerprint", "")).strip()
        if not rel or not secret:
            continue
        normalized = {
            "path": rel,
            "pattern_name": str(item.get("pattern_name", "")),
            "fingerprint": secret,
            "masked_value": str(item.get("masked_value", "")),
        }
        by_key[(rel.casefold(), secret)] = normalized
    merged = list(by_key.values())
    merged.sort(key=lambda item: (item["path"].casefold(), item["pattern_name"]))
    return merged


def write_baseline(
    path: Path,
    findings: list[SecretFinding] | tuple[SecretFinding, ...],
    root: Path,
) -> Path:
    """Merge current findings into ``path``. Never writes plaintext secrets."""
    existing: list[dict[str, str]] = []
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            raw = payload.get("records", [])
            if isinstance(raw, list):
                existing = [item for item in raw if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError):
            existing = []
    records = merge_records(existing, records_from_findings(findings, root))
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"version": BASELINE_VERSION, "records": records}, indent=2) + "\n"
    path.write_text(body, encoding="utf-8")
    _LOG.info("Wrote baseline %s (%s record(s))", path, len(records))
    return path
