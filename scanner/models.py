"""Shared data models for patterns, findings, and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
import re


class Severity(StrEnum):
    """How urgent a match is. Expanded into a full system in a later phase."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class SecretPattern:
    """One detection rule: a named regex with a default severity."""

    name: str
    regex: str
    severity: Severity
    description: str
    flags: int = 0
    value_group: int | None = None


@dataclass(frozen=True)
class PatternMatch:
    """A regex hit inside a piece of text. Not a final user-facing finding."""

    pattern_name: str
    severity: Severity
    description: str
    matched_text: str
    start: int
    end: int
    compiled_pattern: re.Pattern[str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SecretFinding:
    """One user-facing finding. Never stores the plaintext secret.

    ``line_number`` is 1-based, matching how editors and GitHub show files.
    ``confidence`` is reserved for a later phase; it is not a security verdict.
    """

    file_path: Path
    line_number: int
    secret_type: str
    severity: Severity
    masked_value: str
    description: str
    pattern_name: str
    timestamp: datetime = field(default_factory=_utc_now)
    confidence: float | None = None

    def location(self, root: Path | None = None) -> str:
        """Return ``path:line`` in GitHub-style form, using forward slashes."""
        path = self.file_path
        if root is not None:
            try:
                path = path.resolve().relative_to(root.expanduser().resolve())
            except ValueError:
                pass
        return f"{path.as_posix()}:{self.line_number}"


@dataclass(frozen=True)
class ScanResult:
    """Complete outcome of one scan run."""

    target: Path
    started_at: datetime
    finished_at: datetime
    files_scanned: int
    lines_scanned: int
    findings: tuple[SecretFinding, ...]

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def scan_time(self) -> datetime:
        """Alias used later in JSON reports."""
        return self.started_at
