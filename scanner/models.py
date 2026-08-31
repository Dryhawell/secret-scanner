"""Shared data models for patterns, findings, and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
import re


class Severity(StrEnum):
    """Triage label. Policy lives in scanner.severity, not on this enum."""

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
    ``confidence`` is detection confidence (0–99), never a proof of exploitability.
    """

    file_path: Path
    line_number: int
    secret_type: str
    severity: Severity
    masked_value: str
    description: str
    pattern_name: str
    timestamp: datetime = field(default_factory=_utc_now)
    confidence: int = 0
    fingerprint: str = ""
    commit: str = ""

    def display_path(self, root: Path | None = None) -> str:
        """Return a posix path, relative to ``root`` when possible."""
        path = self.file_path
        if root is not None:
            try:
                path = path.resolve().relative_to(root.expanduser().resolve())
            except ValueError:
                pass
        return path.as_posix()

    def location(self, root: Path | None = None) -> str:
        """Return ``path:line``, or ``commit:path:line`` in history mode."""
        path = self.display_path(root)
        if self.commit:
            return f"{self.commit[:12]}:{path}:{self.line_number}"
        return f"{path}:{self.line_number}"

    def to_dict(self, root: Path | None = None) -> dict[str, object]:
        """JSON-safe view. Never includes the plaintext secret."""
        return {
            "file_path": (
                self.display_path(root) if root is not None else self.file_path.as_posix()
            ),
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "masked_value": self.masked_value,
            "description": self.description,
            "pattern_name": self.pattern_name,
            "fingerprint": self.fingerprint,
            "commit": self.commit,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class ScanResult:
    """Complete outcome of one scan run."""

    target: Path
    started_at: datetime
    finished_at: datetime
    files_scanned: int
    lines_scanned: int
    findings: tuple[SecretFinding, ...]
    placeholders_ignored: int = 0
    allowlist_ignored: int = 0
    baseline_ignored: int = 0

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def scan_time(self) -> datetime:
        """Alias used later in JSON reports."""
        return self.started_at

    def to_dict(self, root: Path | None = None) -> dict[str, object]:
        """JSON-safe scan summary. Finding values stay masked."""
        return {
            "target": str(self.target),
            "scan_time": self.scan_time.isoformat(),
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "findings_count": self.findings_count,
            "placeholders_ignored": self.placeholders_ignored,
            "allowlist_ignored": self.allowlist_ignored,
            "baseline_ignored": self.baseline_ignored,
            "findings": [item.to_dict(root=root) for item in self.findings],
        }
