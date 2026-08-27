"""Shared data models.

PHASE 3 introduces pattern-related models only. Scan findings
(SecretFinding / ScanResult) arrive in a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
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
