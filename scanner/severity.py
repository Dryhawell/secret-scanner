"""Severity policy for secret findings.

Severity is a *triage* label, not a proof that a credential is valid or
exploitable. A CRITICAL finding still needs human review, revoke, and rotate.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Sequence

from scanner.models import SecretFinding, Severity

# Higher rank = more urgent. Used for "minimum severity" filters later (CLI).
RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Display order: CRITICAL first.
SORT_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# Single source of truth. Adding a pattern without an entry here is an error.
PATTERN_SEVERITY: dict[str, Severity] = {
    # CRITICAL: material that typically means "assume compromise".
    "AWS Access Key ID": Severity.CRITICAL,
    "Private Key": Severity.CRITICAL,
    # HIGH: tokens and keys that grant API or data access.
    "GitHub Token": Severity.HIGH,
    "GitHub Fine-Grained Token": Severity.HIGH,
    "Google API Key": Severity.HIGH,
    "Stripe API Key": Severity.HIGH,
    "JWT": Severity.HIGH,
    "Generic API Key": Severity.HIGH,
    "Database Connection String": Severity.HIGH,
    # MEDIUM: likely credentials, but often placeholders or local secrets.
    "Generic Password": Severity.MEDIUM,
}


def severity_for(pattern_name: str) -> Severity:
    """Return the policy severity for a pattern name."""
    try:
        return PATTERN_SEVERITY[pattern_name]
    except KeyError as exc:
        raise KeyError(
            f"No severity policy for pattern {pattern_name!r}. "
            "Add it to PATTERN_SEVERITY in scanner/severity.py."
        ) from exc


def rank(severity: Severity) -> int:
    """Numeric rank; CRITICAL is highest."""
    return RANK[severity]


def meets_minimum(severity: Severity, minimum: Severity) -> bool:
    """Return True if ``severity`` is at least ``minimum`` (inclusive)."""
    return rank(severity) >= rank(minimum)


def sort_findings(
    findings: Sequence[SecretFinding],
    location_of: Callable[[SecretFinding], str],
) -> list[SecretFinding]:
    """Sort findings: CRITICAL first, then path, then line."""
    return sorted(
        findings,
        key=lambda item: (
            SORT_ORDER[item.severity],
            location_of(item),
            item.line_number,
        ),
    )


def count_by_severity(findings: Iterable[SecretFinding]) -> dict[Severity, int]:
    """Count findings per severity, including zeros for unused levels."""
    tallies = Counter(item.severity for item in findings)
    return {level: tallies.get(level, 0) for level in Severity}


def format_severity_counts(counts: dict[Severity, int]) -> str:
    """Compact summary such as ``CRITICAL=1  HIGH=4  MEDIUM=2  LOW=0``."""
    return "  ".join(f"{level.value}={counts[level]}" for level in Severity)
