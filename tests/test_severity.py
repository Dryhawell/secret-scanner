"""Tests for the severity policy. No real secrets are used."""

from pathlib import Path

import pytest

from scanner.models import SecretFinding, Severity
from scanner.patterns import default_patterns
from scanner.severity import (
    PATTERN_SEVERITY,
    count_by_severity,
    format_severity_counts,
    meets_minimum,
    rank,
    severity_for,
    sort_findings,
)


def _finding(name: str, line: int, severity: Severity) -> SecretFinding:
    return SecretFinding(
        file_path=Path("config.py"),
        line_number=line,
        secret_type=name,
        severity=severity,
        masked_value="****",
        description="test",
        pattern_name=name,
    )


def test_every_default_pattern_has_matching_policy() -> None:
    patterns = default_patterns()
    names = {pattern.name for pattern in patterns}
    assert names <= set(PATTERN_SEVERITY)
    for pattern in patterns:
        assert pattern.severity is severity_for(pattern.name)
    assert "Contextual Secret" in PATTERN_SEVERITY


def test_cloud_and_private_key_are_critical() -> None:
    assert severity_for("AWS Access Key ID") is Severity.CRITICAL
    assert severity_for("Private Key") is Severity.CRITICAL


def test_tokens_and_api_keys_are_high() -> None:
    assert severity_for("GitHub Token") is Severity.HIGH
    assert severity_for("Generic API Key") is Severity.HIGH
    assert severity_for("Database Connection String") is Severity.HIGH
    assert severity_for("JWT") is Severity.HIGH


def test_generic_password_is_medium() -> None:
    assert severity_for("Generic Password") is Severity.MEDIUM


def test_unknown_pattern_raises() -> None:
    with pytest.raises(KeyError, match="No severity policy"):
        severity_for("Not A Real Pattern")


def test_meets_minimum_is_inclusive() -> None:
    assert meets_minimum(Severity.CRITICAL, Severity.HIGH)
    assert meets_minimum(Severity.HIGH, Severity.HIGH)
    assert not meets_minimum(Severity.MEDIUM, Severity.HIGH)
    assert not meets_minimum(Severity.LOW, Severity.MEDIUM)


def test_rank_orders_urgency() -> None:
    assert rank(Severity.CRITICAL) > rank(Severity.HIGH) > rank(Severity.MEDIUM) > rank(
        Severity.LOW
    )


def test_sort_findings_puts_critical_first() -> None:
    findings = [
        _finding("Generic Password", 1, Severity.MEDIUM),
        _finding("AWS Access Key ID", 9, Severity.CRITICAL),
        _finding("GitHub Token", 2, Severity.HIGH),
    ]
    ordered = sort_findings(findings, location_of=lambda item: item.location())
    assert [item.severity for item in ordered] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    ]


def test_count_and_format_include_unused_levels() -> None:
    findings = [
        _finding("Private Key", 1, Severity.CRITICAL),
        _finding("GitHub Token", 2, Severity.HIGH),
        _finding("GitHub Token", 3, Severity.HIGH),
    ]
    counts = count_by_severity(findings)
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.MEDIUM] == 0
    assert counts[Severity.LOW] == 0
    assert format_severity_counts(counts) == "CRITICAL=1  HIGH=2  MEDIUM=0  LOW=0"
