"""Unit tests for finding and scan-result models."""

from datetime import datetime, timezone
from pathlib import Path

from scanner.models import ScanResult, SecretFinding, Severity


def test_secret_finding_location_uses_github_style(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "config.py"
    finding = SecretFinding(
        file_path=nested,
        line_number=27,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        masked_value="AKIA****************",
        description="test",
        pattern_name="AWS Access Key ID",
    )
    assert finding.location(root=tmp_path) == "src/config.py:27"


def test_scan_result_findings_count() -> None:
    now = datetime.now(timezone.utc)
    empty = ScanResult(
        target=Path("."),
        started_at=now,
        finished_at=now,
        files_scanned=0,
        lines_scanned=0,
        findings=(),
    )
    assert empty.findings_count == 0


def test_finding_to_dict_has_no_plaintext_field(tmp_path: Path) -> None:
    finding = SecretFinding(
        file_path=tmp_path / "config.py",
        line_number=3,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        masked_value="AKIA****************",
        description="test",
        pattern_name="AWS Access Key ID",
        confidence=90,
    )
    payload = finding.to_dict(root=tmp_path)
    assert "matched_text" not in payload
    assert "fingerprint" in payload
    assert payload["masked_value"] == "AKIA****************"
    assert payload["line_number"] == 3

