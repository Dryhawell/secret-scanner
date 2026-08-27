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
