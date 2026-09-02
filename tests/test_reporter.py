"""JSON reporter tests. All secrets are constructed fakes."""

import json
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import ScanResult, SecretFinding, Severity
from scanner.scanner import Scanner
from utils.reporter import default_report_path, dumps_report, write_json_report


def _finding(tmp_path: Path) -> SecretFinding:
    return SecretFinding(
        file_path=tmp_path / "config.py",
        line_number=3,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        masked_value="AKIA****************",
        description="test",
        pattern_name="AWS Access Key ID",
        confidence=90,
    )


def test_default_report_path_matches_spec_shape() -> None:
    when = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
    path = default_report_path(when, directory=Path("reports"))
    assert path.as_posix() == "reports/scan_2026-08-27_1200.json"


def test_json_payload_has_required_keys_and_masked_values(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    finding = _finding(tmp_path)
    result = ScanResult(
        target=tmp_path,
        started_at=now,
        finished_at=now,
        files_scanned=1,
        lines_scanned=3,
        findings=(finding,),
    )
    payload = json.loads(dumps_report(result, [finding], tmp_path))
    assert payload["files_scanned"] == 1
    assert payload["files_skipped_oversized"] == 0
    assert payload["files_skipped_binary"] == 0
    assert payload["findings_count"] == 1
    assert "scan_time" in payload
    assert payload["findings"][0]["masked_value"] == "AKIA****************"
    assert payload["findings"][0]["line_number"] == 3
    assert "*" in payload["findings"][0]["masked_value"]


def test_write_json_report_creates_file_without_plaintext(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    result = Scanner().scan(tmp_path)
    reports = tmp_path / "out"
    path = write_json_report(
        result,
        list(result.findings),
        tmp_path,
        reports_dir=reports,
    )
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    assert path.parent == reports
    assert path.name.startswith("scan_")
    assert path.suffix == ".json"
    assert aws not in text
    assert "masked_value" in data["findings"][0]
    assert data["findings_count"] == result.findings_count
