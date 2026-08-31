"""SARIF reporter tests. All secrets are constructed fakes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cli.interface import run
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.scanner import Scanner
from utils.sarif import build_sarif, dumps_sarif, rule_id, write_sarif_report


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
        fingerprint="abc123",
    )


def test_rule_id_is_stable() -> None:
    assert rule_id("AWS Access Key ID") == "AWS-Access-Key-ID"
    assert rule_id("Contextual Secret") == "Contextual-Secret"


def test_sarif_document_has_schema_and_no_snippet(tmp_path: Path) -> None:
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
    payload = build_sarif(result, [finding], tmp_path)
    assert payload["version"] == "2.1.0"
    run0 = payload["runs"][0]
    assert run0["tool"]["driver"]["name"] == "Secret Scanner"
    hit = run0["results"][0]
    assert hit["ruleId"] == "AWS-Access-Key-ID"
    assert hit["level"] == "error"
    assert hit["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert "snippet" not in json.dumps(payload)
    assert "AKIA****************" in hit["message"]["text"]


def test_write_sarif_omits_plaintext(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    result = Scanner().scan(tmp_path)
    reports = tmp_path / "out"
    path = write_sarif_report(
        result,
        list(result.findings),
        tmp_path,
        reports_dir=reports,
    )
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    assert path.suffix == ".sarif"
    assert aws not in text
    assert "snippet" not in text
    assert data["runs"][0]["results"]
    dumps_sarif(result, list(result.findings), tmp_path)


def test_cli_format_sarif_writes_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "scan.sarif"
    code = run(
        ["--no-color", "--format", "sarif", "--output", str(report), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"] == []


def test_cli_infers_sarif_from_output_suffix(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "out.sarif"
    code = run(
        ["--no-color", "--output", str(report), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
