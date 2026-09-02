"""HTML reporter tests. All secrets are constructed fakes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cli.interface import run
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.scanner import Scanner
from utils.html_report import render_html, write_html_report


def test_html_escapes_markup(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    finding = SecretFinding(
        file_path=tmp_path / "config.py",
        line_number=3,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        masked_value="AKIA****************",
        description="test",
        pattern_name="<script>alert(1)</script>",
        confidence=90,
    )
    result = ScanResult(
        target=tmp_path,
        started_at=now,
        finished_at=now,
        files_scanned=1,
        lines_scanned=3,
        findings=(finding,),
    )
    page = render_html(result, [finding], tmp_path)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "AKIA****************" in page


def test_html_empty_state(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    result = ScanResult(
        target=tmp_path,
        started_at=now,
        finished_at=now,
        files_scanned=1,
        lines_scanned=1,
        findings=(),
    )
    page = render_html(result, [], tmp_path)
    assert "No potential secrets found." in page
    assert "Oversize skipped" in page


def test_write_html_omits_plaintext(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    result = Scanner().scan(tmp_path)
    path = write_html_report(
        result,
        list(result.findings),
        tmp_path,
        reports_dir=tmp_path / "out",
    )
    text = path.read_text(encoding="utf-8")
    assert path.suffix == ".html"
    assert aws not in text
    assert "AWS_ACCESS_KEY_ID" not in text
    assert "<!DOCTYPE html>" in text


def test_cli_format_html_writes_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "scan.html"
    code = run(
        ["--no-color", "--format", "html", "--output", str(report), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    text = report.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text
    assert "No potential secrets found." in text


def test_cli_infers_html_from_output_suffix(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "out.html"
    code = run(
        ["--no-color", "--output", str(report), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    assert "<!DOCTYPE html>" in report.read_text(encoding="utf-8")
