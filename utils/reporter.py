"""JSON scan reports.

Reports store *masked* values only. Default files land in ``reports/``
and are gitignored so a scan of your own tree cannot commit findings.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scanner.models import ScanResult, SecretFinding

DEFAULT_REPORTS_DIR = Path("reports")


def default_report_path(
    when: datetime,
    directory: Path = DEFAULT_REPORTS_DIR,
) -> Path:
    """Return ``reports/scan_YYYY-MM-DD_HHMM.json`` (seconds if that file exists)."""
    directory = Path(directory)
    stamped = directory / f"scan_{when.strftime('%Y-%m-%d_%H%M')}.json"
    if not stamped.exists():
        return stamped
    return directory / f"scan_{when.strftime('%Y-%m-%d_%H%M%S')}.json"


def build_payload(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> dict[str, object]:
    """Build a JSON-serializable dict. Never includes plaintext secrets."""
    payload = result.to_dict(root=target)
    payload["findings"] = [item.to_dict(root=target) for item in findings]
    payload["findings_count"] = len(findings)
    return payload


def dumps_report(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> str:
    """Return pretty-printed JSON text ending with a newline."""
    return json.dumps(build_payload(result, findings, target), indent=2) + "\n"


def write_json_report(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
    output: Path | None = None,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> Path:
    """Write a JSON report and return the path that was written."""
    path = Path(output) if output is not None else default_report_path(
        result.scan_time, directory=reports_dir
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_report(result, findings, target), encoding="utf-8")
    return path
