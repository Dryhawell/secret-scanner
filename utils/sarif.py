"""SARIF 2.1.0 reports for GitHub Code Scanning and similar UIs.

The document never includes plaintext secrets or source-line snippets.
A snippet would copy the original line — and the credential — into
the code scanning API. Messages use the masked value only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from scanner.models import ScanResult, SecretFinding, Severity
from scanner.version import __version__
from utils.reporter import DEFAULT_REPORTS_DIR, default_report_path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Secret Scanner"
INFORMATION_URI = "https://github.com/Dryhawell/secret-scanner"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}
_ID_PARTS = re.compile(r"[A-Za-z0-9]+")


def rule_id(pattern_name: str) -> str:
    """Stable SARIF ruleId: letters and digits from the pattern name."""
    parts = _ID_PARTS.findall(pattern_name)
    slug = "-".join(parts)[:64]
    return slug or "pattern"


def build_sarif(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> dict[str, object]:
    """Return a SARIF 2.1.0 object. Never includes plaintext secrets."""
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in findings:
        rid = rule_id(finding.pattern_name)
        if rid not in rules:
            rules[rid] = _rule(finding, rid)
        uri = finding.display_path(target)
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL[finding.severity],
                "message": {
                    "text": (
                        f"Potential {finding.pattern_name} "
                        f"(masked: {finding.masked_value})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": finding.line_number},
                        }
                    }
                ],
                "partialFingerprints": {
                    "secretFingerprint/v1": finding.fingerprint,
                },
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "maskedValue": finding.masked_value,
                    "commit": finding.commit,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "filesScanned": result.files_scanned,
                    "filesSkippedOversized": result.files_skipped_oversized,
                    "filesSkippedBinary": result.files_skipped_binary,
                },
            }
        ],
    }


def _rule(finding: SecretFinding, rid: str) -> dict[str, object]:
    return {
        "id": rid,
        "name": finding.pattern_name,
        "shortDescription": {"text": finding.pattern_name},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "help": {
            "text": (
                "A potential leaked credential. Rotate the secret if it is "
                "real. This report stores a masked value only."
            )
        },
        "properties": {
            "tags": ["security", "external/cwe/cwe-798"],
            "precision": "medium",
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def dumps_sarif(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> str:
    """Return pretty-printed SARIF text ending with a newline."""
    return json.dumps(build_sarif(result, findings, target), indent=2) + "\n"


def write_sarif_report(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
    output: Path | None = None,
    reports_dir: Path | None = None,
) -> Path:
    """Write a SARIF file and return the path that was written."""
    directory = reports_dir or DEFAULT_REPORTS_DIR
    path = (
        Path(output)
        if output is not None
        else default_report_path(result.scan_time, directory=directory, suffix=".sarif")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_sarif(result, findings, target), encoding="utf-8")
    return path
