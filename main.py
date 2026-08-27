"""Secret Scanner entry point.

PHASE 4 runs detection on discovered files. A full argparse CLI arrives later.
Detected values are printed in masked form only.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scanner import Scanner
from scanner.detector import Detection
from scanner.models import Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _display_path(path: Path, target: Path) -> str:
    try:
        resolved_target = target.expanduser().resolve()
        return path.resolve().relative_to(resolved_target).as_posix()
    except ValueError:
        return path.as_posix()


def _print_finding(finding: Detection, target: Path) -> None:
    location = _display_path(finding.file_path, target)
    print(finding.severity.value)
    print(f"{location}:{finding.line_number}")
    print(finding.pattern_name)
    print(finding.masked_value)
    print()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("Secret Scanner")
        print("Usage: python main.py <path>")
        return 2

    target = Path(args[0])
    scanner = Scanner()

    try:
        summary = scanner.scan(target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 2

    findings = sorted(
        summary.findings,
        key=lambda item: (
            _SEVERITY_ORDER[item.severity],
            _display_path(item.file_path, target),
            item.line_number,
        ),
    )

    print("Secret Scanner")
    print()
    print(f"Target: {target}")
    print()
    print(f"Files scanned: {summary.files_scanned}")
    print(f"Potential secrets found: {summary.findings_count}")
    print()

    if findings:
        for finding in findings:
            _print_finding(finding, target)
        print("Scan completed.")
        return 1

    print("Scan completed.")
    print("No potential secrets found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
