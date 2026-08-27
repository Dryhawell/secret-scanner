"""Secret Scanner entry point.

Detected values are printed in masked form only. A full argparse CLI arrives later.
"""

from __future__ import annotations

import sys
from pathlib import Path

from scanner import Scanner
from scanner.models import SecretFinding
from scanner.severity import count_by_severity, format_severity_counts, sort_findings


def _print_finding(finding: SecretFinding, target: Path) -> None:
    print(finding.severity.value)
    print(finding.location(root=target))
    print(finding.secret_type)
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
        result = scanner.scan(target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 2

    findings = sort_findings(
        result.findings,
        location_of=lambda item: item.location(root=target),
    )
    counts = count_by_severity(findings)

    print("Secret Scanner")
    print()
    print(f"Target: {target}")
    print()
    print(f"Files scanned: {result.files_scanned}")
    print(f"Lines scanned: {result.lines_scanned:,}")
    print(f"Potential secrets found: {result.findings_count}")
    print(f"Placeholders ignored: {result.placeholders_ignored}")
    print(f"By severity: {format_severity_counts(counts)}")
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
