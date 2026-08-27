"""Secret detection: apply compiled patterns to file contents.

Reads files line by line, asks PatternEngine for hits, and stores *masked*
values only. False positives, context, and confidence arrive later.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scanner.models import SecretFinding
from scanner.patterns import PatternEngine

# Lines longer than this are skipped. A minified 5 MB line can freeze a regex
# and would load a huge string into memory anyway.
DEFAULT_MAX_LINE_LENGTH = 100_000


def mask_secret(value: str, visible_prefix: int = 4) -> str:
    """Return a redacted form of ``value`` for display and reports.

    Short values are fully starred so a 6-character password cannot be
    reconstructed from the prefix. Longer values keep a small prefix so a
    human can still recognise the secret *type*.
    """
    if not value:
        return ""
    if len(value) <= visible_prefix * 2:
        return "*" * len(value)
    return value[:visible_prefix] + ("*" * (len(value) - visible_prefix))


@dataclass(frozen=True)
class FileScan:
    """Findings plus how many physical lines were visited in one file."""

    findings: tuple[SecretFinding, ...]
    lines_scanned: int


class Detector:
    """Scan a single file or a single line for secret patterns."""

    def __init__(
        self,
        engine: PatternEngine | None = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    ) -> None:
        self.engine = engine or PatternEngine()
        self.max_line_length = max_line_length

    def scan_line(self, line: str, file_path: Path, line_number: int) -> list[SecretFinding]:
        """Return findings for one line. The line itself is not stored."""
        if len(line) > self.max_line_length:
            return []

        findings: list[SecretFinding] = []
        for match in self.engine.find_in_text(line):
            findings.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=match.pattern_name,
                    severity=match.severity,
                    masked_value=mask_secret(match.matched_text),
                    description=match.description,
                    pattern_name=match.pattern_name,
                )
            )
        return findings

    def scan_file(self, path: Path) -> FileScan:
        """Read ``path`` line by line. Unreadable files yield an empty result."""
        findings: list[SecretFinding] = []
        lines_scanned = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    lines_scanned = line_number
                    findings.extend(
                        self.scan_line(line.rstrip("\n"), path, line_number)
                    )
        except OSError:
            return FileScan(findings=(), lines_scanned=0)
        return FileScan(findings=tuple(findings), lines_scanned=lines_scanned)
