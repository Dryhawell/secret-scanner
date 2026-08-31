"""Secret detection: apply compiled patterns to file contents.

Reads files line by line, applies format patterns, then context analysis
for sensitive assignments. Placeholder values and low-entropy generic
strings are dropped. Confidence is a detection score, not a verdict.
Shannon entropy supports scoring; it is never used as a standalone detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scanner.confidence import calculate_confidence
from scanner.context import CONTEXTUAL_PATTERN_NAME, find_context_hits
from scanner.entropy import ENTROPY_GATED_PATTERNS, is_low_entropy
from scanner.filters import is_placeholder
from scanner.fingerprint import secret_id
from scanner.models import SecretFinding
from scanner.patterns import PatternEngine
from scanner.severity import severity_for
from utils.logger import get_logger

_LOG = get_logger()

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


def _already_reported(value: str, kept: set[str]) -> bool:
    """Skip context hits already covered by a format-specific pattern."""
    return any(value == item or value in item or item in value for item in kept)


@dataclass(frozen=True)
class FileScan:
    """Findings plus how many physical lines were visited in one file."""

    findings: tuple[SecretFinding, ...]
    lines_scanned: int
    placeholders_ignored: int = 0


class Detector:
    """Scan a single file or a single line for secret patterns."""

    def __init__(
        self,
        engine: PatternEngine | None = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    ) -> None:
        self.engine = engine or PatternEngine()
        self.max_line_length = max_line_length

    def scan_line(
        self, line: str, file_path: Path, line_number: int, *, commit: str = ""
    ) -> tuple[list[SecretFinding], int]:
        """Return (findings, placeholders_ignored) for one line."""
        if len(line) > self.max_line_length:
            return [], 0

        findings: list[SecretFinding] = []
        ignored = 0
        pattern_matches = self.engine.find_in_text(line)
        kept_values: set[str] = set()

        for match in pattern_matches:
            if is_placeholder(match.matched_text):
                ignored += 1
                continue
            if (
                match.pattern_name in ENTROPY_GATED_PATTERNS
                and is_low_entropy(match.matched_text)
            ):
                ignored += 1
                continue
            kept_values.add(match.matched_text)
            findings.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=match.pattern_name,
                    severity=match.severity,
                    masked_value=mask_secret(match.matched_text),
                    description=match.description,
                    pattern_name=match.pattern_name,
                    confidence=calculate_confidence(
                        match.pattern_name, match.matched_text, line
                    ),
                    fingerprint=secret_id(match.pattern_name, match.matched_text),
                    commit=commit,
                )
            )

        for hit in find_context_hits(line):
            if is_placeholder(hit.value):
                ignored += 1
                continue
            if is_low_entropy(hit.value):
                ignored += 1
                continue
            if _already_reported(hit.value, kept_values):
                continue
            kept_values.add(hit.value)
            findings.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=CONTEXTUAL_PATTERN_NAME,
                    severity=severity_for(CONTEXTUAL_PATTERN_NAME),
                    masked_value=mask_secret(hit.value),
                    description=(
                        f"Sensitive assignment to {hit.identifier!r} "
                        "without a known vendor-specific secret format."
                    ),
                    pattern_name=CONTEXTUAL_PATTERN_NAME,
                    confidence=calculate_confidence(
                        CONTEXTUAL_PATTERN_NAME, hit.value, line
                    ),
                    fingerprint=secret_id(CONTEXTUAL_PATTERN_NAME, hit.value),
                    commit=commit,
                )
            )
        return findings, ignored

    def scan_file(self, path: Path) -> FileScan:
        """Read ``path`` line by line. Unreadable files yield an empty result."""
        findings: list[SecretFinding] = []
        lines_scanned = 0
        ignored = 0
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    lines_scanned = line_number
                    line_findings, line_ignored = self.scan_line(
                        line.rstrip("\n"), path, line_number
                    )
                    findings.extend(line_findings)
                    ignored += line_ignored
        except OSError as exc:
            _LOG.error("Unable to read file %s: %s", path, exc.strerror or exc)
            return FileScan(findings=(), lines_scanned=0, placeholders_ignored=0)
        if findings:
            for finding in findings:
                _LOG.warning(
                    "Potential secret detected: %s at %s:%s (%s, confidence=%s%%)",
                    finding.pattern_name,
                    path.name,
                    finding.line_number,
                    finding.severity.value,
                    finding.confidence,
                )
        return FileScan(
            findings=tuple(findings),
            lines_scanned=lines_scanned,
            placeholders_ignored=ignored,
        )
