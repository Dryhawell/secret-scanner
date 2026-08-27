"""Scan orchestration.

Discover candidate files, then run the detector on each one. Later phases
will wrap findings in a richer ScanResult model.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scanner.detector import Detection, Detector
from scanner.file_handler import ScanConfig, iter_scan_files
from scanner.patterns import PatternEngine


@dataclass(frozen=True)
class ScanSummary:
    """PHASE 4 scan outcome. Promoted to ScanResult in a later phase."""

    target: Path
    files_scanned: int
    findings: list[Detection]

    @property
    def findings_count(self) -> int:
        return len(self.findings)


class Scanner:
    """Coordinates discovery and detection against a file or directory."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        engine: PatternEngine | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.engine = engine or PatternEngine()
        self.detector = Detector(engine=self.engine)

    def discover_files(self, target: str | Path) -> list[Path]:
        """Return scan-candidate files under ``target``."""
        return list(iter_scan_files(target, self.config))

    def scan(self, target: str | Path) -> ScanSummary:
        """Discover files, detect secrets, return a summary.

        Findings store masked values only. Plaintext matches stay inside
        PatternEngine for the duration of a single line, then are dropped.
        """
        root = Path(target).expanduser()
        files = self.discover_files(root)
        findings: list[Detection] = []
        for path in files:
            findings.extend(self.detector.scan_file(path))
        resolved = root.resolve() if root.exists() else root
        return ScanSummary(
            target=resolved,
            files_scanned=len(files),
            findings=findings,
        )
