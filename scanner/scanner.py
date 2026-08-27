"""Scan orchestration: discover files, detect secrets, return ScanResult."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scanner.detector import Detector
from scanner.file_handler import ScanConfig, iter_scan_files
from scanner.models import ScanResult, SecretFinding
from scanner.patterns import PatternEngine


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

    def scan(self, target: str | Path) -> ScanResult:
        """Discover files, detect secrets, return a structured result.

        Findings store masked values only. Plaintext matches stay inside
        PatternEngine for the duration of a single line, then are dropped.
        """
        started_at = datetime.now(timezone.utc)
        root = Path(target).expanduser()
        files = self.discover_files(root)
        findings: list[SecretFinding] = []
        lines_scanned = 0
        for path in files:
            file_scan = self.detector.scan_file(path)
            findings.extend(file_scan.findings)
            lines_scanned += file_scan.lines_scanned
        resolved = root.resolve() if root.exists() else root
        return ScanResult(
            target=resolved,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            files_scanned=len(files),
            lines_scanned=lines_scanned,
            findings=tuple(findings),
        )
