"""Scan orchestration: discover files, detect secrets, return ScanResult."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scanner.detector import Detector
from scanner.file_handler import ScanConfig, iter_scan_files
from scanner.models import ScanResult, SecretFinding
from scanner.patterns import PatternEngine
from utils.logger import get_logger

_LOG = get_logger()


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
        _LOG.info("Scan started: %s", root)
        files = self.discover_files(root)
        _LOG.info("Discovered %s candidate file(s)", len(files))
        findings: list[SecretFinding] = []
        lines_scanned = 0
        placeholders_ignored = 0
        for path in files:
            _LOG.debug("Scanning file %s", path)
            file_scan = self.detector.scan_file(path)
            findings.extend(file_scan.findings)
            lines_scanned += file_scan.lines_scanned
            placeholders_ignored += file_scan.placeholders_ignored
        resolved = root.resolve() if root.exists() else root
        finished_at = datetime.now(timezone.utc)
        _LOG.info(
            "Scan completed: files=%s lines=%s findings=%s ignored=%s",
            len(files),
            lines_scanned,
            len(findings),
            placeholders_ignored,
        )
        return ScanResult(
            target=resolved,
            started_at=started_at,
            finished_at=finished_at,
            files_scanned=len(files),
            lines_scanned=lines_scanned,
            findings=tuple(findings),
            placeholders_ignored=placeholders_ignored,
        )
