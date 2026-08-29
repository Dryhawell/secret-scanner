"""Scan orchestration: discover files, detect secrets, return ScanResult."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from scanner.detector import Detector
from scanner.file_handler import ScanConfig, iter_scan_files, should_scan_file
from scanner.ignore import ignore_root, is_ignored_finding, is_ignored_path
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
        """Return unique scan-candidate files under ``target``."""
        seen: set[Path] = set()
        unique: list[Path] = []
        for path in iter_scan_files(target, self.config):
            if path in seen:
                continue
            if is_ignored_path(path, ignore_root(Path(target)), self.config.ignore_paths):
                _LOG.debug("Allowlist skipped file %s", path)
                continue
            seen.add(path)
            unique.append(path)
        return unique

    def scan_paths(self, paths: Sequence[Path], *, target: Path) -> ScanResult:
        """Scan an explicit file list (Git staged/changed). Discovery is skipped."""
        started_at = datetime.now(timezone.utc)
        _LOG.info("Scan started (explicit paths): %s", target)
        unique: list[Path] = []
        seen: set[Path] = set()
        for path in paths:
            resolved = path.expanduser().resolve()
            if resolved in seen:
                continue
            if not should_scan_file(resolved, self.config):
                continue
            if is_ignored_path(resolved, ignore_root(target), self.config.ignore_paths):
                _LOG.debug("Allowlist skipped file %s", resolved)
                continue
            seen.add(resolved)
            unique.append(resolved)
        _LOG.info("Discovered %s candidate file(s)", len(unique))
        return self._scan_file_list(unique, target=target, started_at=started_at)

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
        return self._scan_file_list(files, target=root, started_at=started_at)

    def _scan_file_list(
        self,
        files: Sequence[Path],
        *,
        target: Path,
        started_at: datetime,
    ) -> ScanResult:
        findings: list[SecretFinding] = []
        lines_scanned = 0
        placeholders_ignored = 0
        allowlist_ignored = 0
        for path in files:
            _LOG.debug("Scanning file %s", path)
            file_scan = self.detector.scan_file(path)
            lines_scanned += file_scan.lines_scanned
            placeholders_ignored += file_scan.placeholders_ignored
            for finding in file_scan.findings:
                if is_ignored_finding(
                    finding.file_path,
                    finding.pattern_name,
                    ignore_root(target),
                    self.config.ignore_findings,
                ):
                    allowlist_ignored += 1
                    _LOG.debug(
                        "Allowlist dropped %s at %s:%s",
                        finding.pattern_name,
                        path.name,
                        finding.line_number,
                    )
                    continue
                findings.append(finding)
        resolved = target.expanduser()
        resolved = resolved.resolve() if resolved.exists() else resolved
        finished_at = datetime.now(timezone.utc)
        _LOG.info(
            "Scan completed: files=%s lines=%s findings=%s ignored=%s allowlist=%s",
            len(files),
            lines_scanned,
            len(findings),
            placeholders_ignored,
            allowlist_ignored,
        )
        return ScanResult(
            target=resolved,
            started_at=started_at,
            finished_at=finished_at,
            files_scanned=len(files),
            lines_scanned=lines_scanned,
            findings=tuple(findings),
            placeholders_ignored=placeholders_ignored,
            allowlist_ignored=allowlist_ignored,
        )
