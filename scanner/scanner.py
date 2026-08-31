"""Scan orchestration: discover files, detect secrets, return ScanResult."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from scanner.baseline import is_baselined
from scanner.detector import Detector
from scanner.file_handler import ScanConfig, has_excluded_extension, iter_scan_files, should_scan_file
from scanner.history import HistoryLine
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

    def scan_history(self, lines: Sequence[HistoryLine], *, target: Path) -> ScanResult:
        """Scan added lines from Git history. Files need not exist on disk."""
        started_at = datetime.now(timezone.utc)
        _LOG.info("Scan started (git history): %s", target)
        findings: list[SecretFinding] = []
        lines_scanned = 0
        placeholders_ignored = 0
        allowlist_ignored = 0
        baseline_ignored = 0
        root = ignore_root(target)
        skip_names = {".secret-scanner-baseline.json", ".secret-scanner.json",
                      ".secret-scanner.yml", ".secret-scanner.yaml"}
        seen_units: set[tuple[str, str, int]] = set()
        files_seen: set[tuple[str, str]] = set()
        for item in lines:
            if item.relative_path.rsplit("/", 1)[-1].casefold() in skip_names:
                continue
            path = root / item.relative_path
            if has_excluded_extension(path, self.config):
                continue
            if is_ignored_path(path, root, self.config.ignore_paths):
                continue
            unit = (item.commit, item.relative_path, item.line_number)
            if unit in seen_units:
                continue
            seen_units.add(unit)
            files_seen.add((item.commit, item.relative_path))
            lines_scanned += 1
            line_findings, line_ignored = self.detector.scan_line(
                item.text, path, item.line_number, commit=item.commit
            )
            placeholders_ignored += line_ignored
            for finding in line_findings:
                if is_ignored_finding(
                    finding.file_path,
                    finding.pattern_name,
                    root,
                    self.config.ignore_findings,
                ):
                    allowlist_ignored += 1
                    continue
                if is_baselined(finding, root, self.config.baseline_keys):
                    baseline_ignored += 1
                    continue
                findings.append(finding)
        finished_at = datetime.now(timezone.utc)
        _LOG.info(
            "History scan completed: files=%s lines=%s findings=%s",
            len(files_seen),
            lines_scanned,
            len(findings),
        )
        resolved = target.expanduser()
        resolved = resolved.resolve() if resolved.exists() else resolved
        return ScanResult(
            target=resolved,
            started_at=started_at,
            finished_at=finished_at,
            files_scanned=len(files_seen),
            lines_scanned=lines_scanned,
            findings=tuple(findings),
            placeholders_ignored=placeholders_ignored,
            allowlist_ignored=allowlist_ignored,
            baseline_ignored=baseline_ignored,
        )

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
        baseline_ignored = 0
        root = ignore_root(target)
        for path in files:
            _LOG.debug("Scanning file %s", path)
            file_scan = self.detector.scan_file(path)
            lines_scanned += file_scan.lines_scanned
            placeholders_ignored += file_scan.placeholders_ignored
            for finding in file_scan.findings:
                if is_ignored_finding(
                    finding.file_path,
                    finding.pattern_name,
                    root,
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
                if is_baselined(finding, root, self.config.baseline_keys):
                    baseline_ignored += 1
                    _LOG.debug(
                        "Baseline dropped %s at %s:%s",
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
            "Scan completed: files=%s lines=%s findings=%s ignored=%s allowlist=%s baseline=%s",
            len(files),
            lines_scanned,
            len(findings),
            placeholders_ignored,
            allowlist_ignored,
            baseline_ignored,
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
            baseline_ignored=baseline_ignored,
        )
