"""Scan orchestration.

PHASE 2 only discovers files. Detection, severity, and reporting land in
later phases. Keeping this class thin makes it possible to add regex
scanning later without rewriting directory traversal.
"""

from __future__ import annotations

from pathlib import Path

from scanner.file_handler import ScanConfig, iter_scan_files


class Scanner:
    """Coordinates a scan against a file or directory."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def discover_files(self, target: str | Path) -> list[Path]:
        """Return scan-candidate files under ``target``.

        Paths are resolved to absolute form so later phases can report a
        stable location even if the process changes working directory.
        """
        return list(iter_scan_files(target, self.config))
