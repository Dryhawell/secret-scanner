"""Core scanning package.

Holds file discovery, pattern matching, and finding models.
"""

from scanner.detector import Detector, FileScan, mask_secret
from scanner.file_handler import ScanConfig
from scanner.models import PatternMatch, ScanResult, SecretFinding, SecretPattern, Severity
from scanner.patterns import PatternEngine
from scanner.scanner import Scanner

__all__ = [
    "Detector",
    "FileScan",
    "PatternEngine",
    "PatternMatch",
    "ScanConfig",
    "ScanResult",
    "Scanner",
    "SecretFinding",
    "SecretPattern",
    "Severity",
    "mask_secret",
]
