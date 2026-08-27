"""Core scanning package.

Holds file discovery, pattern matching, and finding models.
"""

from scanner.detector import Detector, FileScan, mask_secret
from scanner.filters import is_placeholder
from scanner.file_handler import ScanConfig
from scanner.models import PatternMatch, ScanResult, SecretFinding, SecretPattern, Severity
from scanner.patterns import PatternEngine
from scanner.scanner import Scanner
from scanner.severity import meets_minimum, severity_for

__all__ = [
    "Detector",
    "FileScan",
    "is_placeholder",
    "PatternEngine",
    "PatternMatch",
    "ScanConfig",
    "ScanResult",
    "Scanner",
    "SecretFinding",
    "SecretPattern",
    "Severity",
    "mask_secret",
    "meets_minimum",
    "severity_for",
]
