"""Core scanning package.

Holds file discovery, pattern matching, and finding models.
"""

from scanner.detector import Detection, Detector, mask_secret
from scanner.file_handler import ScanConfig
from scanner.models import PatternMatch, SecretPattern, Severity
from scanner.patterns import PatternEngine
from scanner.scanner import Scanner, ScanSummary

__all__ = [
    "Detection",
    "Detector",
    "PatternEngine",
    "PatternMatch",
    "ScanConfig",
    "ScanSummary",
    "Scanner",
    "SecretPattern",
    "Severity",
    "mask_secret",
]
