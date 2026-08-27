"""Core scanning package.

Holds file discovery, pattern matching, and finding models.
"""

from scanner.file_handler import ScanConfig
from scanner.models import PatternMatch, SecretPattern, Severity
from scanner.patterns import PatternEngine
from scanner.scanner import Scanner

__all__ = [
    "ScanConfig",
    "PatternEngine",
    "PatternMatch",
    "Scanner",
    "SecretPattern",
    "Severity",
]
