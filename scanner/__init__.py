"""Core scanning package.

Holds file discovery, pattern matching, and finding models.
"""

from scanner.confidence import calculate_confidence
from scanner.context import CONTEXTUAL_PATTERN_NAME, is_sensitive_identifier
from scanner.detector import Detector, FileScan, mask_secret
from scanner.entropy import shannon_entropy
from scanner.filters import is_placeholder
from scanner.file_handler import ScanConfig
from scanner.models import PatternMatch, ScanResult, SecretFinding, SecretPattern, Severity
from scanner.patterns import PatternEngine
from scanner.scanner import Scanner
from scanner.severity import meets_minimum, severity_for

__all__ = [
    "CONTEXTUAL_PATTERN_NAME",
    "calculate_confidence",
    "Detector",
    "FileScan",
    "is_placeholder",
    "is_sensitive_identifier",
    "shannon_entropy",
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
