"""Detection confidence scoring.

Confidence is *not* a verdict that a credential is valid, live, or
exploitable. It only answers: "how much does this look like a secret
to the detector?"

Factors used now:
    * pattern strength (vendor format vs generic assignment)
    * context (sensitive variable name on the same line)
    * character variety (a stand-in until Shannon entropy in the next phase)
    * leftover dummy-looking traits that the placeholder filter did not drop

The score is clamped to 5–99. 100% would be dishonest; 0% would hide a hit.
"""

from __future__ import annotations

import re

from scanner.context import CONTEXTUAL_PATTERN_NAME, is_sensitive_identifier

MIN_CONFIDENCE = 5
MAX_CONFIDENCE = 99

# How strongly the *format* implies a real secret. Not the same as severity.
PATTERN_BASE: dict[str, int] = {
    "Private Key": 92,
    "AWS Access Key ID": 90,
    "GitHub Token": 88,
    "GitHub Fine-Grained Token": 88,
    "Stripe API Key": 86,
    "Google API Key": 84,
    "Database Connection String": 80,
    "JWT": 76,
    "Generic API Key": 68,
    "Generic Password": 58,
    "Contextual Secret": 52,
}

_ASSIGNED_NAME = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")


def variety_ratio(value: str) -> float:
    """Unique characters / length. Not Shannon entropy."""
    if not value:
        return 0.0
    return len(set(value)) / len(value)


def line_has_sensitive_name(line: str) -> bool:
    """True if an identifier before ``=`` or ``:`` looks credential-related."""
    for match in _ASSIGNED_NAME.finditer(line):
        if is_sensitive_identifier(match.group(1)):
            return True
    return False


def calculate_confidence(pattern_name: str, value: str, line: str = "") -> int:
    """Return an integer percent in ``[5, 99]``."""
    score = PATTERN_BASE.get(pattern_name, 50)

    if pattern_name != CONTEXTUAL_PATTERN_NAME and line_has_sensitive_name(line):
        score += 8

    variety = variety_ratio(value)
    if variety < 0.25:
        score -= 22
    elif variety < 0.40:
        score -= 10
    elif variety >= 0.70 and len(value) >= 16:
        score += 4

    if pattern_name in {"Generic Password", "Generic API Key", "Contextual Secret"}:
        if len(value) < 12:
            score -= 10
        elif len(value) >= 24:
            score += 3

    return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, score))
