"""Detection confidence scoring.

Confidence is *not* a verdict that a credential is valid, live, or
exploitable. It only answers: "how much does this look like a secret
to the detector?"

Factors:
    * pattern strength (vendor format vs generic assignment)
    * context (sensitive variable name on the same line)
    * Shannon entropy (randomness of the value)
    * length for generic types

The score is clamped to 5–99. 100% would be dishonest; 0% would hide a hit.
"""

from __future__ import annotations

import re

from scanner.context import CONTEXTUAL_PATTERN_NAME, is_sensitive_identifier
from scanner.entropy import entropy_adjustment

MIN_CONFIDENCE = 5
MAX_CONFIDENCE = 99

# How strongly the *format* implies a real secret. Not the same as severity.
PATTERN_BASE: dict[str, int] = {
    "Private Key": 92,
    "AWS Access Key ID": 90,
    "Azure Storage Account Key": 90,
    "GitHub Token": 88,
    "GitHub Fine-Grained Token": 88,
    "Stripe API Key": 86,
    "Google API Key": 84,
    "GitLab Token": 86,
    "Slack Token": 86,
    "npm Token": 86,
    "Hugging Face Token": 84,
    "OpenAI API Key": 86,
    "PyPI Token": 84,
    "SendGrid API Key": 86,
    "Twilio API Key": 84,
    "Discord Webhook": 86,
    "Shopify Token": 84,
    "Telegram Bot Token": 84,
    "Database Connection String": 80,
    "JWT": 76,
    "Generic API Key": 68,
    "Generic Password": 58,
    "Contextual Secret": 52,
}

_ASSIGNED_NAME = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")


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

    score += entropy_adjustment(pattern_name, value)

    if pattern_name in {"Generic Password", "Generic API Key", "Contextual Secret"}:
        if len(value) < 12:
            score -= 10
        elif len(value) >= 24:
            score += 3

    return max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, score))
