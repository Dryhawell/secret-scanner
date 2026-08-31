"""Shannon entropy helpers for secret detection.

Entropy measures how unpredictable a string is, in bits. It is a
*supporting* signal:

    Pattern + context + entropy  →  useful
    Entropy alone                  →  not a detector

A minified JavaScript bundle and a UUIDv4 both look random. Flagging every
high-entropy token in a repo would drown real leaks in noise.
"""

from __future__ import annotations

import math
from collections import Counter

# Contextual / generic values below this are treated as dummy, not secrets.
LOW_ENTROPY_BITS = 2.0

# Patterns whose evidence is the *format*, not randomness of the bytes.
# A PEM header is English and therefore low-entropy by design.
FORMAT_LOCKED_PATTERNS: frozenset[str] = frozenset(
    {
        "Private Key",
        "AWS Access Key ID",
        "GitHub Token",
        "GitHub Fine-Grained Token",
        "Google API Key",
        "Stripe API Key",
        "JWT",
        "Database Connection String",
        "GitLab Token",
        "Slack Token",
        "npm Token",
        "Hugging Face Token",
        "OpenAI API Key",
        "PyPI Token",
    }
)

# Generic hits need randomness *and* a sensitive name/assignment.
ENTROPY_GATED_PATTERNS: frozenset[str] = frozenset(
    {
        "Contextual Secret",
        "Generic Password",
        "Generic API Key",
    }
)


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy of ``value`` in bits per character.

    For a string of length n, each distinct character c with count n_c
    has probability p = n_c / n. Then::

        H = -Σ p * log2(p)

    All identical characters → H = 0.
    A well-mixed token → H closer to log2(alphabet size).
    """
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def unique_ratio(value: str) -> float:
    """Unique characters / length. A cruder cousin of entropy."""
    if not value:
        return 0.0
    return len(set(value)) / len(value)


def is_low_entropy(value: str, threshold: float = LOW_ENTROPY_BITS) -> bool:
    """True when the string is too repetitive to be a useful generic secret."""
    return shannon_entropy(value) < threshold


def entropy_adjustment(pattern_name: str, value: str) -> int:
    """Confidence delta derived from entropy. Format-locked types are skipped."""
    if pattern_name in FORMAT_LOCKED_PATTERNS:
        return 0
    entropy = shannon_entropy(value)
    if entropy < 1.5:
        return -25
    if entropy < 2.5:
        return -12
    if entropy >= 3.5:
        return 6
    return 0
