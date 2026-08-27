"""False-positive filters for likely placeholder secrets.

This module answers: "does this *value* look like documentation, not a
real credential?" It does not look at variable names (context analysis
is a later phase) and it does not score confidence.

Design intent — stay conservative:
    False positive: reporting YOUR_API_KEY_HERE as a leak. Noisy, but
    usually easy to dismiss.
    False negative: skipping a real staging key because it contains the
    letters "test". That is a missed incident.

So we ignore *distinctive* dummy strings, not every value that happens
to include "test" or "secret".
"""

from __future__ import annotations

import re

# Entire value, after normalize. These are textbook dummy passwords/keys.
_EXACT: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "admin",
        "secret",
        "changeme",
        "changeme123",
        "dummy",
        "example",
        "sample",
        "placeholder",
        "xxx",
        "xxxx",
        "xxxxxx",
        "todo",
        "none",
        "null",
        "undefined",
        "your_password",
        "your_api_key",
        "your_secret",
        "your_token",
        "api_key",
        "apikey",
        "token",
        "secret123",
        "password123",
        "admin123",
        "test",
        "testing",
        "test123",
        "foobar",
        "abcdef",
        "abc123",
    }
)

# Distinctive fragments. Not "test", "key", or "secret" — those appear
# inside real tokens and real passwords far too often.
_FRAGMENTS: tuple[str, ...] = (
    "placeholder",
    "changeme",
    "your_api_key",
    "your_password",
    "your_secret",
    "your_token",
    "your_access",
    "insert_here",
    "replace_me",
    "not_a_secret",
    "notasecret",
    "lorem_ipsum",
    "xxxxxxxx",
    "dummy",
    "example",
    "sample_key",
    "sample_token",
)

_YOUR_HERE = re.compile(r"^your_.+_here$")
_REDACTED = re.compile(r"^[\sx*_\-]+$")


def normalize_secret_value(value: str) -> str:
    """Lowercase, strip, treat hyphen as underscore for comparisons."""
    return value.strip().lower().replace("-", "_")


def is_placeholder(value: str) -> bool:
    """Return True if ``value`` looks like a docs/example placeholder."""
    if not value or not value.strip():
        return True

    normalized = normalize_secret_value(value)
    if normalized in _EXACT:
        return True
    if _YOUR_HERE.match(normalized):
        return True
    if any(fragment in normalized for fragment in _FRAGMENTS):
        return True
    # Values that are only stars/x, like ******** or xxxx-xxxx.
    compact = normalized.replace("_", "")
    if len(compact) >= 4 and _REDACTED.fullmatch(compact):
        return True
    return False
