"""Context analysis: sensitive variable names around assignments.

Format regexes catch known shapes (AKIA…, ghp_, JWT). They miss::

    token = "...."
    SECRET_KEY=....

Those values have no public prefix, but the *name* is a strong hint.
This module extracts identifier/value pairs. It does not score entropy
or confidence; those are later phases.

Context-only hits are easier to get wrong than format hits, so the value
must be reasonably long and must pass the placeholder filter downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CONTEXTUAL_PATTERN_NAME = "Contextual Secret"
CONTEXT_MIN_LENGTH = 16

_HINT_TOKENS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "credential",
        "credentials",
    }
)

# Quoted assignments: api_key = "...", "access_token": "...", token: '...'
_QUOTED_ASSIGNMENT = re.compile(
    r"""
    (?:
        (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
      | ['\"](?P<quoted_ident>[A-Za-z_][A-Za-z0-9_-]*)['\"]
    )
    \s*[:=]\s*
    (?P<quote>['\"])
    (?P<value>[^'\"\n]{16,})
    (?P=quote)
    """,
    re.VERBOSE,
)

# .env / shell: SECRET_KEY=unquoted_value  or  export API_TOKEN=...
_UNQUOTED_ASSIGNMENT = re.compile(
    r"""
    (?:export\s+)?
    (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    =
    (?P<value>[^\s#'\"]{16,})
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass(frozen=True)
class ContextHit:
    """One sensitive assignment. ``value`` is still plaintext here."""

    identifier: str
    value: str
    start: int
    end: int


def is_sensitive_identifier(name: str) -> bool:
    """Return True if a variable / key name looks credential-related."""
    tokens = [part for part in name.casefold().replace("-", "_").split("_") if part]
    if not tokens:
        return False
    if "api" in tokens and "key" in tokens:
        return True
    if "private" in tokens and "key" in tokens:
        return True
    if "access" in tokens and "key" in tokens:
        return True
    return any(token in _HINT_TOKENS for token in tokens)


def find_context_hits(line: str) -> list[ContextHit]:
    """Return sensitive assignments on a single line."""
    hits: list[ContextHit] = []
    seen: set[tuple[int, int]] = set()

    for match in _QUOTED_ASSIGNMENT.finditer(line):
        ident = match.group("ident") or match.group("quoted_ident") or ""
        hit = _hit_from_match(ident, match.group("value"), match.start(), match.end())
        if hit is not None and (hit.start, hit.end) not in seen:
            seen.add((hit.start, hit.end))
            hits.append(hit)

    for match in _UNQUOTED_ASSIGNMENT.finditer(line):
        hit = _hit_from_match(
            match.group("ident") or "",
            match.group("value"),
            match.start(),
            match.end(),
        )
        if hit is not None and (hit.start, hit.end) not in seen:
            seen.add((hit.start, hit.end))
            hits.append(hit)

    return hits


def _hit_from_match(
    ident: str, value: str, start: int, end: int
) -> ContextHit | None:
    if not is_sensitive_identifier(ident):
        return None
    if len(value) < CONTEXT_MIN_LENGTH:
        return None
    return ContextHit(identifier=ident, value=value, start=start, end=end)
