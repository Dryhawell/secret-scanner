"""Central secret pattern catalog and regex engine.

This module knows *what* a secret looks like. It does not read files.
File-by-file detection is the next phase.

Every regex below targets a public *format*, never a real credential.
Test values must stay obvious placeholders.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from scanner.models import PatternMatch, SecretPattern
from scanner.severity import severity_for


def default_patterns() -> list[SecretPattern]:
    """Return the built-in pattern catalog.

    Keep this list the single place to add a new secret type.
    """
    return [
        SecretPattern(
            name="AWS Access Key ID",
            regex=r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
            severity=severity_for("AWS Access Key ID"),
            description="AWS access key IDs start with AKIA followed by 16 uppercase alphanumerics.",
        ),
        SecretPattern(
            name="GitHub Token",
            regex=r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
            severity=severity_for("GitHub Token"),
            description="Classic GitHub tokens use a three-letter prefix, underscore, then 36 characters.",
        ),
        SecretPattern(
            name="GitHub Fine-Grained Token",
            regex=r"github_pat_[A-Za-z0-9_]{22,}",
            severity=severity_for("GitHub Fine-Grained Token"),
            description="Fine-grained GitHub PATs start with github_pat_ and a long alphanumeric payload.",
        ),
        SecretPattern(
            name="Google API Key",
            regex=r"AIza[0-9A-Za-z\-_]{35}",
            severity=severity_for("Google API Key"),
            description="Google API keys start with AIza and continue for 35 URL-safe characters.",
        ),
        SecretPattern(
            name="Stripe API Key",
            regex=r"(?<![A-Za-z0-9])(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}",
            severity=severity_for("Stripe API Key"),
            description="Stripe keys look like sk_live_, sk_test_, pk_live_, or pk_test_ plus a payload.",
        ),
        SecretPattern(
            name="JWT",
            regex=r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            severity=severity_for("JWT"),
            description="JWTs are three base64url segments. The header almost always starts with eyJ.",
        ),
        SecretPattern(
            name="Private Key",
            regex=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            severity=severity_for("Private Key"),
            description="PEM private keys are marked by a BEGIN PRIVATE KEY header, not the public key header.",
        ),
        SecretPattern(
            name="Generic API Key",
            regex=r"\b(?:api[_-]?key|apikey)\s*[:=]\s*(['\"])([A-Za-z0-9_\-]{16,})\1",
            severity=severity_for("Generic API Key"),
            description="Assignment of api_key / api-key to a quoted value of at least 16 characters.",
            flags=re.IGNORECASE,
            value_group=2,
        ),
        SecretPattern(
            name="Generic Password",
            regex=r"\b(?:password|passwd|pwd)\s*[:=]\s*(['\"])([^'\"]{8,})\1",
            severity=severity_for("Generic Password"),
            description="Assignment of password / passwd / pwd to a quoted value of at least 8 characters.",
            flags=re.IGNORECASE,
            value_group=2,
        ),
        SecretPattern(
            name="Database Connection String",
            regex=r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|mariadb)://[^\s'\"<>]+",
            severity=severity_for("Database Connection String"),
            description="Database URLs often embed username and password in the scheme://user:pass@host form.",
            flags=re.IGNORECASE,
        ),
    ]


class PatternEngine:
    """Compile patterns once, then search text as many times as needed."""

    def __init__(self, patterns: Sequence[SecretPattern] | None = None) -> None:
        self.patterns = list(patterns) if patterns is not None else default_patterns()
        self._compiled: list[tuple[SecretPattern, re.Pattern[str]]] = [
            (pattern, re.compile(pattern.regex, pattern.flags))
            for pattern in self.patterns
        ]

    def find_in_text(self, text: str) -> list[PatternMatch]:
        """Return every pattern hit in ``text``. Does not read files."""
        matches: list[PatternMatch] = []
        for pattern, compiled in self._compiled:
            for match in compiled.finditer(text):
                matched_text = (
                    match.group(pattern.value_group)
                    if pattern.value_group is not None
                    else match.group(0)
                )
                matches.append(
                    PatternMatch(
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        matched_text=matched_text,
                        start=match.start(),
                        end=match.end(),
                        compiled_pattern=compiled,
                    )
                )
        return matches
