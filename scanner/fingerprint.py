"""One-way fingerprint of a secret. Never store or log the plaintext."""

from __future__ import annotations

import hashlib


def secret_id(pattern_name: str, secret: str) -> str:
    """Return SHA-256 hex of pattern name plus secret.

    The hash is not reversible. It identifies *this* value for a baseline
    without writing the credential to disk.
    """
    digest = hashlib.sha256()
    digest.update(pattern_name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(secret.encode("utf-8"))
    return digest.hexdigest()
