"""Salted HMAC-SHA256 hash for audit input_hash field.

This module must NOT log or print any values derived from user input.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import warnings


def salted_hash(value: str, salt: bytes) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()


def load_salt(salt_b64: str | None) -> bytes:
    if salt_b64:
        return base64.b64decode(salt_b64)
    warnings.warn(
        "GUARDIAN_BR_AUDIT_SALT not set — using a random per-process salt. "
        "Audit input_hash values will not be reproducible across restarts.",
        RuntimeWarning,
        stacklevel=2,
    )
    return os.urandom(32)
