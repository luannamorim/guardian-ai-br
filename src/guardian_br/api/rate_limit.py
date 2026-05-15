"""Rate limiting for Guardian-BR API.

The rate limit middleware runs BEFORE auth (get_principal), so
request.state.principal is not set at check time. We use X-API-Key
header directly (hashed) to assign per-key buckets. Unauthenticated
requests fall back to source IP.
"""

from __future__ import annotations

import hashlib

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def _principal_key_func(request: Request) -> str:
    """Rate-limit by hashed API key, or by IP for unauthenticated requests."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # Use first 16 hex chars of SHA-256(key) — enough for bucket identity,
        # never the raw key, never the full hash (short enough to be safe in
        # slowapi's storage key).
        return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return f"ip:{get_remote_address(request)}"


def make_limiter(rate_limit: str) -> Limiter:
    return Limiter(key_func=_principal_key_func, default_limits=[rate_limit])
