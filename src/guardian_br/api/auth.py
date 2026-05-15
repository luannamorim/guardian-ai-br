"""FastAPI auth dependency: static X-API-Key validator.

Override in production::

    from guardian_br.api import create_app, get_principal, Principal

    app = create_app()

    async def my_jwt_validator(request: Request) -> Principal:
        ...

    app.dependency_overrides[get_principal] = my_jwt_validator

See examples/jwt_auth.py for a complete worked example with PyJWT.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Literal, cast

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from guardian_br.api import metrics as m
from guardian_br.api.settings import Settings

logger = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _get_settings(request: Request) -> Settings:
    """Read Settings from app.state so tests can inject without env vars."""
    state_settings = getattr(request.app.state, "settings", None)
    if state_settings is not None:
        return cast(Settings, state_settings)
    return Settings()


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    key_hash: str
    auth_method: Literal["api_key", "jwt", "anonymous"]
    scopes: frozenset[str] = frozenset()


def _log_auth_failure(
    request: Request,
    *,
    reason: str,
    key_hash_prefix: str | None,
) -> None:
    logger.warning(
        "auth_failure",
        extra={
            "client_ip": request.client.host if request.client else "unknown",
            "key_hash_prefix": key_hash_prefix,
            "path": str(request.url.path),
            "reason": reason,
        },
    )


async def get_principal(
    request: Request,
    api_key: str | None = Depends(_api_key_header),
    settings: Settings = Depends(_get_settings),
) -> Principal:
    """Default static API-key validator.

    Override via app.dependency_overrides[get_principal] = custom_validator.
    """
    if api_key is None:
        _log_auth_failure(request, reason="missing", key_hash_prefix=None)
        m.AUTH_FAILURES.labels(reason="missing").inc()
        raise HTTPException(
            status_code=401,
            detail="X-API-Key header required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    received_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Drain full loop — never short-circuit — to keep timing flat regardless
    # of key position in the rotation set.
    matched = False
    for stored in settings.api_keys_hashed:
        expected = stored.removeprefix("sha256:")
        if secrets.compare_digest(received_hash, expected):
            matched = True

    if not matched:
        _log_auth_failure(request, reason="invalid", key_hash_prefix=received_hash[:12])
        m.AUTH_FAILURES.labels(reason="invalid").inc()
        raise HTTPException(status_code=403, detail="invalid API key")

    principal = Principal(
        id=received_hash[:8],
        key_hash=received_hash,
        auth_method="api_key",
    )
    request.state.principal = principal
    return principal
