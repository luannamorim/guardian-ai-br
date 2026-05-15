"""Override get_principal with a JWT validator (HS256 example).

This file demonstrates how to swap the default static-key auth for JWT
without forking Guardian-BR — use app.dependency_overrides.

Run::

    export GUARDIAN_BR_JWT_SECRET=my-secret
    export GUARDIAN_BR_API_KEYS_HASHED="sha256:..."   # still needed for /v1/metrics auth
    uv run uvicorn examples.jwt_auth:app --reload

Generate a test token::

    python -c "
    import jwt, os
    print(jwt.encode({'sub': 'user1', 'iss': 'guardian-br'},
          os.environ['GUARDIAN_BR_JWT_SECRET'], algorithm='HS256'))
    "

Then call::

    curl -X POST http://localhost:8000/v1/scan \\
      -H 'Authorization: Bearer <token>' \\
      -H 'content-type: application/json' \\
      -d '{"text": "cpf 123.456.789-09", "mode": "REDACT"}'
"""

import hashlib
import os

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from guardian_br.api import Principal, create_app, get_principal

_bearer = HTTPBearer(auto_error=False)
_JWT_SECRET = os.environ.get("GUARDIAN_BR_JWT_SECRET", "")
_JWT_ISS = os.environ.get("GUARDIAN_BR_JWT_ISS", "guardian-br")


async def jwt_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    """JWT validator that replaces the default X-API-Key check.

    Decodes HS256 JWTs signed with GUARDIAN_BR_JWT_SECRET.
    Requires claims: sub, exp, iss.
    """
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not _JWT_SECRET:
        raise RuntimeError("GUARDIAN_BR_JWT_SECRET not set")
    try:
        claims = jwt.decode(
            creds.credentials,
            _JWT_SECRET,
            algorithms=["HS256"],
            issuer=_JWT_ISS,
            options={"require": ["sub", "exp", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=403, detail="invalid token") from exc

    key_hash = hashlib.sha256(creds.credentials.encode()).hexdigest()
    principal = Principal(
        id=claims["sub"],
        key_hash=key_hash,
        auth_method="jwt",
        scopes=frozenset(claims.get("scope", "").split()),
    )
    # Set on request.state so the rate limiter can use principal.id
    request.state.principal = principal
    return principal


app = create_app()
app.dependency_overrides[get_principal] = jwt_principal
