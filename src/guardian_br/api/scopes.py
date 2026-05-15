"""Scope-based authorization dependency for FastAPI routes."""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException

from guardian_br.api.auth import Principal, get_principal


def require_scope(scope: str):  # type: ignore[no-untyped-def]
    """Return a FastAPI dependency that requires *scope* on the resolved principal."""

    async def _check(principal: Principal = Depends(get_principal)) -> None:
        for s in principal.scopes:
            if secrets.compare_digest(s.encode(), scope.encode()):
                return
        raise HTTPException(status_code=403, detail=f"scope '{scope}' required")

    return _check
