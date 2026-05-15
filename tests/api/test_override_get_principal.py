"""Tests for the get_principal override (JWT/OIDC production pattern)."""

import pytest

from guardian_br.api.auth import Principal, get_principal


@pytest.mark.asyncio
async def test_override_skips_api_key_check(app, guardian) -> None:
    """With get_principal overridden, X-API-Key is not required."""
    import httpx
    from fastapi import Request

    fixed_principal = Principal(
        id="override-test",
        key_hash="a" * 64,
        auth_method="jwt",
    )

    async def _fixed_principal(request: Request) -> Principal:
        request.state.principal = fixed_principal
        return fixed_principal

    app.dependency_overrides[get_principal] = _fixed_principal

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        resp = await c.post(
            "/v1/scan",
            json={"text": "x", "mode": "REDACT"},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_override_principal_propagated(app, guardian) -> None:
    """The overridden Principal should be used in the request lifecycle."""
    import httpx
    from fastapi import Request

    received_principals = []

    async def _capturing_principal(request: Request) -> Principal:
        p = Principal(
            id="captured-id",
            key_hash="b" * 64,
            auth_method="jwt",
        )
        request.state.principal = p
        received_principals.append(p)
        return p

    app.dependency_overrides[get_principal] = _capturing_principal

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        await c.post("/v1/scan", json={"text": "x", "mode": "REDACT"})

    assert len(received_principals) >= 1
    assert received_principals[0].id == "captured-id"
    assert received_principals[0].auth_method == "jwt"
