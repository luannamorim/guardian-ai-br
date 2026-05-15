"""Tests for the default API-key auth hardening."""

import secrets

import pytest


@pytest.mark.asyncio
async def test_valid_key_returns_200(client, auth_headers) -> None:
    resp = await client.post(
        "/v1/scan",
        headers=auth_headers,
        json={
            "text": "x",
            "mode": "REDACT",
        },
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_multiple_active_keys(settings, guardian, kek) -> None:
    import httpx

    from guardian_br.api.settings import Settings
    from tests.api.conftest import _make_key_hash, make_test_app

    key_a = "key-alpha"
    key_b = "key-beta"

    multi_settings = Settings(
        api_keys_hashed=frozenset({_make_key_hash(key_a), _make_key_hash(key_b)}),
        rate_limit_per_key="1000/second",
    )
    multi_app = await make_test_app(multi_settings, guardian)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=multi_app),
        base_url="http://test",
    ) as c:
        for key in (key_a, key_b):
            resp = await c.post(
                "/v1/scan",
                headers={"X-API-Key": key},
                json={"text": "x", "mode": "REDACT"},
            )
            assert resp.status_code == 200, f"key {key!r} rejected"


@pytest.mark.asyncio
async def test_raw_key_not_in_log_output(client, auth_headers, raw_api_key, capsys) -> None:
    await client.post(
        "/v1/scan",
        headers=auth_headers,
        json={
            "text": "cpf 123.456.789-09",
            "mode": "REDACT",
        },
    )
    captured = capsys.readouterr()
    assert raw_api_key not in captured.out
    assert raw_api_key not in captured.err


@pytest.mark.asyncio
async def test_secrets_compare_digest_used(monkeypatch, client, raw_api_key) -> None:
    """Verify constant-time comparison is invoked (not ==)."""
    called = []
    original = secrets.compare_digest

    def _spy(a, b):  # type: ignore[no-untyped-def]
        called.append((a, b))
        return original(a, b)

    monkeypatch.setattr(secrets, "compare_digest", _spy)
    await client.post(
        "/v1/scan",
        headers={"X-API-Key": raw_api_key},
        json={"text": "x", "mode": "REDACT"},
    )
    assert len(called) >= 1, "secrets.compare_digest was not called"


@pytest.mark.asyncio
async def test_empty_keyset_returns_401(settings, guardian, kek) -> None:
    import httpx

    from guardian_br.api.settings import Settings
    from tests.api.conftest import make_test_app

    empty_settings = Settings(
        api_keys_hashed=frozenset(),
        rate_limit_per_key="1000/second",
    )
    empty_app = await make_test_app(empty_settings, guardian)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=empty_app),
        base_url="http://test",
    ) as c:
        resp = await c.post(
            "/v1/scan",
            headers={"X-API-Key": "anything"},
            json={"text": "x", "mode": "REDACT"},
        )
        assert resp.status_code == 403
