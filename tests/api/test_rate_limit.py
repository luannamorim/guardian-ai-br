"""Tests for per-principal rate limiting."""

import httpx
import pytest

from guardian_br.api.settings import Settings
from tests.api.conftest import _make_key_hash, make_test_app


async def _make_rate_limited_app(guardian):  # type: ignore[no-untyped-def]
    """Create an app with 1/second limit for testability."""
    key = "rate-test-key"
    tight_settings = Settings(
        api_keys_hashed=frozenset({_make_key_hash(key)}),
        rate_limit_per_key="1/second",
    )
    return await make_test_app(tight_settings, guardian), key


@pytest.mark.asyncio
async def test_rate_limit_exceeded_returns_429(guardian, kek) -> None:
    tight_app, key = await _make_rate_limited_app(guardian)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=tight_app),
        base_url="http://test",
    ) as c:
        # First request should pass
        r1 = await c.post(
            "/v1/scan",
            headers={"X-API-Key": key},
            json={"text": "x", "mode": "REDACT"},
        )
        # Second request within the same second window
        r2 = await c.post(
            "/v1/scan",
            headers={"X-API-Key": key},
            json={"text": "x", "mode": "REDACT"},
        )
        # At least one of the two must fail (or the first passes and second is 429)
        statuses = {r1.status_code, r2.status_code}
        assert 429 in statuses, f"Expected 429 in {statuses}"


@pytest.mark.asyncio
async def test_rate_limit_429_shape(guardian, kek) -> None:
    tight_app, key = await _make_rate_limited_app(guardian)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=tight_app),
        base_url="http://test",
    ) as c:
        responses = [
            await c.post(
                "/v1/scan",
                headers={"X-API-Key": key},
                json={"text": "x", "mode": "REDACT"},
            )
            for _ in range(3)
        ]
    rate_limited = [r for r in responses if r.status_code == 429]
    assert len(rate_limited) >= 1
    body = rate_limited[0].json()
    assert body["code"] == "rate_limited"


@pytest.mark.asyncio
async def test_different_keys_separate_buckets(guardian, kek) -> None:
    key_a = "bucket-key-a"
    key_b = "bucket-key-b"

    tight_settings = Settings(
        api_keys_hashed=frozenset({_make_key_hash(key_a), _make_key_hash(key_b)}),
        rate_limit_per_key="1/second",
    )
    tight_app = await make_test_app(tight_settings, guardian)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=tight_app),
        base_url="http://test",
    ) as c:
        ra = await c.post(
            "/v1/scan",
            headers={"X-API-Key": key_a},
            json={"text": "x", "mode": "REDACT"},
        )
        rb = await c.post(
            "/v1/scan",
            headers={"X-API-Key": key_b},
            json={"text": "x", "mode": "REDACT"},
        )
        # Both first requests should succeed (different buckets)
        assert ra.status_code == 200
        assert rb.status_code == 200
