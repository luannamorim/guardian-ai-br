"""Tests for GET /v1/metrics."""

import pytest


@pytest.mark.asyncio
async def test_metrics_content_type(client, auth_headers) -> None:
    resp = await client.get("/v1/metrics", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_metrics_parseable(client, auth_headers) -> None:
    resp = await client.get("/v1/metrics", headers=auth_headers)
    assert resp.status_code == 200
    # Prometheus text format: lines starting with # or metric_name{...} value
    lines = [ln for ln in resp.text.splitlines() if ln and not ln.startswith("#")]
    assert len(lines) > 0


@pytest.mark.asyncio
async def test_metrics_counter_increments_after_scan(client, auth_headers) -> None:
    await client.post(
        "/v1/scan",
        headers=auth_headers,
        json={
            "text": "cpf 123.456.789-09",
            "mode": "REDACT",
        },
    )
    resp = await client.get("/v1/metrics", headers=auth_headers)
    assert "guardian_scan_total" in resp.text


@pytest.mark.asyncio
async def test_metrics_requires_auth_when_enabled(client) -> None:
    resp = await client.get("/v1/metrics")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_metrics_no_auth_when_disabled(settings, guardian, kek) -> None:
    import httpx

    from guardian_br.api.settings import Settings
    from tests.api.conftest import make_test_app

    open_settings = Settings(
        api_keys_hashed=settings.api_keys_hashed,
        rate_limit_per_key="1000/second",
        metrics_require_auth=False,
    )
    open_app = await make_test_app(open_settings, guardian)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=open_app),
        base_url="http://test",
    ) as c:
        resp = await c.get("/v1/metrics")
        assert resp.status_code == 200
