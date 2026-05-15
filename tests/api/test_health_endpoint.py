"""Tests for GET /v1/healthz."""

import pytest


@pytest.mark.asyncio
async def test_healthz_ready(client) -> None:
    resp = await client.get("/v1/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert all(v == "ok" for v in data["components"].values())


@pytest.mark.asyncio
async def test_healthz_not_ready_on_fail(app, client) -> None:
    from guardian_br.api.routes_health import HealthRegistry

    health = HealthRegistry()

    async def _ok() -> str:  # type: ignore[return]
        return "ok"

    async def _fail() -> str:  # type: ignore[return]
        return "fail"

    health.register("analyzer", _ok)
    health.register("redact_store", _fail)
    app.state.health = health

    resp = await client.get("/v1/healthz")
    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"


@pytest.mark.asyncio
async def test_healthz_components_shape(client) -> None:
    resp = await client.get("/v1/healthz")
    data = resp.json()
    assert isinstance(data["components"], dict)
    for v in data["components"].values():
        assert v in ("ok", "fail", "skipped")


@pytest.mark.asyncio
async def test_healthz_schema_version(client) -> None:
    resp = await client.get("/v1/healthz")
    assert resp.json()["schema_version"] == "3"
