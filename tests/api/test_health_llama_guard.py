"""Tests for /healthz with llama_guard component."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_healthz_includes_llama_guard_component(client, auth_headers) -> None:
    resp = await client.get("/v1/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert "llama_guard" in data["components"]
    assert data["components"]["llama_guard"] == "ok"


@pytest.mark.asyncio
async def test_healthz_503_when_llama_guard_fails(app, auth_headers) -> None:
    import httpx

    from guardian_br.api.routes_health import HealthRegistry

    health = HealthRegistry()

    async def _ok() -> str:
        return "ok"

    async def _fail() -> str:
        return "fail"

    health.register("analyzer", _ok)  # type: ignore[arg-type]
    health.register("redact_store", _ok)  # type: ignore[arg-type]
    health.register("kms", _ok)  # type: ignore[arg-type]
    health.register("llama_guard", _fail)  # type: ignore[arg-type]
    app.state.health = health

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as tmp_client:
        resp = await tmp_client.get("/v1/healthz")
    assert resp.status_code == 503
    assert resp.json()["components"]["llama_guard"] == "fail"


@pytest.mark.asyncio
async def test_healthz_skipped_when_disabled(app) -> None:
    import httpx

    from guardian_br.api.routes_health import HealthRegistry

    health = HealthRegistry()

    async def _ok() -> str:
        return "ok"

    async def _skipped() -> str:
        return "skipped"

    health.register("analyzer", _ok)  # type: ignore[arg-type]
    health.register("redact_store", _ok)  # type: ignore[arg-type]
    health.register("kms", _ok)  # type: ignore[arg-type]
    health.register("llama_guard", _skipped)  # type: ignore[arg-type]
    app.state.health = health

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as tmp_client:
        resp = await tmp_client.get("/v1/healthz")
    assert resp.status_code == 200
    assert resp.json()["components"]["llama_guard"] == "skipped"
    assert resp.json()["status"] == "ready"
