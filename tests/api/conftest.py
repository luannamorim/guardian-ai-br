"""Shared fixtures for API tests."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from guardian_br.api.auth import Principal
from guardian_br.api.settings import Settings
from guardian_br.core.kms import EnvKMSProvider
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from guardian_br.guardian import Guardian


def _make_key_hash(key: str) -> str:
    """Return the ``sha256:<hex>`` hash of an API key, matching Settings format."""
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


async def make_test_app(settings: Settings, guardian: Guardian) -> FastAPI:
    """Create a test app with state pre-seeded, bypassing the real lifespan."""
    from guardian_br.api.app import create_app
    from guardian_br.api.dependencies import get_guardian
    from guardian_br.api.routes_health import HealthRegistry

    created = create_app(settings=settings)
    created.dependency_overrides[get_guardian] = lambda: guardian

    health = HealthRegistry()

    async def _ok():  # type: ignore[return]
        return "ok"

    health.register("analyzer", _ok)
    health.register("redact_store", _ok)
    health.register("kms", _ok)
    created.state.guardian = guardian
    created.state.settings = settings
    created.state.health = health
    return created


@pytest.fixture
def raw_api_key() -> str:
    return "test-api-key-AAA"


@pytest.fixture
def hashed_api_key(raw_api_key: str) -> str:
    return "sha256:" + hashlib.sha256(raw_api_key.encode()).hexdigest()


@pytest.fixture
def kek(monkeypatch: pytest.MonkeyPatch) -> str:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", key)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    return key


@pytest.fixture
def settings(hashed_api_key: str) -> Settings:
    return Settings(
        api_keys_hashed=frozenset({hashed_api_key}),
        rate_limit_per_key="1000/second",
        metrics_require_auth=True,
    )


@pytest.fixture
def guardian(kek: str) -> Guardian:
    store = SQLiteRedactStore(":memory:")
    kms = EnvKMSProvider()
    return Guardian(redact_store=store, kms=kms)


@pytest_asyncio.fixture
async def app(settings: Settings, guardian: Guardian, kek: str):  # type: ignore[no-untyped-def]
    from guardian_br.api.app import create_app

    created = create_app(settings=settings)

    # Override guardian with the test instance (pre-warmed store/kms)
    from guardian_br.api.dependencies import get_guardian

    created.dependency_overrides[get_guardian] = lambda: guardian

    async with _lifespan_shim(created, guardian, settings):
        yield created


@asynccontextmanager
async def _lifespan_shim(
    app,  # type: ignore[no-untyped-def]
    guardian: Guardian,
    settings: Settings,
) -> AsyncGenerator[None, None]:
    """Set up app.state without going through the real lifespan (which tries to read KMS env)."""
    from guardian_br.api.routes_health import HealthRegistry

    health = HealthRegistry()

    async def _ok():  # type: ignore[return]
        return "ok"

    health.register("analyzer", _ok)
    health.register("redact_store", _ok)
    health.register("kms", _ok)

    app.state.guardian = guardian
    app.state.settings = settings
    app.state.health = health
    yield


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[httpx.AsyncClient, None]:  # type: ignore[no-untyped-def]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def auth_headers(raw_api_key: str) -> dict[str, str]:
    return {"X-API-Key": raw_api_key}


@pytest.fixture
def override_principal_fixture():  # type: ignore[no-untyped-def]
    """Returns a factory that creates a fixed Principal for dependency override."""

    def _make(*, id: str = "overridden", auth_method: str = "jwt") -> Principal:
        return Principal(id=id, key_hash="x" * 64, auth_method=auth_method)  # type: ignore[arg-type]

    return _make
