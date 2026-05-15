"""Tests for api/scopes.py and scope-aware key format."""

from __future__ import annotations

import hashlib

import httpx
import pytest
import pytest_asyncio

from guardian_br.api.settings import Settings
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from guardian_br.guardian import Guardian
from tests.api.conftest import make_test_app


def _key_hash(key: str, *, scope: str | None = None) -> str:
    h = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
    if scope:
        return h + ":" + scope
    return h


@pytest_asyncio.fixture
async def scope_client():  # type: ignore[no-untyped-def]
    """App with two keys: scan-only and audit:read-scoped."""
    import base64
    import secrets as sec

    from guardian_br.adversarial.ollama_classifier import _DisabledClassifier
    from guardian_br.core.kms import EnvKMSProvider

    scan_key = "test-scan-key"
    audit_key = "test-audit-key"
    settings = Settings(
        api_keys_hashed=frozenset(
            {
                _key_hash(scan_key),
                _key_hash(audit_key, scope="audit:read"),
            }
        ),
        rate_limit_per_key="1000/second",
        metrics_require_auth=False,
    )
    import os

    os.environ.setdefault("GUARDIAN_BR_KEK_v1", base64.b64encode(sec.token_bytes(32)).decode())
    os.environ.setdefault("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    store = SQLiteRedactStore(":memory:")
    guardian = Guardian(
        redact_store=store,
        kms=EnvKMSProvider(),
        classifier=_DisabledClassifier(),  # type: ignore[arg-type]
    )
    app = await make_test_app(settings, guardian)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client, scan_key, audit_key


@pytest.mark.asyncio
async def test_scan_key_can_scan(scope_client) -> None:  # type: ignore[no-untyped-def]
    client, scan_key, _ = scope_client
    resp = await client.post(
        "/v1/scan",
        json={"text": "hello"},
        headers={"X-API-Key": scan_key},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scan_key_cannot_read_audit(scope_client) -> None:  # type: ignore[no-untyped-def]
    client, scan_key, _ = scope_client
    resp = await client.get("/v1/audit", headers={"X-API-Key": scan_key})
    assert resp.status_code == 403
    assert "audit:read" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_audit_key_can_read_audit(scope_client) -> None:  # type: ignore[no-untyped-def]
    client, _, audit_key = scope_client
    resp = await client.get("/v1/audit", headers={"X-API-Key": audit_key})
    assert resp.status_code == 200
    data = resp.json()
    assert "rows" in data


@pytest.mark.asyncio
async def test_audit_key_can_also_scan(scope_client) -> None:  # type: ignore[no-untyped-def]
    client, _, audit_key = scope_client
    resp = await client.post(
        "/v1/scan",
        json={"text": "hello"},
        headers={"X-API-Key": audit_key},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_no_key_returns_401(scope_client) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = scope_client
    resp = await client.get("/v1/audit")
    assert resp.status_code == 401
