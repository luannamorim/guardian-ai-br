"""Integration: verify audit rows are materialized correctly for each event type."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

import httpx
import pytest
import pytest_asyncio

from guardian_br.api.settings import Settings
from guardian_br.core.auditor import Auditor
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from guardian_br.guardian import Guardian

_SALT = b"u" * 32


def _scan_hash(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


def _audit_hash(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest() + ":audit:read"


@pytest_asyncio.fixture
async def logging_app():  # type: ignore[no-untyped-def]
    from guardian_br.adversarial.ollama_classifier import _DisabledClassifier
    from guardian_br.api.app import create_app
    from guardian_br.api.dependencies import get_guardian, get_store
    from guardian_br.api.routes_health import HealthRegistry
    from guardian_br.core.kms import EnvKMSProvider

    scan_key = "logging-scan"
    audit_key = "logging-audit"
    settings = Settings(
        api_keys_hashed=frozenset({_scan_hash(scan_key), _audit_hash(audit_key)}),
        rate_limit_per_key="1000/second",
        metrics_require_auth=False,
    )
    os.environ.setdefault("GUARDIAN_BR_KEK_v1", base64.b64encode(secrets.token_bytes(32)).decode())
    os.environ.setdefault("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    store = SQLiteRedactStore(":memory:")
    auditor = Auditor(store=store, salt=_SALT)
    guardian = Guardian(
        redact_store=store,
        kms=EnvKMSProvider(),
        classifier=_DisabledClassifier(),  # type: ignore[arg-type]
        auditor=auditor,
    )

    app = create_app(settings=settings)
    app.dependency_overrides[get_guardian] = lambda: guardian
    app.dependency_overrides[get_store] = lambda: store

    health = HealthRegistry()

    async def _ok():  # type: ignore[return]
        return "ok"

    for name in ("analyzer", "redact_store", "kms", "llama_guard", "audit_log"):
        health.register(name, _ok)
    app.state.guardian = guardian
    app.state.settings = settings
    app.state.health = health
    app.state.store = store
    app.state.auditor = auditor

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client, store, scan_key, audit_key


@pytest.mark.asyncio
async def test_scan_produces_audit_row(logging_app) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, _ = logging_app
    resp = await client.post(
        "/v1/scan",
        json={"text": "hello world"},
        headers={"X-API-Key": scan_key},
    )
    assert resp.status_code == 200
    rows = store.query_audit()
    scan_rows = [r for r in rows if r.event_type == "scan"]
    assert len(scan_rows) >= 1
    row = scan_rows[0]
    assert row.principal_id is not None
    assert row.mode == "REDACT"
    assert row.latency_ms is not None and row.latency_ms >= 0
    assert row.input_hash is not None
    assert row.blocked is False


@pytest.mark.asyncio
async def test_scan_row_input_hash_not_plaintext(logging_app) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, _ = logging_app
    text = "meu cpf eh 123.456.789-09"
    await client.post("/v1/scan", json={"text": text}, headers={"X-API-Key": scan_key})
    rows = [r for r in store.query_audit() if r.event_type == "scan"]
    assert all("123.456.789-09" not in (r.input_hash or "") for r in rows)


@pytest.mark.asyncio
async def test_auth_failure_produces_audit_row(logging_app) -> None:  # type: ignore[no-untyped-def]
    client, store, _, _ = logging_app
    await client.post(
        "/v1/scan",
        json={"text": "hi"},
        headers={"X-API-Key": "bad-key"},
    )
    rows = [r for r in store.query_audit() if r.event_type == "auth_failure"]
    assert len(rows) >= 1
    assert rows[0].principal_id == "unknown"


@pytest.mark.asyncio
async def test_block_scan_still_writes_row(logging_app) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, _ = logging_app
    await client.post(
        "/v1/scan",
        json={"text": "hello", "mode": "BLOCK"},
        headers={"X-API-Key": scan_key},
    )
    rows = [r for r in store.query_audit() if r.event_type == "scan"]
    assert len(rows) >= 1
    assert rows[0].mode == "BLOCK"


@pytest.mark.asyncio
async def test_unmask_miss_writes_audit_row(logging_app) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, _ = logging_app
    fake_handle = "a" * 32
    resp = await client.post(
        "/v1/unmask",
        json={"handle": fake_handle},
        headers={"X-API-Key": scan_key},
    )
    assert resp.status_code == 404
    rows = [r for r in store.query_audit() if r.event_type == "unmask"]
    assert len(rows) >= 1
    assert rows[0].handle == fake_handle
    assert rows[0].blocked is True
