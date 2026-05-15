"""Tests for GET /v1/audit endpoint."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio

from guardian_br.api.settings import Settings
from guardian_br.core.auditor import Auditor
from guardian_br.core.redact_store import AuditRow
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from guardian_br.guardian import Guardian
from tests.api.conftest import make_test_app

_SALT = b"t" * 32
_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _audit_key_hash(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest() + ":audit:read"


def _scan_key_hash(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


@pytest_asyncio.fixture
async def audit_client():  # type: ignore[no-untyped-def]
    import base64
    import os
    import secrets as sec

    from guardian_br.adversarial.ollama_classifier import _DisabledClassifier
    from guardian_br.api.dependencies import get_store
    from guardian_br.core.kms import EnvKMSProvider

    scan_key = "my-scan-key"
    audit_key = "my-audit-key"
    settings = Settings(
        api_keys_hashed=frozenset(
            {
                _scan_key_hash(scan_key),
                _audit_key_hash(audit_key),
            }
        ),
        rate_limit_per_key="1000/second",
        metrics_require_auth=False,
    )
    os.environ.setdefault("GUARDIAN_BR_KEK_v1", base64.b64encode(sec.token_bytes(32)).decode())
    os.environ.setdefault("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    store = SQLiteRedactStore(":memory:")
    auditor = Auditor(store=store, salt=_SALT)
    guardian = Guardian(
        redact_store=store,
        kms=EnvKMSProvider(),
        classifier=_DisabledClassifier(),  # type: ignore[arg-type]
        auditor=auditor,
    )
    app = await make_test_app(settings, guardian)
    app.dependency_overrides[get_store] = lambda: store
    app.state.store = store
    app.state.auditor = auditor
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client, store, scan_key, audit_key


@pytest.mark.asyncio
async def test_no_auth_returns_401(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, *_ = audit_client
    resp = await client.get("/v1/audit")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_scan_key_returns_403(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, audit_key = audit_client
    resp = await client.get("/v1/audit", headers={"X-API-Key": scan_key})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_key_returns_rows(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, audit_key = audit_client
    store.append_audit(AuditRow(id="x1", timestamp=_TS, event_type="scan"))
    resp = await client.get("/v1/audit", headers={"X-API-Key": audit_key})
    assert resp.status_code == 200
    data = resp.json()
    assert "rows" in data
    assert any(r["id"] == "x1" for r in data["rows"])


@pytest.mark.asyncio
async def test_limit_parameter(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, audit_key = audit_client
    now = datetime.now(UTC)
    for i in range(5):
        store.append_audit(AuditRow(id=f"r{i}", timestamp=now, event_type="scan"))
    resp = await client.get("/v1/audit?limit=2", headers={"X-API-Key": audit_key})
    assert resp.status_code == 200
    assert len(resp.json()["rows"]) == 2


@pytest.mark.asyncio
async def test_next_since_pagination_cursor(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, audit_key = audit_client
    now = datetime.now(UTC)
    for i in range(3):
        store.append_audit(AuditRow(id=f"p{i}", timestamp=now, event_type="scan"))
    resp = await client.get("/v1/audit?limit=3", headers={"X-API-Key": audit_key})
    data = resp.json()
    assert data["next_since"] is not None


@pytest.mark.asyncio
async def test_no_raw_pii_in_audit_rows(audit_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key, audit_key = audit_client
    cpf = "123.456.789-09"
    await client.post(
        "/v1/scan",
        json={"text": f"meu cpf eh {cpf}"},
        headers={"X-API-Key": scan_key},
    )
    resp = await client.get("/v1/audit", headers={"X-API-Key": audit_key})
    body_str = resp.text
    assert cpf not in body_str
