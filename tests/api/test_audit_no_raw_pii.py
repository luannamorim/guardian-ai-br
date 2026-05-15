"""Security gate: raw PII must never appear in audit log rows or logs."""

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

_SALT = b"v" * 32
_CPF = "529.982.247-25"  # valid CPF checksum


def _scan_hash(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


@pytest_asyncio.fixture
async def pii_client():  # type: ignore[no-untyped-def]
    from guardian_br.adversarial.ollama_classifier import _DisabledClassifier
    from guardian_br.api.app import create_app
    from guardian_br.api.dependencies import get_guardian, get_store
    from guardian_br.api.routes_health import HealthRegistry
    from guardian_br.core.kms import EnvKMSProvider

    scan_key = "pii-scan"
    settings = Settings(
        api_keys_hashed=frozenset({_scan_hash(scan_key)}),
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
        yield client, store, scan_key


@pytest.mark.asyncio
async def test_audit_rows_contain_no_raw_cpf(pii_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key = pii_client
    await client.post(
        "/v1/scan",
        json={"text": f"meu cpf eh {_CPF}"},
        headers={"X-API-Key": scan_key},
    )
    rows = store.query_audit()
    assert rows, "expected at least one audit row"
    for row in rows:
        dumped = row.model_dump_json()
        assert _CPF not in dumped, f"raw PII found in audit row: {row.id}"


@pytest.mark.asyncio
async def test_audit_rows_contain_no_raw_cpf_in_detections(pii_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key = pii_client
    await client.post(
        "/v1/scan",
        json={"text": f"meu cpf eh {_CPF}"},
        headers={"X-API-Key": scan_key},
    )
    for row in store.query_audit():
        for det in row.detections:
            for v in det.values():
                assert _CPF not in v


@pytest.mark.asyncio
async def test_input_hash_is_not_plaintext(pii_client) -> None:  # type: ignore[no-untyped-def]
    client, store, scan_key = pii_client
    text = f"meu cpf eh {_CPF}"
    await client.post("/v1/scan", json={"text": text}, headers={"X-API-Key": scan_key})
    rows = store.query_audit()
    for row in rows:
        assert row.input_hash != text
        if row.input_hash:
            assert _CPF not in row.input_hash
