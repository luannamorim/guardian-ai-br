"""Tests for shadow mode through the REST API."""

from __future__ import annotations

import httpx
import pytest

from guardian_br import Guardian, Mode


@pytest.mark.asyncio
async def test_scan_shadow_per_request(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    payload = {"text": "meu cpf eh 123.456.789-09", "mode": "BLOCK", "shadow": True}
    resp = await client.post("/v1/scan", headers=auth_headers, json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["blocked"] is False
    assert body["shadow"] is True
    assert body["would_block"] is True
    assert body["redacted_text"] == "meu cpf eh <BR_CPF>"


@pytest.mark.asyncio
async def test_scan_block_without_shadow_returns_422(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
) -> None:
    payload = {"text": "meu cpf eh 123.456.789-09", "mode": "BLOCK"}
    resp = await client.post("/v1/scan", headers=auth_headers, json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_settings_shadow_mode_default(
    client: httpx.AsyncClient,
    auth_headers: dict[str, str],
    app,  # type: ignore[no-untyped-def]
    kek: str,
) -> None:
    # Replace app.state.guardian with one configured for shadow_mode=True.
    from guardian_br.adversarial.ollama_classifier import _DisabledClassifier
    from guardian_br.core.kms import EnvKMSProvider
    from guardian_br.core.sqlite_redact_store import SQLiteRedactStore

    g = Guardian(
        mode_default=Mode.BLOCK,
        shadow_mode=True,
        redact_store=SQLiteRedactStore(":memory:"),
        kms=EnvKMSProvider(),
        classifier=_DisabledClassifier(),  # type: ignore[arg-type]
    )
    from guardian_br.api.dependencies import get_guardian

    app.dependency_overrides[get_guardian] = lambda: g
    resp = await client.post(
        "/v1/scan",
        headers=auth_headers,
        json={"text": "meu cpf eh 123.456.789-09"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["blocked"] is False
    assert body["shadow"] is True
    assert body["would_block"] is True
