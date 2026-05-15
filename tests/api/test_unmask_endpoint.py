"""Tests for POST /v1/unmask."""

import pytest


@pytest.mark.asyncio
async def test_unmask_hit(client, auth_headers) -> None:
    scan_resp = await client.post(
        "/v1/scan",
        headers=auth_headers,
        json={
            "text": "cpf 123.456.789-09",
            "mode": "REVERSIBLE_REDACT",
        },
    )
    handle = scan_resp.json()["detections"][0]["redact_token"]

    resp = await client.post("/v1/unmask", headers=auth_headers, json={"handle": handle})
    assert resp.status_code == 200
    assert resp.json()["value"] == "123.456.789-09"


@pytest.mark.asyncio
async def test_unmask_unknown_handle_returns_404(client, auth_headers) -> None:
    resp = await client.post(
        "/v1/unmask",
        headers=auth_headers,
        json={
            "handle": "0" * 32,
        },
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "handle_not_found"


@pytest.mark.asyncio
async def test_unmask_uniform_404_body(client, auth_headers) -> None:
    """All miss cases return the same response body (no oracle)."""
    resp1 = await client.post("/v1/unmask", headers=auth_headers, json={"handle": "0" * 32})
    resp2 = await client.post("/v1/unmask", headers=auth_headers, json={"handle": "a" * 32})
    assert resp1.status_code == resp2.status_code == 404
    assert resp1.json()["code"] == resp2.json()["code"] == "handle_not_found"
    assert resp1.json()["detail"] == resp2.json()["detail"]


@pytest.mark.asyncio
async def test_unmask_malformed_handle_returns_422(client, auth_headers) -> None:
    resp = await client.post("/v1/unmask", headers=auth_headers, json={"handle": "short"})
    assert resp.status_code == 422
    assert resp.json()["code"] == "validation_error"


@pytest.mark.asyncio
async def test_unmask_non_hex_handle_returns_422(client, auth_headers) -> None:
    resp = await client.post(
        "/v1/unmask",
        headers=auth_headers,
        json={
            "handle": "Z" * 32,  # uppercase Z is not hex
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_unmask_missing_api_key_returns_401(client) -> None:
    resp = await client.post("/v1/unmask", json={"handle": "0" * 32})
    assert resp.status_code == 401
