"""Tests for dashboard/client.py using httpx.MockTransport."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from guardian_br.dashboard.client import AuditClient, DashboardAuthError

_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _row_dict(id: str, ts: datetime = _TS) -> dict[str, object]:
    return {
        "id": id,
        "timestamp": ts.isoformat(),
        "event_type": "scan",
        "principal_id": None,
        "client_ip": None,
        "request_fingerprint": None,
        "input_hash": None,
        "salt_key_id": None,
        "mode": None,
        "latency_ms": None,
        "detections": [],
        "adversarial_label": None,
        "adversarial_unsafe": None,
        "blocked": None,
        "handle": None,
        "entity_type": None,
        "hmac_prev": None,
        "hmac_self": None,
    }


def _page(rows: list[dict[str, object]], next_since: str | None) -> httpx.Response:
    body = {"rows": rows, "next_since": next_since}
    return httpx.Response(
        200,
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )


def _client(transport: httpx.MockTransport) -> AuditClient:
    c = AuditClient("http://test", "key", timeout_s=5)
    c._http = httpx.Client(transport=transport, base_url="http://test")
    return c


# ── single page ───────────────────────────────────────────────────────────────


def test_fetch_single_page_returns_all_rows() -> None:
    rows_data = [_row_dict("r1"), _row_dict("r2")]

    def handler(req: httpx.Request) -> httpx.Response:
        return _page(rows_data, None)

    rows = _client(httpx.MockTransport(handler)).fetch()
    assert len(rows) == 2
    assert rows[0].id == "r1"
    assert rows[1].id == "r2"


def test_fetch_empty_page_returns_empty_list() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return _page([], None)

    assert _client(httpx.MockTransport(handler)).fetch() == []


# ── pagination ────────────────────────────────────────────────────────────────


def test_fetch_walks_cursor_across_pages() -> None:
    page1 = [_row_dict("r1"), _row_dict("r2")]
    page2 = [_row_dict("r3")]
    calls: list[str | None] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.params.get("until"))
        if len(calls) == 1:
            return _page(page1, _TS.isoformat())
        return _page(page2, None)

    rows = _client(httpx.MockTransport(handler)).fetch()
    assert len(rows) == 3
    assert len(calls) == 2
    assert calls[1] == _TS.isoformat()  # cursor was passed on second request


def test_fetch_deduplicates_boundary_overlap() -> None:
    ts_boundary = _TS
    page1 = [_row_dict("r1", _TS + timedelta(seconds=1)), _row_dict("r2", ts_boundary)]
    page2 = [_row_dict("r2", ts_boundary), _row_dict("r3", _TS - timedelta(seconds=1))]
    call_count = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        if call_count[0] == 1:
            return _page(page1, ts_boundary.isoformat())
        return _page(page2, None)

    rows = _client(httpx.MockTransport(handler)).fetch()
    ids = [r.id for r in rows]
    assert ids.count("r2") == 1
    assert len(rows) == 3


def test_fetch_stops_at_max_rows() -> None:
    page_data = [_row_dict(f"r{i}") for i in range(10)]
    call_count = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        limit = int(req.url.params.get("limit", 1000))
        subset = page_data[:limit]
        next_since = _TS.isoformat() if len(page_data) > limit else None
        return _page(subset, next_since)

    rows = _client(httpx.MockTransport(handler)).fetch(max_rows=3)
    assert len(rows) <= 3


# ── auth errors ───────────────────────────────────────────────────────────────


def test_fetch_raises_auth_error_on_401() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    with pytest.raises(DashboardAuthError) as exc_info:
        _client(httpx.MockTransport(handler)).fetch()
    assert exc_info.value.status_code == 401


def test_fetch_raises_auth_error_on_403() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    with pytest.raises(DashboardAuthError) as exc_info:
        _client(httpx.MockTransport(handler)).fetch()
    assert exc_info.value.status_code == 403


def test_fetch_raises_http_error_on_500() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with pytest.raises(httpx.HTTPStatusError):
        _client(httpx.MockTransport(handler)).fetch()
