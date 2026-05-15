"""SQLite-specific audit log tests (round-trip, filters, purge)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from guardian_br.core.redact_store import AuditRow
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore

_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _store() -> SQLiteRedactStore:
    return SQLiteRedactStore(":memory:")


def _row(id: str, ts: datetime | None = None, **kwargs: object) -> AuditRow:
    return AuditRow(id=id, timestamp=ts or _TS, event_type="scan", **kwargs)  # type: ignore[arg-type]


def test_empty_store_query_returns_empty() -> None:
    assert _store().query_audit() == []


def test_append_and_query_roundtrip() -> None:
    store = _store()
    row = AuditRow(
        id="r1",
        timestamp=_TS,
        event_type="scan",
        principal_id="p1",
        mode="REDACT",
        latency_ms=3.5,
        detections=[{"entity_type": "BR_CPF", "lgpd_article": "Art. 5"}],
        adversarial_label="safe",
        adversarial_unsafe=False,
        blocked=False,
    )
    store.append_audit(row)
    result = store.query_audit()[0]
    assert result.id == "r1"
    assert result.principal_id == "p1"
    assert result.mode == "REDACT"
    assert result.latency_ms == 3.5
    assert result.detections == [{"entity_type": "BR_CPF", "lgpd_article": "Art. 5"}]
    assert result.adversarial_label == "safe"
    assert result.adversarial_unsafe is False
    assert result.blocked is False


def test_since_filter() -> None:
    store = _store()
    now = datetime.now(UTC)
    store.append_audit(_row("old", ts=now - timedelta(minutes=10)))
    store.append_audit(_row("new", ts=now))
    results = store.query_audit(since=now - timedelta(seconds=1))
    ids = {r.id for r in results}
    assert "new" in ids
    assert "old" not in ids


def test_until_filter() -> None:
    store = _store()
    now = datetime.now(UTC)
    store.append_audit(_row("old", ts=now - timedelta(minutes=10)))
    store.append_audit(_row("new", ts=now))
    results = store.query_audit(until=now - timedelta(seconds=1))
    ids = {r.id for r in results}
    assert "old" in ids
    assert "new" not in ids


def test_limit() -> None:
    store = _store()
    for i in range(10):
        store.append_audit(_row(str(i)))
    assert len(store.query_audit(limit=3)) == 3


def test_ordering_descending() -> None:
    store = _store()
    now = datetime.now(UTC)
    store.append_audit(_row("first", ts=now - timedelta(seconds=5)))
    store.append_audit(_row("second", ts=now))
    results = store.query_audit()
    assert results[0].id == "second"
    assert results[1].id == "first"


def test_hmac_fields_round_trip() -> None:
    store = _store()
    row = AuditRow(
        id="h1",
        timestamp=_TS,
        event_type="scan",
        hmac_prev="prevhash",
        hmac_self="selfhash",
    )
    store.append_audit(row)
    result = store.query_audit()[0]
    assert result.hmac_prev == "prevhash"
    assert result.hmac_self == "selfhash"


def test_purge_audit_removes_old_rows() -> None:
    store = _store()
    now = datetime.now(UTC)
    store.append_audit(_row("old1", ts=now - timedelta(days=2)))
    store.append_audit(_row("old2", ts=now - timedelta(days=1)))
    store.append_audit(_row("recent", ts=now))
    purged = store.purge_audit(before=now - timedelta(hours=1))
    assert purged == 2
    remaining = store.query_audit()
    assert len(remaining) == 1
    assert remaining[0].id == "recent"


def test_nullable_fields_round_trip() -> None:
    store = _store()
    row = AuditRow(id="nullable", timestamp=_TS, event_type="auth_failure")
    store.append_audit(row)
    result = store.query_audit()[0]
    assert result.principal_id is None
    assert result.input_hash is None
    assert result.adversarial_unsafe is None
    assert result.blocked is None
