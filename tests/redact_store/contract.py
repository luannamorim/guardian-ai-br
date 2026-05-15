"""RedactStore contract test suite.

Adapter packages (guardrails-br-postgres, guardrails-br-redis) must subclass
RedactStoreContractTests and provide a ``store`` fixture. All tests in this
mixin must pass before an adapter can be considered compliant.

Usage::

    class TestMyAdapterContract(RedactStoreContractTests):
        @pytest.fixture
        def store(self):
            return MyAdapterStore(...)
"""

from datetime import UTC, datetime, timedelta

import pytest

from guardian_br.core.entities import BR_CPF
from guardian_br.core.redact_store import AuditRow, RedactRecord


def _make_record(
    handle: str = "abc123",
    entity_type: str = BR_CPF,
    *,
    expires_at: datetime | None = None,
) -> RedactRecord:
    now = datetime.now(UTC)
    return RedactRecord(
        handle=handle,
        wrapped_dek=b"fake-wrapped-dek",
        kek_key_id="v1",
        nonce=b"\x00" * 12,
        ciphertext=b"fake-ciphertext",
        entity_type=entity_type,
        created_at=now,
        expires_at=expires_at,
    )


class RedactStoreContractTests:
    """Mixin. Subclass and provide a ``store`` fixture."""

    @pytest.fixture
    def store(self):  # type: ignore[override]
        raise NotImplementedError("Subclass must provide a store fixture")

    def test_put_get_roundtrip(self, store) -> None:  # type: ignore[override]
        rec = _make_record()
        store.put(rec)
        result = store.get(rec.handle)
        assert result is not None
        assert result.handle == rec.handle
        assert result.wrapped_dek == rec.wrapped_dek
        assert result.kek_key_id == rec.kek_key_id
        assert result.nonce == rec.nonce
        assert result.ciphertext == rec.ciphertext
        assert result.entity_type == rec.entity_type

    def test_get_unknown_handle_returns_none(self, store) -> None:  # type: ignore[override]
        result = store.get("00000000000000000000000000000000")
        assert result is None

    def test_delete_removes_record(self, store) -> None:  # type: ignore[override]
        rec = _make_record(handle="del-me")
        store.put(rec)
        assert store.delete("del-me") is True
        assert store.get("del-me") is None

    def test_delete_returns_false_on_miss(self, store) -> None:  # type: ignore[override]
        assert store.delete("nonexistent-handle") is False

    def test_put_handle_collision_raises(self, store) -> None:  # type: ignore[override]
        from guardian_br.core.sqlite_redact_store import HandleCollisionError

        rec = _make_record(handle="collision-handle")
        store.put(rec)
        with pytest.raises((HandleCollisionError, Exception)):
            store.put(rec)

    def test_ttl_expiry(self, store) -> None:  # type: ignore[override]
        past = datetime.now(UTC) - timedelta(seconds=1)
        rec = _make_record(handle="expired-handle", expires_at=past)
        store.put(rec)
        result = store.get(rec.handle)
        assert result is None

    def test_no_expiry_record_persists(self, store) -> None:  # type: ignore[override]
        rec = _make_record(handle="no-expiry", expires_at=None)
        store.put(rec)
        assert store.get("no-expiry") is not None

    def test_ping_returns_true(self, store) -> None:  # type: ignore[override]
        assert store.ping() is True

    def test_query_audit_empty_store(self, store) -> None:  # type: ignore[override]
        rows = store.query_audit()
        assert rows == []

    def test_query_audit_round_trip(self, store) -> None:  # type: ignore[override]
        row = AuditRow(
            id="abc123",
            timestamp=datetime.now(UTC),
            event_type="scan",
            principal_id="p1",
            mode="REDACT",
            latency_ms=5.0,
            detections=[{"entity_type": "BR_CPF", "lgpd_article": "Art. 5"}],
            blocked=False,
        )
        store.append_audit(row)
        results = store.query_audit()
        assert len(results) == 1
        assert results[0].id == "abc123"
        assert results[0].event_type == "scan"
        assert results[0].principal_id == "p1"
        assert results[0].detections == [{"entity_type": "BR_CPF", "lgpd_article": "Art. 5"}]

    def test_query_audit_since_filter(self, store) -> None:  # type: ignore[override]
        now = datetime.now(UTC)
        past = now - timedelta(seconds=10)
        store.append_audit(
            AuditRow(id="old1", timestamp=past, event_type="scan", principal_id="p1")
        )
        store.append_audit(AuditRow(id="new1", timestamp=now, event_type="scan", principal_id="p2"))
        results = store.query_audit(since=now)
        ids = {r.id for r in results}
        assert "new1" in ids
        assert "old1" not in ids

    def test_query_audit_limit(self, store) -> None:  # type: ignore[override]
        now = datetime.now(UTC)
        for i in range(5):
            store.append_audit(
                AuditRow(id=f"row{i}", timestamp=now, event_type="scan", principal_id="p")
            )
        results = store.query_audit(limit=3)
        assert len(results) == 3

    def test_query_audit_ordering(self, store) -> None:  # type: ignore[override]
        now = datetime.now(UTC)
        earlier = now - timedelta(seconds=5)
        store.append_audit(
            AuditRow(id="first", timestamp=earlier, event_type="scan", principal_id="p")
        )
        store.append_audit(
            AuditRow(id="second", timestamp=now, event_type="scan", principal_id="p")
        )
        results = store.query_audit()
        assert results[0].id == "second"
        assert results[1].id == "first"
