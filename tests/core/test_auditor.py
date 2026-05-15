"""Tests for core/auditor.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from guardian_br.core.audit_fallback import FallbackAuditWriter
from guardian_br.core.auditor import Auditor, _DisabledAuditor
from guardian_br.core.redact_store import AuditRow
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore

_SALT = b"s" * 32
_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _store() -> SQLiteRedactStore:
    return SQLiteRedactStore(":memory:")


def _row() -> AuditRow:
    return AuditRow(id="abc", timestamp=_TS, event_type="scan")


def test_append_writes_to_store() -> None:
    store = _store()
    auditor = Auditor(store=store, salt=_SALT)
    auditor.append(_row())
    assert len(store.query_audit()) == 1


def test_append_calls_on_write_ok() -> None:
    store = _store()
    called_with: list[str] = []
    auditor = Auditor(store=store, salt=_SALT, on_write_ok=called_with.append)
    auditor.append(_row())
    assert called_with == ["scan"]


def test_append_falls_back_to_file_on_store_error(tmp_path: Path) -> None:
    path = tmp_path / "fallback.jsonl"

    class BrokenStore:
        def append_audit(self, row: AuditRow) -> None:
            raise RuntimeError("store is down")

        def query_audit(self, **kwargs: object) -> list[AuditRow]:
            raise RuntimeError("down")

        def ping(self) -> bool:
            return False

    fallback_called: list[str] = []
    auditor = Auditor(
        store=BrokenStore(),  # type: ignore[arg-type]
        salt=_SALT,
        fallback=FallbackAuditWriter(path),
        on_fallback=fallback_called.append,
    )
    auditor.append(_row())
    assert path.exists()
    assert fallback_called == ["store_unreachable"]


def test_append_drops_on_both_failures() -> None:
    """When store and fallback both fail, append must not raise."""

    class BrokenStore:
        def append_audit(self, row: AuditRow) -> None:
            raise RuntimeError("down")

        def query_audit(self, **kwargs: object) -> list[AuditRow]:
            raise RuntimeError("down")

        def ping(self) -> bool:
            return False

    class BrokenFallback:
        def append(self, row: AuditRow) -> None:
            raise OSError("disk full")

    fallback_called: list[str] = []
    auditor = Auditor(
        store=BrokenStore(),  # type: ignore[arg-type]
        salt=_SALT,
        fallback=BrokenFallback(),  # type: ignore[arg-type]
        on_fallback=fallback_called.append,
    )
    auditor.append(_row())  # must not raise
    assert "disk_full" in fallback_called


def test_record_scan_writes_row() -> None:
    store = _store()
    auditor = Auditor(store=store, salt=_SALT)

    class FakeDet:
        entity_type = "BR_CPF"
        lgpd_article = "Art. 5"

    auditor.record_scan(
        text="hello",
        principal_id="p1",
        client_ip="127.0.0.1",
        request_fingerprint="abc",
        mode="REDACT",
        detections=[FakeDet()],  # type: ignore[list-item]
        adversarial=None,
        latency_ms=5.0,
        blocked=False,
    )
    rows = store.query_audit()
    assert rows[0].event_type == "scan"
    assert rows[0].principal_id == "p1"
    assert rows[0].mode == "REDACT"
    assert rows[0].detections == [{"entity_type": "BR_CPF", "lgpd_article": "Art. 5"}]


def test_record_scan_input_hash_not_raw_text() -> None:
    store = _store()
    auditor = Auditor(store=store, salt=_SALT)
    sensitive = "123.456.789-09"

    auditor.record_scan(
        text=sensitive,
        principal_id="p",
        client_ip=None,
        request_fingerprint=None,
        mode="REDACT",
        detections=[],
        adversarial=None,
        latency_ms=1.0,
        blocked=False,
    )
    rows = store.query_audit()
    assert rows[0].input_hash != sensitive
    assert sensitive not in (rows[0].input_hash or "")


def test_record_auth_failure_writes_row() -> None:
    store = _store()
    auditor = Auditor(store=store, salt=_SALT)
    auditor.record_auth_failure(client_ip="1.2.3.4", request_fingerprint="fp", reason="missing")
    rows = store.query_audit()
    assert rows[0].event_type == "auth_failure"
    assert rows[0].principal_id == "unknown"


def test_hmac_chain_populates_hmac_self() -> None:
    store = _store()
    auditor = Auditor(store=store, salt=_SALT, hmac_chain=True, hmac_secret=b"k" * 32)
    auditor.append(_row())
    rows = store.query_audit()
    assert rows[0].hmac_self is not None
    assert len(rows[0].hmac_self) == 64


def test_disabled_auditor_is_noop() -> None:
    da = _DisabledAuditor()
    da.record_scan(
        text="x",
        principal_id=None,
        client_ip=None,
        request_fingerprint=None,
        mode="REDACT",
        detections=[],
        adversarial=None,
        latency_ms=0.0,
        blocked=False,
    )
    da.record_unmask(handle="h", principal_id=None, success=True)
    da.record_handle_event(action="handle_put", handle="h", entity_type="BR_CPF")
    da.record_auth_failure(client_ip=None, request_fingerprint=None, reason="missing")
