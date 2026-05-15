"""Tests for core/audit_chain.py."""

from __future__ import annotations

from datetime import UTC, datetime

from guardian_br.core.audit_chain import compute_hmac, verify_chain
from guardian_br.core.redact_store import AuditRow

_SECRET = b"s" * 32
_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _row(id: str = "abc", **kwargs: object) -> AuditRow:
    return AuditRow(id=id, timestamp=_TS, event_type="scan", **kwargs)  # type: ignore[arg-type]


def test_compute_hmac_returns_hex() -> None:
    row = _row()
    h = compute_hmac(row, None, _SECRET)
    assert len(h) == 64
    int(h, 16)


def test_compute_hmac_deterministic() -> None:
    row = _row()
    assert compute_hmac(row, None, _SECRET) == compute_hmac(row, None, _SECRET)


def test_compute_hmac_changes_with_prev() -> None:
    row = _row()
    h1 = compute_hmac(row, None, _SECRET)
    h2 = compute_hmac(row, "prev_hash", _SECRET)
    assert h1 != h2


def test_compute_hmac_changes_with_secret() -> None:
    row = _row()
    h1 = compute_hmac(row, None, b"a" * 32)
    h2 = compute_hmac(row, None, b"b" * 32)
    assert h1 != h2


def test_verify_chain_empty() -> None:
    assert verify_chain([], _SECRET) == []


def test_verify_chain_single_row_no_hmac() -> None:
    row = _row()
    bad = verify_chain([row], _SECRET)
    assert 0 in bad


def test_verify_chain_valid_chain() -> None:
    r1 = _row("r1")
    h1 = compute_hmac(r1, None, _SECRET)
    r1 = r1.model_copy(update={"hmac_self": h1})

    r2 = _row("r2")
    h2 = compute_hmac(r2, h1, _SECRET)
    r2 = r2.model_copy(update={"hmac_prev": h1, "hmac_self": h2})

    assert verify_chain([r1, r2], _SECRET) == []


def test_verify_chain_detects_tampered_row() -> None:
    r1 = _row("r1")
    h1 = compute_hmac(r1, None, _SECRET)
    r1 = r1.model_copy(update={"hmac_self": h1})

    r2 = _row("r2")
    r2_tampered = r2.model_copy(update={"hmac_prev": h1, "hmac_self": "deadbeef" + "0" * 56})

    bad = verify_chain([r1, r2_tampered], _SECRET)
    assert 1 in bad


def test_verify_chain_wrong_secret() -> None:
    r1 = _row("r1")
    h1 = compute_hmac(r1, None, _SECRET)
    r1 = r1.model_copy(update={"hmac_self": h1})
    bad = verify_chain([r1], b"wrong" + b"0" * 27)
    assert 0 in bad
