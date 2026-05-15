"""Auditor: orchestrates per-scan audit log persistence.

This module must NOT log or print any values derived from user input.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from guardian_br.core.redact_store import AuditRow, RedactStore

if TYPE_CHECKING:
    from guardian_br.core.adversarial import AdversarialResult
    from guardian_br.core.audit_fallback import FallbackAuditWriter
    from guardian_br.core.schemas import Detection


class Auditor:
    """Wires a RedactStore + HMAC chain + fallback writer for audit persistence.

    ``append`` never raises to its caller — store failure falls back to file,
    file failure increments a metric and drops. SPEC §159: scan continues.
    """

    def __init__(
        self,
        *,
        store: RedactStore | None,
        salt: bytes,
        salt_key_id: str = "default",
        hmac_chain: bool = False,
        hmac_secret: bytes | None = None,
        fallback: FallbackAuditWriter | None = None,
        on_write_ok: Callable[[str], None] | None = None,
        on_fallback: Callable[[str], None] | None = None,
    ) -> None:
        self._store = store
        self._salt = salt
        self._salt_key_id = salt_key_id
        self._hmac_chain = hmac_chain
        self._hmac_secret = hmac_secret
        self._fallback = fallback
        self._on_write_ok = on_write_ok
        self._on_fallback = on_fallback
        self._lock = threading.Lock()
        self._last_hmac: str | None = None
        if hmac_chain and store is not None:
            self._last_hmac = self._seed_chain()

    def _seed_chain(self) -> str | None:
        try:
            assert self._store is not None
            rows = self._store.query_audit(limit=1)
            return rows[0].hmac_self if rows else None
        except Exception:
            return None

    def _apply_chain(self, row: AuditRow) -> AuditRow:
        if not self._hmac_chain or self._hmac_secret is None:
            return row
        from guardian_br.core.audit_chain import compute_hmac

        with self._lock:
            prev = self._last_hmac
            h = compute_hmac(row, prev, self._hmac_secret)
            updated = row.model_copy(update={"hmac_prev": prev, "hmac_self": h})
            self._last_hmac = h
        return updated

    def append(self, row: AuditRow) -> None:
        """Persist a row. Falls back to file on store failure. Never raises."""
        row = self._apply_chain(row)
        if self._store is not None:
            try:
                self._store.append_audit(row)
                if self._on_write_ok:
                    self._on_write_ok(row.event_type)
                return
            except Exception:
                pass

        if self._fallback is not None:
            try:
                self._fallback.append(row)
                reason = "store_unreachable" if self._store is not None else "no_store"
                if self._on_fallback:
                    self._on_fallback(reason)
            except OSError:
                if self._on_fallback:
                    self._on_fallback("disk_full")
            except Exception:
                if self._on_fallback:
                    self._on_fallback("store_error")

    def record_scan(
        self,
        *,
        text: str,
        principal_id: str | None,
        client_ip: str | None,
        request_fingerprint: str | None,
        mode: str,
        detections: list[Detection],
        adversarial: AdversarialResult | None,
        latency_ms: float,
        blocked: bool,
    ) -> None:
        from guardian_br.core.audit_hash import salted_hash

        row = AuditRow(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            event_type="scan",
            principal_id=principal_id or "library",
            client_ip=client_ip,
            request_fingerprint=request_fingerprint,
            input_hash=salted_hash(text, self._salt),
            salt_key_id=self._salt_key_id,
            mode=mode,  # type: ignore[arg-type]
            latency_ms=latency_ms,
            detections=[
                {"entity_type": d.entity_type, "lgpd_article": d.lgpd_article or "unknown"}
                for d in detections
            ],
            adversarial_label=adversarial.label if adversarial else None,
            adversarial_unsafe=adversarial.unsafe if adversarial else None,
            blocked=blocked,
        )
        self.append(row)

    def record_unmask(self, *, handle: str, principal_id: str | None, success: bool) -> None:
        row = AuditRow(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            event_type="unmask",
            principal_id=principal_id or "library",
            handle=handle,
            blocked=not success,
        )
        self.append(row)

    def record_handle_event(self, *, action: str, handle: str, entity_type: str) -> None:
        row = AuditRow(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            event_type=action,  # type: ignore[arg-type]
            handle=handle,
            entity_type=entity_type,
        )
        self.append(row)

    def record_auth_failure(
        self,
        *,
        client_ip: str | None,
        request_fingerprint: str | None,
        reason: str,
    ) -> None:
        row = AuditRow(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            event_type="auth_failure",
            principal_id="unknown",
            client_ip=client_ip,
            request_fingerprint=request_fingerprint,
        )
        self.append(row)


class _DisabledAuditor:
    """No-op auditor for library use without an audit store."""

    def append(self, row: AuditRow) -> None:
        pass

    def record_scan(self, **kwargs: object) -> None:
        pass

    def record_unmask(self, **kwargs: object) -> None:
        pass

    def record_handle_event(self, **kwargs: object) -> None:
        pass

    def record_auth_failure(self, **kwargs: object) -> None:
        pass
