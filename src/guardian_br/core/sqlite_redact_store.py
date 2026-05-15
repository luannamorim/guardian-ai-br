"""SQLite-backed RedactStore. Zero-config default for dev/CI.

This module must not import logging or use print() — raw PII flows
through this path and must never appear in any log output.
See CLAUDE.md: "Any logger.* or print( call inside a PII-handling
code path is a bug."
"""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from guardian_br.core.redact_store import AuditRow, RedactRecord


class HandleCollisionError(Exception):
    """Raised when put() receives a handle that already exists in the store."""

    pass


class SQLiteRedactStore:
    """SQLiteRedactStore is the reference RedactStore implementation.

    path=":memory:" (default) gives an in-process store suitable for
    tests and single-process library use. Pass a file path for
    persistent storage across restarts.
    """

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        default_ttl_s: int | None = None,
    ) -> None:
        self._default_ttl_s = default_ttl_s
        self._conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
        )
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS redact_records (
                handle      TEXT PRIMARY KEY,
                wrapped_dek BLOB NOT NULL,
                kek_key_id  TEXT NOT NULL,
                nonce       BLOB NOT NULL,
                ciphertext  BLOB NOT NULL,
                entity_type TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_redact_expires
                ON redact_records(expires_at);

            CREATE TABLE IF NOT EXISTS audit_log (
                id                  TEXT PRIMARY KEY,
                timestamp           TEXT NOT NULL,
                event_type          TEXT NOT NULL,
                principal_id        TEXT,
                client_ip           TEXT,
                request_fingerprint TEXT,
                input_hash          TEXT,
                salt_key_id         TEXT,
                mode                TEXT,
                latency_ms          REAL,
                detections          TEXT,
                adversarial_label   TEXT,
                adversarial_unsafe  INTEGER,
                blocked             INTEGER,
                handle              TEXT,
                entity_type         TEXT,
                hmac_prev           TEXT,
                hmac_self           TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_principal
                ON audit_log(principal_id);
        """)

    def put(self, record: RedactRecord) -> None:
        expires = record.expires_at.isoformat() if record.expires_at else None
        try:
            self._conn.execute(
                """
                INSERT INTO redact_records
                    (handle, wrapped_dek, kek_key_id, nonce, ciphertext,
                     entity_type, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.handle,
                    record.wrapped_dek,
                    record.kek_key_id,
                    record.nonce,
                    record.ciphertext,
                    record.entity_type,
                    record.created_at.isoformat(),
                    expires,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HandleCollisionError(f"handle {record.handle!r} already exists in store") from exc

    def get(self, handle: str) -> RedactRecord | None:
        now = datetime.now(UTC).isoformat()
        row = self._conn.execute(
            """
            SELECT handle, wrapped_dek, kek_key_id, nonce, ciphertext,
                   entity_type, created_at, expires_at
            FROM redact_records
            WHERE handle = ?
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (handle, now),
        ).fetchone()
        if row is None:
            return None
        handle_, wrapped_dek, kek_key_id, nonce, ciphertext, entity_type, created_at, expires_at = (
            row
        )
        return RedactRecord(
            handle=handle_,
            wrapped_dek=bytes(wrapped_dek),
            kek_key_id=kek_key_id,
            nonce=bytes(nonce),
            ciphertext=bytes(ciphertext),
            entity_type=entity_type,
            created_at=datetime.fromisoformat(created_at),
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
        )

    def delete(self, handle: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM redact_records WHERE handle = ?",
            (handle,),
        )
        return cursor.rowcount > 0

    def ping(self) -> bool:
        try:
            self._conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    def purge_expired(self) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = self._conn.execute(
            "DELETE FROM redact_records WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
        return cursor.rowcount

    def purge_audit(self, before: datetime) -> int:
        cursor = self._conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?",
            (before.isoformat(),),
        )
        return cursor.rowcount

    def append_audit(self, row: AuditRow) -> None:
        self._conn.execute(
            """
            INSERT INTO audit_log (
                id, timestamp, event_type, principal_id, client_ip,
                request_fingerprint, input_hash, salt_key_id, mode, latency_ms,
                detections, adversarial_label, adversarial_unsafe, blocked,
                handle, entity_type, hmac_prev, hmac_self
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row.id,
                row.timestamp.isoformat(),
                row.event_type,
                row.principal_id,
                row.client_ip,
                row.request_fingerprint,
                row.input_hash,
                row.salt_key_id,
                row.mode,
                row.latency_ms,
                json.dumps(row.detections, separators=(",", ":")) if row.detections else "[]",
                row.adversarial_label,
                int(row.adversarial_unsafe) if row.adversarial_unsafe is not None else None,
                int(row.blocked) if row.blocked is not None else None,
                row.handle,
                row.entity_type,
                row.hmac_prev,
                row.hmac_self,
            ),
        )

    def query_audit(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRow]:
        clauses = []
        params: list[object] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until.isoformat())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"""
            SELECT id, timestamp, event_type, principal_id, client_ip,
                   request_fingerprint, input_hash, salt_key_id, mode, latency_ms,
                   detections, adversarial_label, adversarial_unsafe, blocked,
                   handle, entity_type, hmac_prev, hmac_self
            FROM audit_log
            {where}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [_row_to_audit(r) for r in rows]


def _row_to_audit(r: tuple) -> AuditRow:  # type: ignore[type-arg]
    (
        id_,
        timestamp,
        event_type,
        principal_id,
        client_ip,
        request_fingerprint,
        input_hash,
        salt_key_id,
        mode,
        latency_ms,
        detections_json,
        adversarial_label,
        adversarial_unsafe,
        blocked,
        handle,
        entity_type,
        hmac_prev,
        hmac_self,
    ) = r
    return AuditRow(
        id=id_,
        timestamp=datetime.fromisoformat(timestamp),
        event_type=event_type,
        principal_id=principal_id,
        client_ip=client_ip,
        request_fingerprint=request_fingerprint,
        input_hash=input_hash,
        salt_key_id=salt_key_id,
        mode=mode,
        latency_ms=latency_ms,
        detections=json.loads(detections_json) if detections_json else [],
        adversarial_label=adversarial_label,
        adversarial_unsafe=bool(adversarial_unsafe) if adversarial_unsafe is not None else None,
        blocked=bool(blocked) if blocked is not None else None,
        handle=handle,
        entity_type=entity_type,
        hmac_prev=hmac_prev,
        hmac_self=hmac_self,
    )
