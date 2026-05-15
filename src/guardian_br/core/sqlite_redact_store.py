"""SQLite-backed RedactStore. Zero-config default for dev/CI.

This module must not import logging or use print() — raw PII flows
through this path and must never appear in any log output.
See CLAUDE.md: "Any logger.* or print( call inside a PII-handling
code path is a bug."
"""

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

    def query_audit(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRow]:
        raise NotImplementedError(
            "Audit log persistence is implemented in a follow-up PR. "
            "Adapters must implement query_audit before shipping."
        )
