"""RedactStore Protocol and associated data types.

This Protocol is authoritative for all adapter packages
(guardrails-br-postgres, guardrails-br-redis). Adapters must pass
the contract-test suite in tests/redact_store/contract.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


class RedactRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    handle: str
    wrapped_dek: bytes
    kek_key_id: str
    nonce: bytes
    ciphertext: bytes
    entity_type: str
    created_at: datetime
    expires_at: datetime | None = None


class AuditRow(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    handle: str
    entity_type: str
    action: str


@runtime_checkable
class RedactStore(Protocol):
    def put(self, record: RedactRecord) -> None: ...

    def get(self, handle: str) -> RedactRecord | None: ...

    def delete(self, handle: str) -> bool: ...

    def ping(self) -> bool: ...

    def query_audit(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRow]:
        """Audit log query.

        Stubbed with NotImplementedError in the SQLite reference impl.
        Audit-log persistence lands in a dedicated follow-up PR. Adapter
        authors: implement this method before shipping.
        """
        ...
