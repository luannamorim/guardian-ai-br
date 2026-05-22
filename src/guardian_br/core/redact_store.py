"""RedactStore Protocol and associated data types.

This Protocol is authoritative for all adapter packages
(guardrails-br-postgres, guardrails-br-redis). Adapters must pass
the contract-test suite in tests/redact_store/contract.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

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

    id: str
    timestamp: datetime
    event_type: Literal["scan", "unmask", "handle_put", "handle_delete", "auth_failure"]
    principal_id: str | None = None
    client_ip: str | None = None
    request_fingerprint: str | None = None
    input_hash: str | None = None
    salt_key_id: str | None = None
    mode: Literal["REDACT", "REVERSIBLE_REDACT", "BLOCK"] | None = None
    latency_ms: float | None = None
    detections: list[dict[str, str]] = []
    adversarial_label: str | None = None
    adversarial_unsafe: bool | None = None
    blocked: bool | None = None
    would_block: bool | None = None
    handle: str | None = None
    entity_type: str | None = None
    hmac_prev: str | None = None
    hmac_self: str | None = None


@runtime_checkable
class RedactStore(Protocol):
    def put(self, record: RedactRecord) -> None: ...

    def get(self, handle: str) -> RedactRecord | None: ...

    def delete(self, handle: str) -> bool: ...

    def ping(self) -> bool: ...

    def append_audit(self, row: AuditRow) -> None: ...

    def query_audit(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRow]: ...
