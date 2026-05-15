"""HMAC chain helpers for append-only audit log tamper detection."""

from __future__ import annotations

import hashlib
import hmac
import json

from guardian_br.core.redact_store import AuditRow


def compute_hmac(row: AuditRow, prev_hmac: str | None, secret: bytes) -> str:
    payload = "|".join(
        [
            prev_hmac or "",
            row.id,
            row.timestamp.isoformat(),
            row.event_type,
            row.input_hash or "",
            row.principal_id or "",
            json.dumps(row.detections, separators=(",", ":"), sort_keys=True),
        ]
    )
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_chain(rows: list[AuditRow], secret: bytes) -> list[int]:
    """Return indexes of rows whose HMAC does not match the chain."""
    bad: list[int] = []
    prev_hmac: str | None = None
    for i, row in enumerate(rows):
        expected = compute_hmac(row, prev_hmac, secret)
        stored = row.hmac_self or ""
        if not hmac.compare_digest(expected, stored):
            bad.append(i)
        prev_hmac = row.hmac_self
    return bad
