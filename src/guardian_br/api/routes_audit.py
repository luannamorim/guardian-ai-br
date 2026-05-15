"""GET /v1/audit — paginated audit log query (requires audit:read scope)."""

from __future__ import annotations

import time
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from guardian_br.api import metrics as m
from guardian_br.api.auth import Principal, get_principal
from guardian_br.api.dependencies import get_store
from guardian_br.api.schemas import AuditQueryResponse
from guardian_br.api.scopes import require_scope
from guardian_br.core.redact_store import RedactStore

router = APIRouter()


@router.get("/audit", response_model=AuditQueryResponse)
async def get_audit(
    principal: Principal = Depends(get_principal),
    _scope: None = Depends(require_scope("audit:read")),
    store: RedactStore = Depends(get_store),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> AuditQueryResponse:
    """Return paginated audit log rows in descending timestamp order.

    Use ``since`` to filter rows at or after a given timestamp.
    Use ``next_since`` from the response to paginate forward.
    """
    t0 = time.perf_counter()
    try:
        rows = store.query_audit(since=since, until=until, limit=limit)
        m.AUDIT_QUERY_LATENCY.labels(outcome="ok").observe(time.perf_counter() - t0)
    except Exception:
        m.AUDIT_QUERY_LATENCY.labels(outcome="error").observe(time.perf_counter() - t0)
        raise
    next_since = rows[-1].timestamp if len(rows) == limit else None
    return AuditQueryResponse(rows=rows, next_since=next_since)
