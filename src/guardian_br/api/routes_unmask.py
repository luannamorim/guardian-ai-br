from fastapi import APIRouter, Depends, Request

from guardian_br.api import metrics as m
from guardian_br.api.auth import Principal, get_principal
from guardian_br.api.dependencies import get_guardian
from guardian_br.api.schemas import UnmaskRequest, UnmaskResponse
from guardian_br.core.errors import HandleNotFound
from guardian_br.guardian import Guardian

router = APIRouter()


@router.post("/unmask", response_model=UnmaskResponse)
async def unmask_endpoint(
    request: Request,
    body: UnmaskRequest,
    principal: Principal = Depends(get_principal),
    guardian: Guardian = Depends(get_guardian),
) -> UnmaskResponse:
    """Retrieve the original value for a reversible-redact handle.

    Returns 404 for unknown, expired, and tampered handles — the
    response is intentionally uniform to prevent oracle attacks.
    """
    value = guardian.unmask(body.handle)
    if value is None:
        m.UNMASK_TOTAL.labels(result="miss").inc()
        raise HandleNotFound(body.handle)
    m.UNMASK_TOTAL.labels(result="hit").inc()
    return UnmaskResponse(value=value)
