from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from prometheus_client import generate_latest

from guardian_br.api import metrics as m
from guardian_br.api.auth import get_principal
from guardian_br.api.dependencies import get_settings
from guardian_br.api.settings import Settings

router = APIRouter()


@router.get("/metrics")
async def metrics_endpoint(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> Response:
    """Prometheus metrics exposition (text/plain, v0.0.4).

    Requires X-API-Key by default (GUARDIAN_BR_METRICS_REQUIRE_AUTH=true).
    Set to false for network-policy-protected scrape endpoints.
    """
    if settings.metrics_require_auth:
        # Validate inline — same logic as get_principal but without the
        # full FastAPI dependency chain to avoid double-counting failures.
        api_key: str | None = request.headers.get("X-API-Key")
        await get_principal(request, api_key=api_key, settings=settings)
    return Response(
        content=generate_latest(m.REGISTRY),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
