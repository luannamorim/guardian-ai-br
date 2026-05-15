"""Exception handlers for the FastAPI app."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from guardian_br.api.schemas import ErrorResponse
from guardian_br.core.errors import BlockedError


async def blocked_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, BlockedError)
    body = ErrorResponse(detail=str(exc), code="blocked", adversarial=exc.adversarial)
    return JSONResponse(status_code=422, content=body.model_dump())


async def handle_not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    # Uniform 404 for miss, expired, and tampered — do not distinguish.
    body = ErrorResponse(detail="handle not found", code="handle_not_found")
    return JSONResponse(status_code=404, content=body.model_dump())


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errs = exc.errors()
    detail = str(errs[0].get("msg", "validation error")) if errs else "validation error"
    body = ErrorResponse(detail=detail, code="validation_error")
    return JSONResponse(status_code=422, content=body.model_dump())


def rate_limit_handler(request: Request, exc: Exception) -> JSONResponse:
    # Must be synchronous: SlowAPIMiddleware uses sync_check_limits which
    # falls back to the default handler when the registered handler is async.
    assert isinstance(exc, RateLimitExceeded)
    retry_after = getattr(exc, "retry_after", None)
    headers = {"Retry-After": str(retry_after)} if retry_after else {}
    body = ErrorResponse(detail=f"rate limit exceeded: {exc.detail}", code="rate_limited")
    return JSONResponse(status_code=429, content=body.model_dump(), headers=headers)
