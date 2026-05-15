"""Healthcheck endpoint with extensible readiness registry.

PR3 (Llama Guard) adds its readiness check via:

    app.state.health.register("llama_guard", _llama_guard_check)

without modifying this file.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from guardian_br.api.dependencies import get_health_registry
from guardian_br.api.schemas import HealthResponse

router = APIRouter()

CheckResult = Literal["ok", "fail", "skipped"]
ReadinessCheck = Callable[[], Awaitable[CheckResult]]


class HealthRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, ReadinessCheck] = {}

    def register(self, name: str, check: ReadinessCheck) -> None:
        self._checks[name] = check

    async def evaluate(self) -> tuple[Literal["ready", "not_ready"], dict[str, CheckResult]]:
        names = list(self._checks)
        checks = list(self._checks.values())

        async def _safe(check: ReadinessCheck) -> CheckResult:
            try:
                return await check()
            except Exception:
                return "fail"

        outcomes: list[CheckResult] = list(await asyncio.gather(*(_safe(c) for c in checks)))
        results = dict(zip(names, outcomes, strict=True))
        overall: Literal["ready", "not_ready"] = (
            "not_ready" if any(v == "fail" for v in results.values()) else "ready"
        )
        return overall, results


@router.get("/healthz", response_model=HealthResponse)
async def healthz(
    request: Request,
    registry: HealthRegistry = Depends(get_health_registry),
) -> JSONResponse:
    status, components = await registry.evaluate()
    body = HealthResponse(status=status, components=components)
    http_status = 200 if status == "ready" else 503
    return JSONResponse(status_code=http_status, content=body.model_dump())
