"""FastAPI application factory for Guardian-BR.

Usage (dev)::

    uv run uvicorn guardian_br.api.app:app --reload

Or via docker-compose::

    docker compose up guardian-br
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from guardian_br.adversarial.factory import build_default_classifier
from guardian_br.api.errors import (
    blocked_error_handler,
    handle_not_found_handler,
    rate_limit_handler,
    validation_error_handler,
)
from guardian_br.api.rate_limit import make_limiter
from guardian_br.api.routes_audit import router as audit_router
from guardian_br.api.routes_health import HealthRegistry
from guardian_br.api.routes_health import router as health_router
from guardian_br.api.routes_metrics import router as metrics_router
from guardian_br.api.routes_scan import router as scan_router
from guardian_br.api.routes_unmask import router as unmask_router
from guardian_br.api.settings import Settings
from guardian_br.core.adversarial import AdversarialClassifier
from guardian_br.core.audit_fallback import FallbackAuditWriter
from guardian_br.core.audit_hash import load_salt
from guardian_br.core.auditor import Auditor
from guardian_br.core.errors import BlockedError, HandleNotFound
from guardian_br.core.kms import EnvKMSProvider
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from guardian_br.guardian import Guardian

_CheckResult = Literal["ok", "fail", "skipped"]


async def _make_analyzer_check(
    guardian: Guardian,
) -> Callable[[], Awaitable[_CheckResult]]:
    async def _check() -> _CheckResult:
        try:
            guardian._get_analyzer()
            return "ok"
        except Exception:
            return "fail"

    return _check


async def _make_store_check(
    store: SQLiteRedactStore,
) -> Callable[[], Awaitable[_CheckResult]]:
    async def _check() -> _CheckResult:
        return "ok" if store.ping() else "fail"

    return _check


async def _make_kms_check(
    kms: EnvKMSProvider,
) -> Callable[[], Awaitable[_CheckResult]]:
    async def _check() -> _CheckResult:
        try:
            kms.current_key_id()
            return "ok"
        except Exception:
            return "fail"

    return _check


async def _make_llama_guard_check(
    classifier: AdversarialClassifier,
    enabled: bool,
) -> Callable[[], Awaitable[_CheckResult]]:
    async def _check() -> _CheckResult:
        if not enabled:
            return "skipped"
        from starlette.concurrency import run_in_threadpool

        try:
            ok = await run_in_threadpool(classifier.ping)
            return "ok" if ok else "fail"
        except Exception:
            return "fail"

    return _check


def create_app(*, settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Pass *settings* explicitly in tests or tooling; omit to read from env.
    """
    resolved_settings = settings or Settings()

    if not resolved_settings.api_keys_hashed:
        import warnings

        warnings.warn(
            "GUARDIAN_BR_API_KEYS_HASHED is empty and get_principal is not overridden. "
            "All authenticated endpoints will return 401. "
            "Set the env var or override get_principal via app.dependency_overrides.",
            stacklevel=2,
        )

    limiter = make_limiter(resolved_settings.rate_limit_per_key)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        import warnings

        from guardian_br.api import metrics as m
        from guardian_br.api.telemetry import setup_telemetry, shutdown_telemetry

        setup_telemetry(resolved_settings)

        store = SQLiteRedactStore()
        kms = EnvKMSProvider()
        classifier = build_default_classifier(resolved_settings)

        salt_b64 = (
            resolved_settings.audit_salt.get_secret_value()
            if resolved_settings.audit_salt
            else None
        )
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            audit_salt = load_salt(salt_b64)

        hmac_secret: bytes | None = None
        if resolved_settings.audit_hmac_chain and resolved_settings.audit_hmac_secret:
            import base64

            hmac_secret = base64.b64decode(resolved_settings.audit_hmac_secret.get_secret_value())

        fallback = FallbackAuditWriter(resolved_settings.audit_fallback_path)
        auditor = Auditor(
            store=store,
            salt=audit_salt,
            salt_key_id=resolved_settings.audit_salt_key_id,
            hmac_chain=resolved_settings.audit_hmac_chain,
            hmac_secret=hmac_secret,
            fallback=fallback,
            on_write_ok=lambda et: m.AUDIT_WRITES.labels(event_type=et, outcome="ok").inc(),
            on_fallback=lambda r: m.AUDIT_FALLBACK.labels(reason=r).inc(),
        )

        guardian = Guardian(
            redact_store=store,
            kms=kms,
            classifier=classifier,
            auditor=auditor,
            mode_default=resolved_settings.default_mode,
        )
        guardian.warm_up()

        if (
            resolved_settings.adversarial_enabled
            and resolved_settings.adversarial_warmup_on_startup
        ):
            import contextlib

            from starlette.concurrency import run_in_threadpool

            with contextlib.suppress(Exception):
                await run_in_threadpool(classifier.classify, "aquecimento")

        health = HealthRegistry()
        health.register("analyzer", await _make_analyzer_check(guardian))
        health.register("redact_store", await _make_store_check(store))
        health.register("kms", await _make_kms_check(kms))
        health.register(
            "llama_guard",
            await _make_llama_guard_check(classifier, resolved_settings.adversarial_enabled),
        )
        health.register("audit_log", await _make_store_check(store))

        app.state.guardian = guardian
        app.state.settings = resolved_settings
        app.state.health = health
        app.state.classifier = classifier
        app.state.store = store
        app.state.auditor = auditor

        yield

        shutdown_telemetry()

    app = FastAPI(
        title="Guardian-BR",
        description="Brazilian LLM guardrails layer — BR PII detection with LGPD mapping and PT-BR adversarial classification.",
        version="0.1.0",
        lifespan=lifespan,
    )

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor().instrument_app(app, excluded_urls="v1/healthz,v1/metrics")
    except ImportError:
        pass

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
    app.add_exception_handler(BlockedError, blocked_error_handler)
    app.add_exception_handler(HandleNotFound, handle_not_found_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)

    app.include_router(scan_router, prefix="/v1", tags=["scan"])
    app.include_router(unmask_router, prefix="/v1", tags=["unmask"])
    app.include_router(audit_router, prefix="/v1", tags=["audit"])
    app.include_router(health_router, prefix="/v1", tags=["health"])
    app.include_router(metrics_router, prefix="/v1", tags=["observability"])

    return app


# Module-level app instance for `uvicorn guardian_br.api.app:app`
app = create_app()
