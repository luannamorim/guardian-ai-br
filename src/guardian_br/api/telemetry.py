"""OpenTelemetry SDK setup for Guardian-BR API.

All SDK imports are deferred inside functions and guarded with try/except so
the module is safe to import when only opentelemetry-api (base dep) is present.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guardian_br.api.settings import Settings

_provider: Any = None


def setup_telemetry(settings: Settings) -> None:
    """Configure the OTel SDK when OTLP endpoint is set. No-op otherwise.

    Always attempts to instrument httpx (idempotent) so Ollama HTTP spans are
    captured if the SDK is available.
    """
    global _provider

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
    except ImportError:
        pass

    if not settings.otlp_endpoint:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return

    version = importlib.metadata.version("guardrails-br")
    resource = Resource({SERVICE_NAME: settings.otel_service_name, SERVICE_VERSION: version})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=settings.otlp_endpoint, insecure=settings.otlp_insecure)
        )
    )
    trace.set_tracer_provider(provider)
    _provider = provider


def shutdown_telemetry() -> None:
    """Flush the BatchSpanProcessor queue and shut down the provider."""
    global _provider
    if _provider is not None:
        with contextlib.suppress(Exception):
            _provider.shutdown()
        _provider = None
