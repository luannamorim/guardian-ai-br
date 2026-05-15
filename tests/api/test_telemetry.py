"""Tests for OpenTelemetry span instrumentation in guardian.py.

The OTel global TracerProvider cannot be replaced once set, so the provider
is configured once at module level; each test clears the exporter.
"""

from __future__ import annotations

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from guardian_br import BlockedError, Guardian
from guardian_br.core.modes import Mode

# ── One-time OTel provider setup ──────────────────────────────────────────────
_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))
trace.set_tracer_provider(_PROVIDER)


@pytest.fixture
def otel_exporter() -> InMemorySpanExporter:  # type: ignore[return]
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def _spans(exporter: InMemorySpanExporter, name: str):  # type: ignore[no-untyped-def]
    return [s for s in exporter.get_finished_spans() if s.name == name]


# ── span presence ─────────────────────────────────────────────────────────────


def test_scan_creates_guardian_scan_span(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado")
    assert len(_spans(otel_exporter, "guardian.scan")) == 1


def test_pii_child_span_created(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("meu cpf eh 123.456.789-09")
    pii = _spans(otel_exporter, "guardian.pii")
    scan = _spans(otel_exporter, "guardian.scan")
    assert len(pii) == 1
    assert pii[0].parent is not None
    assert pii[0].parent.span_id == scan[0].context.span_id


def test_adversarial_child_span_created(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado", skip_adversarial=False)
    adv = _spans(otel_exporter, "guardian.adversarial")
    scan = _spans(otel_exporter, "guardian.scan")
    assert len(adv) == 1
    assert adv[0].parent is not None
    assert adv[0].parent.span_id == scan[0].context.span_id


def test_no_adversarial_span_when_skipped(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado", skip_adversarial=True)
    assert len(_spans(otel_exporter, "guardian.adversarial")) == 0


# ── guardian.scan attributes ──────────────────────────────────────────────────


def test_scan_span_carries_mode_attribute(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado")
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert span.attributes["guardian.mode"] == "REDACT"


def test_scan_span_carries_decision_allowed(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado")
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert span.attributes["guardian.decision"] == "allowed"


def test_scan_span_carries_decision_blocked(otel_exporter: InMemorySpanExporter) -> None:
    g = Guardian(mode_default=Mode.BLOCK)
    with pytest.raises(BlockedError):
        g.scan("meu cpf eh 123.456.789-09")
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert span.attributes["guardian.decision"] == "blocked"
    assert span.status.status_code == StatusCode.ERROR


def test_scan_span_carries_detection_count(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("meu cpf eh 123.456.789-09")
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert span.attributes["guardian.detections_count"] == 1


def test_scan_span_carries_latency_attributes(otel_exporter: InMemorySpanExporter) -> None:
    Guardian().scan("nenhum dado")
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert "guardian.latency_ms_pii" in (span.attributes or {})
    assert "guardian.latency_ms_total" in (span.attributes or {})


def test_scan_span_adversarial_latency_present_when_not_skipped(
    otel_exporter: InMemorySpanExporter,
) -> None:
    Guardian().scan("nenhum dado", skip_adversarial=False)
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert "guardian.latency_ms_adversarial" in (span.attributes or {})


def test_scan_span_adversarial_latency_absent_when_skipped(
    otel_exporter: InMemorySpanExporter,
) -> None:
    Guardian().scan("nenhum dado", skip_adversarial=True)
    span = _spans(otel_exporter, "guardian.scan")[0]
    assert "guardian.latency_ms_adversarial" not in (span.attributes or {})


# ── security: no raw PII ──────────────────────────────────────────────────────


def test_no_raw_text_in_span_attributes(otel_exporter: InMemorySpanExporter) -> None:
    raw_cpf = "123.456.789-09"
    Guardian().scan(f"meu cpf eh {raw_cpf}")
    for span in otel_exporter.get_finished_spans():
        for val in (span.attributes or {}).values():
            assert raw_cpf not in str(val), f"span {span.name!r} leaks raw PII"


# ── setup_telemetry noop ──────────────────────────────────────────────────────


def test_setup_telemetry_noop_when_no_endpoint(otel_exporter: InMemorySpanExporter) -> None:
    from guardian_br.api.settings import Settings
    from guardian_br.api.telemetry import setup_telemetry

    setup_telemetry(Settings(api_keys_hashed=frozenset()))  # otlp_endpoint is None

    result = Guardian().scan("meu cpf eh 123.456.789-09")
    assert result.detections[0].entity_type == "BR_CPF"
    assert len(_spans(otel_exporter, "guardian.scan")) == 1
