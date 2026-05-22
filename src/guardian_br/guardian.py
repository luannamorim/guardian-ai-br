from __future__ import annotations

import contextlib
import json
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

try:
    from opentelemetry import trace as _otel_trace

    _OTEL_AVAILABLE = True
except ImportError:
    _otel_trace = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.adversarial import AdversarialClassifier, AdversarialResult
from guardian_br.core.crypto import DEKCache, decrypt_value, encrypt_value, new_dek
from guardian_br.core.entities import BR_ENTITIES
from guardian_br.core.errors import BlockedError
from guardian_br.core.kms import EnvKMSProvider, KMSProvider, WrappedDEK
from guardian_br.core.modes import Mode
from guardian_br.core.redact_store import RedactRecord, RedactStore
from guardian_br.core.schemas import Detection, ScanResult
from guardian_br.lgpd.loader import load_lgpd_mapping
from guardian_br.pii.custom import CustomRecognizerSpec

if TYPE_CHECKING:
    from guardian_br.core.auditor import Auditor

_DEFAULT_HANDLE_TTL_S = 86_400  # 24 hours
_TRACER = _otel_trace.get_tracer("guardian_br") if _OTEL_AVAILABLE else None


class Guardian:
    """Entry point for Guardian-BR PII detection.

    Library use::

        result = Guardian().scan("meu cpf eh 123.456.789-09")
        print(result.redacted_text)  # "meu cpf eh <BR_CPF>"

    Reversible redact::

        g = Guardian(mode_default=Mode.REVERSIBLE_REDACT)
        result = g.scan("cpf 123.456.789-09")
        handle = result.detections[0].redact_token
        assert g.unmask(handle) == "123.456.789-09"
    """

    def __init__(
        self,
        *,
        analyzer: AnalyzerEngine | None = None,
        redact_store: RedactStore | None = None,
        kms: KMSProvider | None = None,
        classifier: AdversarialClassifier | None = None,
        auditor: Auditor | None = None,
        mode_default: Mode = Mode.REDACT,
        dek_cache_ttl_s: int = 300,
        custom_recognizers: Sequence[CustomRecognizerSpec] | None = None,
        shadow_mode: bool = False,
    ) -> None:
        self._analyzer = analyzer
        self._redact_store = redact_store
        self._kms = kms
        self._classifier = classifier
        self._auditor = auditor
        self._mode_default = mode_default
        self._dek_cache = DEKCache(ttl_s=dek_cache_ttl_s)
        self._shadow_mode = shadow_mode
        self._custom_recognizers: tuple[CustomRecognizerSpec, ...] = tuple(custom_recognizers or ())
        self._custom_entity_lgpd: dict[str, str] = {
            spec.entity_type: spec.lgpd_article
            for spec in self._custom_recognizers
            if spec.lgpd_article is not None
        }
        self._all_entities: list[str] = list(BR_ENTITIES) + [
            spec.entity_type for spec in self._custom_recognizers
        ]

    @property
    def mode_default(self) -> Mode:
        return self._mode_default

    @property
    def shadow_mode(self) -> bool:
        return self._shadow_mode

    def warm_up(self) -> None:
        """Force lazy initialization of the analyzer engine and classifier."""
        import contextlib

        self._get_analyzer()
        with contextlib.suppress(Exception):
            self._get_classifier().ping()

    def _get_analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            from guardian_br.pii.registry import build_analyzer_engine

            self._analyzer = build_analyzer_engine(custom_recognizers=self._custom_recognizers)
        return self._analyzer

    def _get_redact_store(self) -> RedactStore:
        if self._redact_store is None:
            from guardian_br.core.sqlite_redact_store import SQLiteRedactStore

            self._redact_store = SQLiteRedactStore()
        return self._redact_store

    def _get_kms(self) -> KMSProvider:
        if self._kms is None:
            self._kms = EnvKMSProvider()
        return self._kms

    def _get_classifier(self) -> AdversarialClassifier:
        if self._classifier is None:
            from guardian_br.adversarial import _DisabledClassifier

            self._classifier = _DisabledClassifier()
        return self._classifier

    def _get_auditor(self) -> Auditor:
        if self._auditor is None:
            from guardian_br.core.auditor import _DisabledAuditor

            self._auditor = _DisabledAuditor()  # type: ignore[assignment]
        return self._auditor  # type: ignore[return-value]

    def scan(
        self,
        text: str,
        *,
        mode: Mode | None = None,
        skip_adversarial: bool = False,
        principal_id: str | None = None,
        client_ip: str | None = None,
        request_fingerprint: str | None = None,
        shadow: bool | None = None,
    ) -> ScanResult:
        """Scan *text* for BR PII and return a frozen ScanResult.

        Detections include only entities whose checksums pass validation.
        The ``mode`` argument overrides the instance's ``mode_default``.

        BLOCK: raises BlockedError if any PII is detected OR adversarial is unsafe.
        REDACT: replaces each span with ``<ENTITY_TYPE>``.
        REVERSIBLE_REDACT: replaces each span with ``<RDX:{handle}>``
            and stores the encrypted original (AES-256-GCM) so it can be
            recovered via unmask(handle).

        ``shadow`` overrides the instance's ``shadow_mode``. When True and
        the effective mode is BLOCK, the scan never raises: instead it
        records ``would_block=True`` to the audit log and returns a redacted
        result so callers can roll out a BLOCK policy without impact.
        """
        t_total = time.perf_counter()
        effective_mode = mode if mode is not None else self._mode_default
        effective_shadow = shadow if shadow is not None else self._shadow_mode
        analyzer = self._get_analyzer()
        mapping = load_lgpd_mapping()

        with (
            _TRACER.start_as_current_span("guardian.scan") if _TRACER else contextlib.nullcontext()
        ) as span:
            t_pii = time.perf_counter()
            with (
                _TRACER.start_as_current_span("guardian.pii")
                if _TRACER
                else contextlib.nullcontext()
            ):
                results = analyzer.analyze(
                    text=text,
                    language="pt",
                    entities=self._all_entities,
                )
                detections: list[Detection] = []
                for r in results:
                    rule = mapping.rules.get(r.entity_type)
                    lgpd_article = (
                        rule.lgpd_articles[0].article
                        if rule
                        else self._custom_entity_lgpd.get(r.entity_type)
                    )
                    detections.append(
                        Detection(
                            entity_type=r.entity_type,
                            start=r.start,
                            end=r.end,
                            score=r.score,
                            lgpd_article=lgpd_article,
                        )
                    )
            latency_ms_pii = (time.perf_counter() - t_pii) * 1000

            adv: AdversarialResult | None = None
            latency_ms_adv: float | None = None
            if not skip_adversarial:
                t_adv = time.perf_counter()
                with (
                    _TRACER.start_as_current_span("guardian.adversarial")
                    if _TRACER
                    else contextlib.nullcontext()
                ) as adv_span:
                    adv = self._get_classifier().classify(text)
                    if adv_span:
                        adv_span.set_attribute("guardian.adversarial_source", adv.source)
                latency_ms_adv = (time.perf_counter() - t_adv) * 1000

            latency_ms = (time.perf_counter() - t_total) * 1000
            would_block_now = effective_mode is Mode.BLOCK and (
                bool(detections) or (adv is not None and adv.unsafe)
            )
            is_blocked = would_block_now and not effective_shadow
            input_hash = self._get_auditor().hash_input(text)

            if span:
                span.set_attribute("guardian.mode", effective_mode.value)
                span.set_attribute("guardian.latency_ms_pii", latency_ms_pii)
                if latency_ms_adv is not None:
                    span.set_attribute("guardian.latency_ms_adversarial", latency_ms_adv)
                span.set_attribute("guardian.latency_ms_total", latency_ms)
                span.set_attribute("guardian.detections_count", len(detections))
                if detections:
                    span.set_attribute(
                        "guardian.detections",
                        json.dumps(
                            [
                                {
                                    "entity_type": d.entity_type,
                                    "lgpd_article": d.lgpd_article or "unknown",
                                }
                                for d in detections
                            ],
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    )
                if input_hash:
                    span.set_attribute("guardian.input_hash", input_hash)
                if effective_shadow and would_block_now:
                    decision = "shadow_block"
                elif is_blocked:
                    decision = "blocked"
                else:
                    decision = "allowed"
                span.set_attribute("guardian.decision", decision)
                span.set_attribute("guardian.shadow", effective_shadow)
                span.set_attribute("guardian.would_block", would_block_now)
                if is_blocked:
                    span.set_status(_otel_trace.StatusCode.ERROR, "blocked")

            self._get_auditor().record_scan(
                text=text,
                input_hash=input_hash,
                principal_id=principal_id,
                client_ip=client_ip,
                request_fingerprint=request_fingerprint,
                mode=effective_mode.value,
                detections=detections,
                adversarial=adv,
                latency_ms=latency_ms,
                blocked=is_blocked,
                would_block=would_block_now,
            )

            if effective_mode is Mode.BLOCK:
                if is_blocked:
                    raise BlockedError(detections, adversarial=adv)
                if would_block_now and effective_shadow:
                    # Shadow: produce redacted text so callers can compare
                    # what the live policy would have returned.
                    def shadow_placeholder(d: Detection) -> str:
                        return f"<{d.entity_type}>"

                    redacted_text = _redact(text, detections, shadow_placeholder)
                    return ScanResult(
                        mode=effective_mode,
                        blocked=False,
                        shadow=True,
                        would_block=True,
                        text=text,
                        detections=detections,
                        redacted_text=redacted_text,
                        adversarial=adv,
                    )
                return ScanResult(
                    mode=effective_mode,
                    blocked=False,
                    shadow=effective_shadow,
                    text=text,
                    detections=[],
                    redacted_text=text,
                    adversarial=adv,
                )

            if effective_mode is Mode.REVERSIBLE_REDACT:
                detections = self._store_and_tokenize(text, detections)

                def placeholder_fn(d: Detection) -> str:
                    return f"<RDX:{d.redact_token}>"
            else:

                def placeholder_fn(d: Detection) -> str:
                    return f"<{d.entity_type}>"

            redacted_text = _redact(text, detections, placeholder_fn)
            return ScanResult(
                mode=effective_mode,
                shadow=effective_shadow,
                would_block=would_block_now,
                text=text,
                detections=detections,
                redacted_text=redacted_text,
                adversarial=adv,
            )

    def _store_and_tokenize(
        self,
        text: str,
        detections: list[Detection],
    ) -> list[Detection]:
        """Encrypt each detected span and store in RedactStore.

        Returns a new list with redact_token set on each Detection.
        """
        store = self._get_redact_store()
        kms = self._get_kms()
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=_DEFAULT_HANDLE_TTL_S)
        updated: list[Detection] = []
        for det in detections:
            raw_value = text[det.start : det.end]
            handle = uuid.uuid4().hex
            dek = new_dek()
            aad = handle.encode() + b"|" + det.entity_type.encode()
            nonce, ct = encrypt_value(raw_value, dek, aad)
            wrapped = kms.wrap(dek)
            store.put(
                RedactRecord(
                    handle=handle,
                    wrapped_dek=wrapped.ciphertext,
                    kek_key_id=wrapped.kek_key_id,
                    nonce=nonce,
                    ciphertext=ct,
                    entity_type=det.entity_type,
                    created_at=now,
                    expires_at=expires_at,
                )
            )
            self._get_auditor().record_handle_event(
                action="handle_put", handle=handle, entity_type=det.entity_type
            )
            self._dek_cache.put((handle, wrapped.kek_key_id), dek)
            del dek
            updated.append(det.model_copy(update={"redact_token": handle}))
        return updated

    def unmask(self, handle: str, *, principal_id: str | None = None) -> str | None:
        """Return the original value for *handle*, or None if not found/expired/tampered.

        No authorization check — library callers are trusted. The FastAPI layer
        enforces principal-based authorization via Depends(get_principal).
        """
        store = self._get_redact_store()
        record = store.get(handle)
        if record is None:
            self._get_auditor().record_unmask(
                handle=handle, principal_id=principal_id, success=False
            )
            return None
        cache_key = (handle, record.kek_key_id)
        dek = self._dek_cache.get(cache_key)
        if dek is None:
            kms = self._get_kms()
            try:
                dek = kms.unwrap(
                    WrappedDEK(ciphertext=record.wrapped_dek, kek_key_id=record.kek_key_id)
                )
            except Exception:
                self._get_auditor().record_unmask(
                    handle=handle, principal_id=principal_id, success=False
                )
                return None
            self._dek_cache.put(cache_key, dek)
        aad = handle.encode() + b"|" + record.entity_type.encode()
        plaintext_bytes = decrypt_value(record.ciphertext, record.nonce, dek, aad)
        success = plaintext_bytes is not None
        self._get_auditor().record_unmask(handle=handle, principal_id=principal_id, success=success)
        if not success:
            return None
        return plaintext_bytes.decode("utf-8")  # type: ignore[union-attr]


def _redact(
    text: str,
    detections: list[Detection],
    placeholder_fn: Callable[[Detection], str],
) -> str:
    """Replace detected spans back-to-front so positions stay valid."""
    result = text
    for det in sorted(detections, key=lambda d: d.start, reverse=True):
        placeholder = placeholder_fn(det)
        result = result[: det.start] + placeholder + result[det.end :]
    return result
