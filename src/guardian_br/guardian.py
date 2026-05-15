from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.crypto import DEKCache, decrypt_value, encrypt_value, new_dek
from guardian_br.core.entities import BR_ENTITIES
from guardian_br.core.errors import BlockedError
from guardian_br.core.kms import EnvKMSProvider, KMSProvider, WrappedDEK
from guardian_br.core.modes import Mode
from guardian_br.core.redact_store import RedactRecord, RedactStore
from guardian_br.core.schemas import Detection, ScanResult
from guardian_br.lgpd.loader import load_lgpd_mapping

if TYPE_CHECKING:
    pass

_DEFAULT_HANDLE_TTL_S = 86_400  # 24 hours


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
        mode_default: Mode = Mode.REDACT,
        dek_cache_ttl_s: int = 300,
    ) -> None:
        self._analyzer = analyzer
        self._redact_store = redact_store
        self._kms = kms
        self._mode_default = mode_default
        self._dek_cache = DEKCache(ttl_s=dek_cache_ttl_s)

    @property
    def mode_default(self) -> Mode:
        return self._mode_default

    def warm_up(self) -> None:
        """Force lazy initialization of the analyzer engine."""
        self._get_analyzer()

    def _get_analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            from guardian_br.pii.registry import build_analyzer_engine

            self._analyzer = build_analyzer_engine()
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

    def scan(self, text: str, *, mode: Mode | None = None) -> ScanResult:
        """Scan *text* for BR PII and return a frozen ScanResult.

        Detections include only entities whose checksums pass validation.
        The ``mode`` argument overrides the instance's ``mode_default``.

        BLOCK: raises BlockedError if any PII is detected.
        REDACT: replaces each span with ``<ENTITY_TYPE>``.
        REVERSIBLE_REDACT: replaces each span with ``<RDX:{handle}>``
            and stores the encrypted original (AES-256-GCM) so it can be
            recovered via unmask(handle).
        """
        effective_mode = mode if mode is not None else self._mode_default
        analyzer = self._get_analyzer()
        mapping = load_lgpd_mapping()

        results = analyzer.analyze(
            text=text,
            language="pt",
            entities=list(BR_ENTITIES),
        )

        detections: list[Detection] = []
        for r in results:
            rule = mapping.rules.get(r.entity_type)
            lgpd_article = rule.lgpd_articles[0].article if rule else None
            detections.append(
                Detection(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=r.score,
                    lgpd_article=lgpd_article,
                )
            )

        if effective_mode is Mode.BLOCK:
            if detections:
                raise BlockedError(detections)
            return ScanResult(
                mode=effective_mode,
                blocked=False,
                text=text,
                detections=[],
                redacted_text=text,
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
            text=text,
            detections=detections,
            redacted_text=redacted_text,
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
            self._dek_cache.put((handle, wrapped.kek_key_id), dek)
            del dek
            updated.append(det.model_copy(update={"redact_token": handle}))
        return updated

    def unmask(self, handle: str) -> str | None:
        """Return the original value for *handle*, or None if not found/expired/tampered.

        No authorization check — library callers are trusted. The FastAPI layer
        enforces principal-based authorization via Depends(get_principal).
        """
        store = self._get_redact_store()
        record = store.get(handle)
        if record is None:
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
                return None
            self._dek_cache.put(cache_key, dek)
        aad = handle.encode() + b"|" + record.entity_type.encode()
        plaintext_bytes = decrypt_value(record.ciphertext, record.nonce, dek, aad)
        if plaintext_bytes is None:
            return None
        return plaintext_bytes.decode("utf-8")


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
