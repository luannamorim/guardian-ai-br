"""Tests for the custom-recognizer plugin interface (SPEC FR 12)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from guardian_br import CustomRecognizerSpec, Guardian


def test_custom_spec_rejects_invalid_entity_type() -> None:
    with pytest.raises(ValidationError):
        CustomRecognizerSpec(entity_type="lowercase", patterns=[r"\d+"])
    with pytest.raises(ValidationError):
        CustomRecognizerSpec(entity_type="HAS SPACE", patterns=[r"\d+"])


def test_custom_spec_rejects_empty_patterns() -> None:
    with pytest.raises(ValidationError):
        CustomRecognizerSpec(entity_type="X", patterns=[])


def test_custom_spec_rejects_uncompilable_pattern() -> None:
    with pytest.raises(ValidationError, match="invalid regex"):
        CustomRecognizerSpec(entity_type="X", patterns=[r"[unclosed"])


def test_custom_recognizer_detected_and_redacted() -> None:
    spec = CustomRecognizerSpec(
        entity_type="ACME_ACCOUNT",
        patterns=[r"ACME-\d{6}"],
        context=["conta"],
        lgpd_article="Art. 5º, I",
    )
    g = Guardian(custom_recognizers=[spec])
    result = g.scan("minha conta ACME-123456 está bloqueada")
    assert any(d.entity_type == "ACME_ACCOUNT" for d in result.detections)
    assert "<ACME_ACCOUNT>" in result.redacted_text


def test_custom_recognizer_lgpd_article_propagates() -> None:
    spec = CustomRecognizerSpec(
        entity_type="INT_CONTRACT",
        patterns=[r"CNT-[A-Z]{2}\d{4}"],
        lgpd_article="Art. 6º",
    )
    g = Guardian(custom_recognizers=[spec])
    result = g.scan("contrato CNT-AB1234")
    det = next(d for d in result.detections if d.entity_type == "INT_CONTRACT")
    assert det.lgpd_article == "Art. 6º"


def test_custom_recognizer_validator_filters_matches() -> None:
    # Only accept matches whose last digit is even
    def even_last(s: str) -> bool:
        return s[-1] in "02468"

    spec = CustomRecognizerSpec(
        entity_type="ACME_EVEN",
        patterns=[r"ACME-\d{6}"],
        validator=even_last,
    )
    g = Guardian(custom_recognizers=[spec])
    matched = g.scan("ACME-123456")  # even
    unmatched = g.scan("ACME-123457")  # odd
    assert any(d.entity_type == "ACME_EVEN" and d.score > 0 for d in matched.detections)
    assert not any(d.entity_type == "ACME_EVEN" and d.score > 0 for d in unmatched.detections)


def test_custom_recognizer_does_not_break_builtin() -> None:
    spec = CustomRecognizerSpec(entity_type="ACME_X", patterns=[r"ACME-\d+"])
    g = Guardian(custom_recognizers=[spec])
    result = g.scan("cpf 529.982.247-25 e ACME-9")
    types = {d.entity_type for d in result.detections}
    assert "BR_CPF" in types
    assert "ACME_X" in types


def test_custom_recognizer_validator_exception_silenced() -> None:
    def bad_validator(_: str) -> bool:
        raise RuntimeError("boom")

    spec = CustomRecognizerSpec(
        entity_type="ACME_VAL",
        patterns=[r"ACME-\d+"],
        validator=bad_validator,
    )
    g = Guardian(custom_recognizers=[spec])
    result = g.scan("ACME-1234")
    # validator returning falsy → recognizer emits at MIN_SCORE (0), which Presidio drops
    assert not any(d.entity_type == "ACME_VAL" and d.score > 0 for d in result.detections)
