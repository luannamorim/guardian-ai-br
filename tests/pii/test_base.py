"""Unit tests for ChecksumValidatedRecognizer base class.

Uses a minimal fixture subclass so the base class is tested in isolation,
independent of any production recognizer's regex or checksum logic.
"""

from unittest.mock import MagicMock

import pytest
from presidio_analyzer import Pattern
from presidio_analyzer.entity_recognizer import EntityRecognizer

from guardian_br.pii.recognizers._base import (
    _BASE_SCORE,
    ChecksumValidatedRecognizer,
)
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_FIXTURE_COMPILED = compile_pattern(r"\d{4}")
_FIXTURE_ENTITY = "FIXTURE_ENTITY"


class _AlwaysValidRecognizer(ChecksumValidatedRecognizer):
    SUPPORTED_ENTITY = _FIXTURE_ENTITY
    PATTERNS = [Pattern("FIXTURE_PATTERN", _FIXTURE_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["fixture"]
    COMPILED_PATTERN = _FIXTURE_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return True


class _AlwaysInvalidRecognizer(_AlwaysValidRecognizer):
    def validate_result(self, pattern_text: str) -> bool:
        return False


def test_compiled_pattern_drives_matching() -> None:
    recognizer = _AlwaysValidRecognizer()
    assert recognizer._analyze_patterns_in_text("abcd") == []
    assert len(recognizer._analyze_patterns_in_text("1234")) == 1


def test_validate_result_default_raises_not_implemented() -> None:
    class _NoOverride(ChecksumValidatedRecognizer):
        SUPPORTED_ENTITY = _FIXTURE_ENTITY
        PATTERNS = [Pattern("FIXTURE_PATTERN", _FIXTURE_COMPILED.pattern, _BASE_SCORE)]
        CONTEXT = ["fixture"]
        COMPILED_PATTERN = _FIXTURE_COMPILED

    recognizer = _NoOverride()
    with pytest.raises(NotImplementedError):
        recognizer.validate_result("1234")


def test_checksum_pass_emits_full_score() -> None:
    recognizer = _AlwaysValidRecognizer()
    results = recognizer._analyze_patterns_in_text("1234")
    assert len(results) == 1
    assert results[0].score == _BASE_SCORE
    assert results[0].entity_type == _FIXTURE_ENTITY


def test_checksum_fail_silences_match() -> None:
    recognizer = _AlwaysInvalidRecognizer()
    results = recognizer._analyze_patterns_in_text("1234")
    assert len(results) == 1
    assert results[0].score == EntityRecognizer.MIN_SCORE


def test_redos_timeout_is_caught() -> None:
    import regex

    mock_compiled = MagicMock()
    mock_compiled.finditer.side_effect = regex.error("timeout")

    class _TimeoutRecognizer(_AlwaysValidRecognizer):
        COMPILED_PATTERN = mock_compiled

    recognizer = _TimeoutRecognizer()
    results = recognizer._analyze_patterns_in_text("1234")
    assert results == []


def test_subclass_without_classvars_raises() -> None:
    class _Incomplete(ChecksumValidatedRecognizer):
        pass

    with pytest.raises(AttributeError):
        _Incomplete()
