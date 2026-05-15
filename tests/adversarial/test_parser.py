"""Tests for parse_llama_guard."""

from __future__ import annotations

import pytest

from guardian_br.adversarial.errors import AdversarialParseError
from guardian_br.adversarial.ollama_parser import parse_llama_guard


def test_safe_response() -> None:
    label, cats = parse_llama_guard("safe")
    assert label == "safe"
    assert cats == []


def test_safe_response_case_insensitive() -> None:
    label, cats = parse_llama_guard("Safe")
    assert label == "safe"


def test_safe_response_with_whitespace() -> None:
    label, cats = parse_llama_guard("  safe  ")
    assert label == "safe"


def test_unsafe_single_category() -> None:
    label, cats = parse_llama_guard("unsafe\nS14")
    assert label == "S14"
    assert cats == ["S14"]


def test_unsafe_multi_category() -> None:
    label, cats = parse_llama_guard("unsafe\nS1,S14")
    assert label == "S1"
    assert cats == ["S1", "S14"]


def test_unsafe_with_spaces_around_categories() -> None:
    label, cats = parse_llama_guard("unsafe\nS1, S5")
    assert label == "S1"
    assert cats == ["S1", "S5"]


def test_unsafe_case_insensitive() -> None:
    label, cats = parse_llama_guard("UNSAFE\nS1")
    assert label == "S1"
    assert cats == ["S1"]


def test_malformed_raises_parse_error() -> None:
    with pytest.raises(AdversarialParseError):
        parse_llama_guard("I'm not sure if this is safe or not.")


def test_empty_raises_parse_error() -> None:
    with pytest.raises(AdversarialParseError):
        parse_llama_guard("")


def test_unsafe_without_category_raises() -> None:
    with pytest.raises(AdversarialParseError):
        parse_llama_guard("unsafe")
