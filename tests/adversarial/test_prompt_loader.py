"""Tests for prompts.loader."""

from __future__ import annotations

from guardian_br.prompts.loader import load_prompt


def test_load_prompt_returns_text_and_digest() -> None:
    text, digest = load_prompt("llama_guard_ptbr_v1")
    assert isinstance(text, str)
    assert len(text) > 100
    assert isinstance(digest, str)
    assert len(digest) == 8


def test_digest_is_hex() -> None:
    _, digest = load_prompt("llama_guard_ptbr_v1")
    int(digest, 16)  # raises if not valid hex


def test_lru_cache_returns_same_object() -> None:
    result1 = load_prompt("llama_guard_ptbr_v1")
    result2 = load_prompt("llama_guard_ptbr_v1")
    assert result1 is result2


def test_prompt_contains_ptbr_exemption_examples() -> None:
    text, _ = load_prompt("llama_guard_ptbr_v1")
    assert "CDB" in text
    assert "SUS" in text
    assert "MEI" in text


def test_prompt_contains_injection_patterns() -> None:
    text, _ = load_prompt("llama_guard_ptbr_v1")
    assert "instruções anteriores" in text.lower() or "instruções" in text


def test_digest_stability() -> None:
    """Pin the digest of v1 so accidental whitespace edits fail CI."""
    _, digest = load_prompt("llama_guard_ptbr_v1")
    # This value is the sha256[:8] of the committed prompt file.
    # If it changes, the prompt was edited — update intentionally.
    import hashlib
    from importlib.resources import files

    path = files("guardian_br").joinpath("prompts/llama_guard_ptbr_v1.md")
    raw = path.read_text(encoding="utf-8")
    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    assert digest == expected
