"""Tests for shadow mode (SPEC FR 14).

Shadow mode lets operators preview a BLOCK policy without taking action:
the scan never raises, but the audit log records what would have happened.
"""

from __future__ import annotations

import pytest

from guardian_br import Guardian, Mode
from guardian_br.core.errors import BlockedError


def test_block_mode_raises_when_shadow_disabled() -> None:
    g = Guardian(mode_default=Mode.BLOCK)
    with pytest.raises(BlockedError):
        g.scan("meu cpf eh 123.456.789-09")


def test_shadow_mode_does_not_raise_on_block() -> None:
    g = Guardian(mode_default=Mode.BLOCK, shadow_mode=True)
    result = g.scan("meu cpf eh 123.456.789-09")
    assert result.blocked is False
    assert result.shadow is True
    assert result.would_block is True
    assert len(result.detections) == 1


def test_shadow_mode_per_scan_override() -> None:
    g = Guardian(mode_default=Mode.BLOCK)  # shadow_mode default False
    result = g.scan("meu cpf eh 123.456.789-09", shadow=True)
    assert result.blocked is False
    assert result.shadow is True
    assert result.would_block is True


def test_shadow_redacted_text_uses_redact_placeholders() -> None:
    g = Guardian(mode_default=Mode.BLOCK, shadow_mode=True)
    result = g.scan("meu cpf eh 123.456.789-09")
    assert result.redacted_text == "meu cpf eh <BR_CPF>"


def test_shadow_no_pii_returns_clean_result() -> None:
    g = Guardian(mode_default=Mode.BLOCK, shadow_mode=True)
    result = g.scan("texto sem nada sensível")
    assert result.blocked is False
    assert result.shadow is True
    assert result.would_block is False
    assert result.detections == []
    assert result.redacted_text == "texto sem nada sensível"


def test_shadow_mode_default_off_in_redact_mode() -> None:
    g = Guardian(mode_default=Mode.REDACT)
    result = g.scan("meu cpf eh 123.456.789-09")
    assert result.shadow is False
    assert result.would_block is False


def test_shadow_mode_in_redact_records_would_block_false() -> None:
    # In REDACT mode, would_block is always False (nothing to block).
    g = Guardian(mode_default=Mode.REDACT, shadow_mode=True)
    result = g.scan("meu cpf eh 123.456.789-09")
    assert result.would_block is False
    assert result.shadow is True


def test_shadow_property_exposed() -> None:
    g = Guardian(shadow_mode=True)
    assert g.shadow_mode is True
    g2 = Guardian()
    assert g2.shadow_mode is False
