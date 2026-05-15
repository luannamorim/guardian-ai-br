"""Integration tests for Guardian.scan with REVERSIBLE_REDACT mode."""

import base64
import secrets

import pytest

from guardian_br import Guardian, Mode
from guardian_br.core.kms import EnvKMSProvider
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore


def make_guardian(monkeypatch: pytest.MonkeyPatch) -> Guardian:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", key)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    store = SQLiteRedactStore(":memory:")
    kms = EnvKMSProvider()
    return Guardian(redact_store=store, kms=kms, mode_default=Mode.REVERSIBLE_REDACT)


def test_reversible_redact_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    result = g.scan("meu cpf é 123.456.789-09")
    assert len(result.detections) == 1
    handle = result.detections[0].redact_token
    assert handle is not None
    assert g.unmask(handle) == "123.456.789-09"


def test_reversible_redact_placeholder_format(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    result = g.scan("cpf 123.456.789-09")
    handle = result.detections[0].redact_token
    assert result.redacted_text == f"cpf <RDX:{handle}>"


def test_reversible_redact_multiple_detections(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    text = "CPF 123.456.789-09 e CNPJ 11.222.333/0001-81"
    result = g.scan(text)
    assert len(result.detections) == 2
    for det in result.detections:
        assert det.redact_token is not None
        recovered = g.unmask(det.redact_token)
        assert recovered is not None
        assert recovered in text


def test_unmask_unknown_handle_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    assert g.unmask("0" * 32) is None


def test_unmask_after_delete_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", key)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    store = SQLiteRedactStore(":memory:")
    g = Guardian(redact_store=store, kms=EnvKMSProvider(), mode_default=Mode.REVERSIBLE_REDACT)
    result = g.scan("cpf 123.456.789-09")
    handle = result.detections[0].redact_token
    assert handle is not None
    store.delete(handle)
    assert g.unmask(handle) is None


def test_redact_mode_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    result = g.scan("cpf 123.456.789-09", mode=Mode.REDACT)
    assert result.redacted_text == "cpf <BR_CPF>"
    assert result.detections[0].redact_token is None


def test_block_mode_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from guardian_br import BlockedError

    g = make_guardian(monkeypatch)
    with pytest.raises(BlockedError) as exc_info:
        g.scan("cpf 123.456.789-09", mode=Mode.BLOCK)
    assert len(exc_info.value.detections) == 1


def test_block_mode_no_detections_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    g = make_guardian(monkeypatch)
    result = g.scan("nenhum dado sensível aqui", mode=Mode.BLOCK)
    assert result.blocked is False
    assert result.detections == []
