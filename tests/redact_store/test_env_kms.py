"""Tests for EnvKMSProvider."""

import base64
import secrets

import pytest

from guardian_br.core.crypto import new_dek
from guardian_br.core.kms import EnvKMSProvider, WrappedDEK


def _b64_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def test_wrap_unwrap_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", _b64_key())
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    kms = EnvKMSProvider()
    dek = new_dek()
    wrapped = kms.wrap(dek)
    assert wrapped.kek_key_id == "v1"
    recovered = kms.unwrap(wrapped)
    assert recovered == dek


def test_current_key_id_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIAN_BR_KEK_CURRENT_ID", raising=False)
    kms = EnvKMSProvider()
    assert kms.current_key_id() == "v1"


def test_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIAN_BR_KEK_v1", raising=False)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    kms = EnvKMSProvider()
    with pytest.raises(RuntimeError, match="GUARDIAN_BR_KEK_v1"):
        kms.wrap(new_dek())


def test_kek_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    kek_v1 = _b64_key()
    kek_v2 = _b64_key()
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", kek_v1)
    monkeypatch.setenv("GUARDIAN_BR_KEK_v2", kek_v2)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")

    kms = EnvKMSProvider()
    dek = new_dek()
    wrapped_v1 = kms.wrap(dek)
    assert wrapped_v1.kek_key_id == "v1"

    # Rotate: v2 is now current
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v2")
    assert kms.current_key_id() == "v2"

    # Old record (wrapped with v1) still decryptable
    recovered = kms.unwrap(wrapped_v1)
    assert recovered == dek

    # New wraps use v2
    wrapped_v2 = kms.wrap(dek)
    assert wrapped_v2.kek_key_id == "v2"
    assert kms.unwrap(wrapped_v2) == dek


def test_tampered_wrapped_dek_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", _b64_key())
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")
    kms = EnvKMSProvider()
    wrapped = kms.wrap(new_dek())
    tampered_ct = bytes([wrapped.ciphertext[0] ^ 0xFF]) + wrapped.ciphertext[1:]
    bad = WrappedDEK(ciphertext=tampered_ct, kek_key_id="v1")
    with pytest.raises(ValueError):
        kms.unwrap(bad)
