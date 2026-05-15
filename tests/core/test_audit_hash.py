"""Tests for core/audit_hash.py."""

from __future__ import annotations

import base64
import os

import pytest

from guardian_br.core.audit_hash import load_salt, salted_hash


def test_determinism() -> None:
    salt = b"a" * 32
    assert salted_hash("hello", salt) == salted_hash("hello", salt)


def test_different_values_different_hashes() -> None:
    salt = b"a" * 32
    assert salted_hash("hello", salt) != salted_hash("world", salt)


def test_different_salts_different_hashes() -> None:
    assert salted_hash("hello", b"a" * 32) != salted_hash("hello", b"b" * 32)


def test_returns_hex_string() -> None:
    result = salted_hash("test", b"x" * 32)
    assert len(result) == 64
    int(result, 16)  # raises ValueError if not hex


def test_load_salt_from_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = os.urandom(32)
    b64 = base64.b64encode(raw).decode()
    assert load_salt(b64) == raw


def test_load_salt_warns_when_none() -> None:
    with pytest.warns(RuntimeWarning, match="GUARDIAN_BR_AUDIT_SALT not set"):
        salt = load_salt(None)
    assert len(salt) == 32


def test_load_salt_none_returns_random_bytes() -> None:
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s1 = load_salt(None)
        s2 = load_salt(None)
    assert s1 != s2
