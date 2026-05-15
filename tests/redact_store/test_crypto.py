"""Unit tests for crypto.py primitives."""

import time

from guardian_br.core.crypto import DEKCache, decrypt_value, encrypt_value, new_dek


def test_new_dek_is_32_bytes() -> None:
    assert len(new_dek()) == 32


def test_new_dek_is_random() -> None:
    assert new_dek() != new_dek()


def test_encrypt_decrypt_roundtrip() -> None:
    dek = new_dek()
    aad = b"test-aad"
    plaintext = "meu cpf é 123.456.789-09"
    nonce, ct = encrypt_value(plaintext, dek, aad)
    result = decrypt_value(ct, nonce, dek, aad)
    assert result is not None
    assert result.decode("utf-8") == plaintext


def test_decrypt_wrong_aad_returns_none() -> None:
    dek = new_dek()
    nonce, ct = encrypt_value("secret", dek, b"aad-v1")
    assert decrypt_value(ct, nonce, dek, b"aad-v2") is None


def test_decrypt_wrong_dek_returns_none() -> None:
    dek1 = new_dek()
    dek2 = new_dek()
    nonce, ct = encrypt_value("secret", dek1, b"aad")
    assert decrypt_value(ct, nonce, dek2, b"aad") is None


def test_decrypt_tampered_ciphertext_returns_none() -> None:
    dek = new_dek()
    nonce, ct = encrypt_value("secret", dek, b"aad")
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    assert decrypt_value(tampered, nonce, dek, b"aad") is None


def test_encrypt_nonce_is_random() -> None:
    dek = new_dek()
    n1, _ = encrypt_value("x", dek, b"a")
    n2, _ = encrypt_value("x", dek, b"a")
    assert n1 != n2


class TestDEKCache:
    def test_put_get_roundtrip(self) -> None:
        cache = DEKCache()
        dek = new_dek()
        cache.put(("h1", "v1"), dek)
        assert cache.get(("h1", "v1")) == dek

    def test_miss_returns_none(self) -> None:
        cache = DEKCache()
        assert cache.get(("nope", "v1")) is None

    def test_ttl_expiry(self) -> None:
        cache = DEKCache(ttl_s=0)
        dek = new_dek()
        cache.put(("h1", "v1"), dek)
        time.sleep(0.01)
        assert cache.get(("h1", "v1")) is None

    def test_lru_eviction(self) -> None:
        cache = DEKCache(ttl_s=300, max_size=2)
        dek_a = new_dek()
        dek_b = new_dek()
        dek_c = new_dek()
        cache.put(("a", "v1"), dek_a)
        cache.put(("b", "v1"), dek_b)
        cache.put(("c", "v1"), dek_c)
        assert cache.get(("a", "v1")) is None  # evicted (LRU)
        assert cache.get(("b", "v1")) == dek_b
        assert cache.get(("c", "v1")) == dek_c

    def test_invalidate(self) -> None:
        cache = DEKCache()
        dek = new_dek()
        cache.put(("h1", "v1"), dek)
        cache.invalidate(("h1", "v1"))
        assert cache.get(("h1", "v1")) is None

    def test_invalidate_nonexistent_is_noop(self) -> None:
        cache = DEKCache()
        cache.invalidate(("nope", "v1"))  # must not raise
