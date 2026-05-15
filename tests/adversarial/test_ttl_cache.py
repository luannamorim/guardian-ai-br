"""Tests for TTLLRUCache."""

from __future__ import annotations

import threading
import time

import pytest

from guardian_br.core.ttl_cache import TTLLRUCache


def test_put_get_roundtrip() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=10)
    cache.put("k", 42)
    assert cache.get("k") == 42


def test_get_unknown_returns_none() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=10)
    assert cache.get("missing") is None


def test_ttl_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    now = time.monotonic()
    cache: TTLLRUCache[str, str] = TTLLRUCache(ttl_s=10, max_size=10)
    monkeypatch.setattr("guardian_br.core.ttl_cache.time.monotonic", lambda: now)
    cache.put("k", "v")
    monkeypatch.setattr("guardian_br.core.ttl_cache.time.monotonic", lambda: now + 11)
    assert cache.get("k") is None


def test_lru_eviction() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=3)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    cache.get("a")  # touch a — b is now LRU
    cache.put("d", 4)  # evicts b
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert cache.get("d") == 4


def test_len_tracks_size() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=10)
    assert len(cache) == 0
    cache.put("a", 1)
    assert len(cache) == 1
    cache.put("b", 2)
    assert len(cache) == 2


def test_clear_empties_cache() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=10)
    cache.put("a", 1)
    cache.clear()
    assert len(cache) == 0
    assert cache.get("a") is None


def test_thread_safety() -> None:
    cache: TTLLRUCache[str, int] = TTLLRUCache(ttl_s=60, max_size=200)
    errors: list[Exception] = []

    def writer(offset: int) -> None:
        try:
            for i in range(100):
                cache.put(f"{offset}-{i}", i)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(cache) <= 200
