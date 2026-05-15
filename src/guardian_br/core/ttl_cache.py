"""Generic TTL LRU cache.

No I/O, no logging, no print — safe to call inside PII-handling paths.
Mirror of DEKCache (core/crypto.py) generalized to arbitrary key/value types.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Hashable
from typing import Generic, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class TTLLRUCache(Generic[K, V]):
    """Threadsafe in-memory TTL LRU cache.

    Entries are evicted after *ttl_s* seconds or when *max_size* is exceeded
    (LRU order). Never persisted to disk.
    """

    def __init__(self, *, ttl_s: int = 300, max_size: int = 1024) -> None:
        self._ttl_s = ttl_s
        self._max_size = max_size
        self._store: OrderedDict[K, tuple[V, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: K) -> V | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return value

    def put(self, key: K, value: V) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            else:
                if len(self._store) >= self._max_size:
                    self._store.popitem(last=False)
            self._store[key] = (value, time.monotonic() + self._ttl_s)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
