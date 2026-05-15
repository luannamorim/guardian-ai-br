"""AES-256-GCM envelope encryption primitives.

No I/O, no logging, no print — safe to call inside PII-handling paths.
"""

import secrets
import threading
import time
from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_DEK_LEN = 32


def new_dek() -> bytes:
    return secrets.token_bytes(_DEK_LEN)


def encrypt_value(plaintext: str, dek: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with *dek* (AES-256-GCM).

    Returns (nonce, ciphertext_with_tag). The 16-byte GCM auth tag is
    appended to the ciphertext by the cryptography library.
    """
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = AESGCM(dek).encrypt(nonce, plaintext.encode(), aad)
    return nonce, ct


def decrypt_value(ciphertext: bytes, nonce: bytes, dek: bytes, aad: bytes) -> bytes | None:
    """Decrypt *ciphertext*. Returns plaintext bytes, or None on auth-tag failure.

    Returning None (rather than raising) prevents callers from distinguishing
    "wrong DEK" vs "tampered ciphertext" — both map to handle-not-found.
    """
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


class DEKCache:
    """In-memory TTL LRU cache for decrypted DEKs.

    Threadsafe. DEKs are evicted after *ttl_s* seconds or when *max_size*
    is exceeded (LRU). Never persisted to disk.
    """

    def __init__(self, ttl_s: int = 300, max_size: int = 1024) -> None:
        self._ttl_s = ttl_s
        self._max_size = max_size
        self._store: OrderedDict[tuple[str, str], tuple[bytes, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple[str, str]) -> bytes | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            dek, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return dek

    def put(self, key: tuple[str, str], dek: bytes) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            else:
                if len(self._store) >= self._max_size:
                    self._store.popitem(last=False)
            self._store[key] = (dek, time.monotonic() + self._ttl_s)

    def invalidate(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._store.pop(key, None)
