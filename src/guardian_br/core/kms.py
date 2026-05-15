"""KMSProvider Protocol and EnvKMSProvider implementation.

EnvKMSProvider reads KEK material from environment variables:

    GUARDIAN_BR_KEK_v1=<base64-encoded 32 bytes>
    GUARDIAN_BR_KEK_CURRENT_ID=v1            (default "v1")

KEK rotation: add GUARDIAN_BR_KEK_v2, set CURRENT_ID=v2, restart.
Old records with kek_key_id="v1" remain decryptable as long as
GUARDIAN_BR_KEK_v1 stays in the environment.
"""

import base64
import os
import secrets
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

from guardian_br.core.crypto import _NONCE_LEN


class WrappedDEK(BaseModel):
    model_config = ConfigDict(frozen=True)

    ciphertext: bytes
    kek_key_id: str


@runtime_checkable
class KMSProvider(Protocol):
    def wrap(self, dek: bytes) -> WrappedDEK: ...

    def unwrap(self, wrapped: WrappedDEK) -> bytes: ...

    def current_key_id(self) -> str: ...


class EnvKMSProvider:
    """Reads KEK from environment variables. Zero external dependencies.

    Wrapping algorithm: AES-256-GCM with 12-byte random nonce.
    AAD = kek_key_id.encode() — binds wrapped DEK to its key version.
    """

    _ENV_PREFIX = "GUARDIAN_BR_KEK_"
    _ENV_CURRENT_ID = "GUARDIAN_BR_KEK_CURRENT_ID"

    def current_key_id(self) -> str:
        return os.environ.get(self._ENV_CURRENT_ID, "v1")

    def _load_kek(self, key_id: str) -> bytes:
        env_var = f"{self._ENV_PREFIX}{key_id}"
        raw = os.environ.get(env_var)
        if not raw:
            raise RuntimeError(
                f"KMS environment variable {env_var!r} not set. "
                "Set GUARDIAN_BR_KEK_<id> to a base64-encoded 32-byte key."
            )
        decoded = base64.b64decode(raw)
        if len(decoded) != 32:
            raise ValueError(f"{env_var} must decode to exactly 32 bytes (got {len(decoded)})")
        return decoded

    def wrap(self, dek: bytes) -> WrappedDEK:
        key_id = self.current_key_id()
        kek = self._load_kek(key_id)
        nonce = secrets.token_bytes(_NONCE_LEN)
        aad = key_id.encode()
        ct = AESGCM(kek).encrypt(nonce, dek, aad)
        return WrappedDEK(ciphertext=nonce + ct, kek_key_id=key_id)

    def unwrap(self, wrapped: WrappedDEK) -> bytes:
        kek = self._load_kek(wrapped.kek_key_id)
        nonce, ct = wrapped.ciphertext[:_NONCE_LEN], wrapped.ciphertext[_NONCE_LEN:]
        aad = wrapped.kek_key_id.encode()
        try:
            return AESGCM(kek).decrypt(nonce, ct, aad)
        except Exception as exc:
            raise ValueError("DEK unwrap failed — wrong KEK or tampered ciphertext") from exc
