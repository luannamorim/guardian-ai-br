from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from guardian_br.core.modes import Mode


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_BR_",
        frozen=True,
        extra="ignore",
    )

    api_keys_hashed: frozenset[str] = frozenset()
    rate_limit_per_key: str = "100/second"
    default_mode: Mode = Mode.REDACT
    metrics_require_auth: bool = True
    max_text_len: int = 10_240
    ollama_base_url: str = "http://localhost:11434"
    llama_guard_model: str = "llama-guard3:8b"
    adversarial_enabled: bool = True
    adversarial_timeout_s: float = 1.5
    adversarial_cache_ttl_s: int = 300
    adversarial_cache_max: int = 1024
    adversarial_prompt: str = "llama_guard_ptbr_v1"
    adversarial_warmup_on_startup: bool = True
    adversarial_fail_open: bool = True

    audit_salt: SecretStr | None = None
    audit_salt_key_id: str = "default"
    audit_hmac_chain: bool = False
    audit_hmac_secret: SecretStr | None = None
    audit_fallback_path: Path = Path("~/.guardian_br/audit_fallback.jsonl").expanduser()

    @field_validator("api_keys_hashed", mode="before")
    @classmethod
    def _parse_keys(cls, v: object) -> frozenset[str]:
        if isinstance(v, str):
            return frozenset(k.strip() for k in v.split(",") if k.strip())
        if isinstance(v, (set, frozenset, list)):
            return frozenset(str(x) for x in v)
        return frozenset()
