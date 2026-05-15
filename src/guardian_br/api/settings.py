from __future__ import annotations

from pydantic import field_validator
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

    @field_validator("api_keys_hashed", mode="before")
    @classmethod
    def _parse_keys(cls, v: object) -> frozenset[str]:
        if isinstance(v, str):
            return frozenset(k.strip() for k in v.split(",") if k.strip())
        if isinstance(v, (set, frozenset, list)):
            return frozenset(str(x) for x in v)
        return frozenset()
