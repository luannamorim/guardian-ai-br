from __future__ import annotations

from pydantic import AnyHttpUrl, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DashboardSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_BR_DASHBOARD_",
        frozen=True,
        extra="ignore",
    )

    api_url: AnyHttpUrl
    api_key: SecretStr
    default_days: int = 7
    max_rows: int = 5000
    request_timeout_s: float = 10.0
