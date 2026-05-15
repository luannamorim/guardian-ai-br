from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

from guardian_br.api.settings import Settings

if TYPE_CHECKING:
    from guardian_br.api.routes_health import HealthRegistry
    from guardian_br.core.redact_store import RedactStore
    from guardian_br.guardian import Guardian


def get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_guardian(request: Request) -> Guardian:
    return request.app.state.guardian  # type: ignore[no-any-return]


def get_health_registry(request: Request) -> HealthRegistry:
    return request.app.state.health  # type: ignore[no-any-return]


def get_store(request: Request) -> RedactStore:
    return request.app.state.store  # type: ignore[no-any-return]
