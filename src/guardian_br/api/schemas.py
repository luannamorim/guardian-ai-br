from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian_br.core.adversarial import AdversarialResult
from guardian_br.core.modes import Mode
from guardian_br.core.schemas import SCHEMA_VERSION

_HANDLE_PATTERN = r"^[a-f0-9]{32}$"


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    mode: Mode | None = None
    skip_adversarial: bool = False


class UnmaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    handle: str = Field(pattern=_HANDLE_PATTERN, min_length=32, max_length=32)


class UnmaskResponse(BaseModel):
    value: str


class HealthResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    components: dict[str, Literal["ok", "fail", "skipped"]]
    schema_version: Literal["3"] = SCHEMA_VERSION


class ErrorResponse(BaseModel):
    detail: str
    code: str
    schema_version: Literal["3"] = SCHEMA_VERSION
    adversarial: AdversarialResult | None = None
