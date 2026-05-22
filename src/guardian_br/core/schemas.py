from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from guardian_br.core.adversarial import AdversarialResult
from guardian_br.core.modes import Mode

if TYPE_CHECKING:
    pass

SCHEMA_VERSION: Literal["3"] = "3"


class Detection(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: str
    start: int
    end: int
    score: float
    lgpd_article: str | None = None
    redact_token: str | None = None


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["3"] = SCHEMA_VERSION
    mode: Mode = Mode.REDACT
    blocked: bool = False
    shadow: bool = False
    would_block: bool = False
    text: str
    detections: list[Detection]
    redacted_text: str
    adversarial: AdversarialResult | None = None
