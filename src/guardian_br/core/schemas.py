from typing import Literal

from pydantic import BaseModel, ConfigDict

from guardian_br.core.modes import Mode

SCHEMA_VERSION: Literal["2"] = "2"


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

    schema_version: Literal["2"] = SCHEMA_VERSION
    mode: Mode = Mode.REDACT
    blocked: bool = False
    text: str
    detections: list[Detection]
    redacted_text: str
