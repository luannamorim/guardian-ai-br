from typing import Literal

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION: Literal["1"] = "1"


class Detection(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: str
    start: int
    end: int
    score: float
    lgpd_article: str | None = None


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1"] = SCHEMA_VERSION
    text: str
    detections: list[Detection]
    redacted_text: str
