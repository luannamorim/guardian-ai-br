from functools import lru_cache
from importlib.resources import files

import yaml
from pydantic import BaseModel


class LGPDArticleRef(BaseModel):
    article: str
    clause: str


class LGPDRule(BaseModel):
    description: str
    sensitivity: str
    lgpd_articles: list[LGPDArticleRef]
    art7_purpose_bases: list[str]
    retention_note: str
    notes: str


class LGPDMapping(BaseModel):
    schema_version: int
    disclaimer: str
    rules: dict[str, LGPDRule]


@lru_cache(maxsize=1)
def load_lgpd_mapping() -> LGPDMapping:
    data_path = files("guardian_br").joinpath("data/lgpd_mapping.yaml")
    raw = yaml.safe_load(data_path.read_text(encoding="utf-8"))
    return LGPDMapping.model_validate(raw)
