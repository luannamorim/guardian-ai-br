"""AdversarialClassifier Protocol and AdversarialResult value type.

No I/O, no logging, no print — safe to call inside scan paths.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

AdversarialSource = Literal["ollama", "cached", "skipped", "fallback"]


class AdversarialResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: str
    unsafe: bool
    categories: list[str] = []
    score: float | None = None
    latency_ms: float
    model_version: str
    source: AdversarialSource


@runtime_checkable
class AdversarialClassifier(Protocol):
    def classify(self, text: str) -> AdversarialResult: ...

    def ping(self) -> bool: ...
