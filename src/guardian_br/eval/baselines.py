"""Comparative baselines for the eval runner (SPEC FR 10).

Each baseline exposes a uniform interface so the runner can score them on
the same corpus and emit a side-by-side report:

- ``GuardianBaseline`` — full Guardian-BR with BR recognizers + PT-BR prompt
- ``PlainPresidioBaseline`` — Presidio AnalyzerEngine with no BR recognizers
  (the published numbers callers see when they reach for vanilla Presidio)
- ``PlainLlamaGuardBaseline`` — same Ollama backend but the generic English
  Llama Guard prompt, no PT-BR legitimate-query primer

Baselines are constructed once and reused per row. Latency is per-row
wall-clock (perf_counter) so all candidates pay the same warm-up cost.
"""

from __future__ import annotations

from typing import Protocol


class _Detection(Protocol):
    entity_type: str
    start: int
    end: int


class Baseline(Protocol):
    name: str

    def scan_pii(self, text: str) -> list[_Detection]: ...

    def classify_adversarial(self, text: str) -> bool: ...


class GuardianBaseline:
    """Full Guardian-BR — what users actually run."""

    name = "guardian-br"

    def __init__(self) -> None:
        from guardian_br.guardian import Guardian

        self._g = Guardian()
        self._g.scan("aquecimento")

    def scan_pii(self, text: str) -> list[_Detection]:
        return list(self._g.scan(text, skip_adversarial=True).detections)

    def classify_adversarial(self, text: str) -> bool:
        result = self._g.scan(text)
        return result.adversarial is not None and result.adversarial.unsafe


class PlainPresidioBaseline:
    """Presidio AnalyzerEngine without Guardian-BR's BR recognizers.

    Establishes the recall floor for BR identifiers in vanilla Presidio.
    Uses the same blank-pt spaCy engine as Guardian-BR so latency
    comparisons isolate recognizer cost.
    """

    name = "plain-presidio"

    def __init__(self) -> None:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

        from guardian_br.pii.registry import _BlankSpacyNlpEngine

        nlp_engine = _BlankSpacyNlpEngine(
            models=[{"lang_code": "pt", "model_name": "blank_pt"}]
        )
        nlp_engine.load()
        registry = RecognizerRegistry(supported_languages=["pt"])
        # Deliberately empty — represents "what Presidio offers BR users
        # out-of-the-box" (no custom BR recognizers installed).
        self._engine = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["pt"],
        )

    def scan_pii(self, text: str) -> list[_Detection]:
        return list(self._engine.analyze(text=text, language="pt", entities=[]))

    def classify_adversarial(self, text: str) -> bool:  # noqa: ARG002
        # Plain Presidio has no adversarial classifier.
        return False


class PlainLlamaGuardBaseline:
    """Llama Guard with its native taxonomy prompt and no PT-BR primer."""

    name = "plain-llama-guard"

    def __init__(self) -> None:
        from guardian_br.adversarial.ollama_classifier import OllamaClassifier

        self._clf = OllamaClassifier(prompt_name="llama_guard_plain_v1")

    def scan_pii(self, text: str) -> list[_Detection]:  # noqa: ARG002
        return []

    def classify_adversarial(self, text: str) -> bool:
        return self._clf.classify(text).unsafe


def build_baseline(name: str) -> Baseline:
    if name == "guardian-br":
        return GuardianBaseline()
    if name == "plain-presidio":
        return PlainPresidioBaseline()
    if name == "plain-llama-guard":
        return PlainLlamaGuardBaseline()
    raise ValueError(f"unknown baseline: {name!r}")


ALL_BASELINES = ("guardian-br", "plain-presidio", "plain-llama-guard")
