from __future__ import annotations

from collections.abc import Sequence

import spacy
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from guardian_br.pii.custom import CustomRecognizerSpec, build_custom_recognizer
from guardian_br.pii.recognizers.cnh import CnhRecognizer
from guardian_br.pii.recognizers.cnpj import CnpjRecognizer
from guardian_br.pii.recognizers.cpf import CpfRecognizer
from guardian_br.pii.recognizers.pis import PisRecognizer
from guardian_br.pii.recognizers.rg import RgRecognizer
from guardian_br.pii.recognizers.titulo_eleitor import TituloEleitorRecognizer


class _BlankSpacyNlpEngine(SpacyNlpEngine):
    """SpaCy NLP engine backed by blank (download-free) language models.

    Uses spacy.blank(lang_code) instead of spacy.load(model_name) so the
    engine works with no model downloads. Provides tokenization for context-
    word scoring; NER is unavailable (not needed for pattern-based recognizers).
    Swap to a full model (e.g. pt_core_news_sm) by replacing this class with
    a standard SpacyNlpEngine in production.
    """

    def load(self) -> None:
        self.nlp = {}  # type: ignore[assignment]
        for model in self.models:
            lang_code = model["lang_code"]
            self.nlp[lang_code] = spacy.blank(lang_code)  # type: ignore[index]


def build_default_registry(
    custom_recognizers: Sequence[CustomRecognizerSpec] | None = None,
) -> RecognizerRegistry:
    """Return a RecognizerRegistry containing all active BR recognizers.

    Optional ``custom_recognizers`` adds user-supplied specs after the
    built-ins so a misbehaving custom regex cannot mask a built-in match.
    """
    registry = RecognizerRegistry(supported_languages=["pt"])
    registry.add_recognizer(CpfRecognizer())
    registry.add_recognizer(CnpjRecognizer())
    registry.add_recognizer(PisRecognizer())
    registry.add_recognizer(CnhRecognizer())
    registry.add_recognizer(TituloEleitorRecognizer())
    registry.add_recognizer(RgRecognizer())
    for spec in custom_recognizers or ():
        registry.add_recognizer(build_custom_recognizer(spec))
    return registry


def build_analyzer_engine(
    custom_recognizers: Sequence[CustomRecognizerSpec] | None = None,
) -> AnalyzerEngine:
    """Build a Presidio AnalyzerEngine configured for PT-BR."""
    nlp_engine = _BlankSpacyNlpEngine(models=[{"lang_code": "pt", "model_name": "blank_pt"}])
    nlp_engine.load()
    registry = build_default_registry(custom_recognizers=custom_recognizers)
    return AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=registry,
        supported_languages=["pt"],
    )
