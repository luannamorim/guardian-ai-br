"""Tests for the TituloEleitorRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_TITULO_ELEITOR
from guardian_br.pii.recognizers.titulo_eleitor import TituloEleitorRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = TituloEleitorRecognizer()
    assert BR_TITULO_ELEITOR in recognizer.supported_entities


def test_valid_titulo_detected(analyzer: AnalyzerEngine, valid_titulos_eleitor: list[str]) -> None:
    for titulo in valid_titulos_eleitor:
        text = f"titulo {titulo}"
        results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
        assert len(results) == 1, f"Expected 1 detection for {titulo!r}, got {len(results)}"
        assert results[0].entity_type == BR_TITULO_ELEITOR


def test_invalid_titulo_not_detected(
    analyzer: AnalyzerEngine, invalid_titulos_eleitor: list[str]
) -> None:
    for titulo in invalid_titulos_eleitor:
        results = analyzer.analyze(text=titulo, language="pt", entities=[BR_TITULO_ELEITOR])
        assert len(results) == 0, (
            f"Expected 0 detections for invalid título {titulo!r}, got {len(results)}"
        )


def test_span_covers_full_match(analyzer: AnalyzerEngine) -> None:
    text = "  123456780191  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "123456780191"


def test_unformatted_titulo_detected(analyzer: AnalyzerEngine) -> None:
    text = "123456780191"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 12


def test_formatted_4_4_4_titulo_detected(analyzer: AnalyzerEngine) -> None:
    text = "1234 5678 0191"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "1234 5678 0191"


def test_titulo_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "meu título de eleitor é 123456780191 do tse"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "123456780191"


def test_multiple_titulos_in_text(analyzer: AnalyzerEngine) -> None:
    text = "eleitor 123456780191 e outro 987654320523 no sistema"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_TITULO_ELEITOR])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"123456780191", "987654320523"}
