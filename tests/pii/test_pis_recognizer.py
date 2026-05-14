"""Tests for the PisRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_PIS
from guardian_br.pii.recognizers.pis import PisRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = PisRecognizer()
    assert BR_PIS in recognizer.supported_entities


def test_valid_pis_detected(analyzer: AnalyzerEngine, valid_pis: list[str]) -> None:
    for pis in valid_pis:
        results = analyzer.analyze(text=pis, language="pt", entities=[BR_PIS])
        assert len(results) == 1, f"Expected 1 detection for {pis!r}, got {len(results)}"
        assert results[0].entity_type == BR_PIS


def test_invalid_pis_not_detected(analyzer: AnalyzerEngine, invalid_pis: list[str]) -> None:
    for pis in invalid_pis:
        results = analyzer.analyze(text=pis, language="pt", entities=[BR_PIS])
        assert len(results) == 0, (
            f"Expected 0 detections for invalid PIS {pis!r}, got {len(results)}"
        )


def test_span_covers_digits_only(analyzer: AnalyzerEngine) -> None:
    text = "  123.45678.90-0  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_PIS])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "123.45678.90-0"


def test_unformatted_pis_detected(analyzer: AnalyzerEngine) -> None:
    text = "56789012346"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_PIS])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 11


def test_pis_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "meu pis é 123.45678.90-0 no cadastro"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_PIS])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "123.45678.90-0"


def test_multiple_pis_in_text(analyzer: AnalyzerEngine) -> None:
    text = "titular 123.45678.90-0 e dependente 987.65432.10-3 no sistema"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_PIS])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"123.45678.90-0", "987.65432.10-3"}
