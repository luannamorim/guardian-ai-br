"""Tests for the CnhRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_CNH
from guardian_br.pii.recognizers.cnh import CnhRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = CnhRecognizer()
    assert BR_CNH in recognizer.supported_entities


def test_valid_cnh_detected(analyzer: AnalyzerEngine, valid_cnhs: list[str]) -> None:
    for cnh in valid_cnhs:
        text = f"cnh {cnh}"
        results = analyzer.analyze(text=text, language="pt", entities=[BR_CNH])
        assert len(results) == 1, f"Expected 1 detection for {cnh!r}, got {len(results)}"
        assert results[0].entity_type == BR_CNH


def test_invalid_cnh_not_detected(analyzer: AnalyzerEngine, invalid_cnhs: list[str]) -> None:
    for cnh in invalid_cnhs:
        results = analyzer.analyze(text=cnh, language="pt", entities=[BR_CNH])
        assert len(results) == 0, (
            f"Expected 0 detections for invalid CNH {cnh!r}, got {len(results)}"
        )


def test_span_covers_digits_only(analyzer: AnalyzerEngine) -> None:
    text = "  98765432109  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNH])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "98765432109"


def test_unformatted_cnh_detected(analyzer: AnalyzerEngine) -> None:
    text = "98765432109"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNH])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 11


def test_cnh_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "minha cnh é 98765432109 do detran"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNH])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "98765432109"


def test_multiple_cnhs_in_text(analyzer: AnalyzerEngine) -> None:
    text = "motorista 98765432109 e outro 23456789029 no sistema"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNH])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"98765432109", "23456789029"}
