"""Tests for the CnpjRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_CNPJ
from guardian_br.pii.recognizers.cnpj import CnpjRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = CnpjRecognizer()
    assert BR_CNPJ in recognizer.supported_entities


def test_valid_cnpj_detected(analyzer: AnalyzerEngine, valid_cnpjs: list[str]) -> None:
    for cnpj in valid_cnpjs:
        results = analyzer.analyze(text=cnpj, language="pt", entities=[BR_CNPJ])
        assert len(results) == 1, f"Expected 1 detection for {cnpj!r}, got {len(results)}"
        assert results[0].entity_type == BR_CNPJ


def test_invalid_cnpj_not_detected(analyzer: AnalyzerEngine, invalid_cnpjs: list[str]) -> None:
    for cnpj in invalid_cnpjs:
        results = analyzer.analyze(text=cnpj, language="pt", entities=[BR_CNPJ])
        assert len(results) == 0, (
            f"Expected 0 detections for invalid CNPJ {cnpj!r}, got {len(results)}"
        )


def test_span_covers_digits_only(analyzer: AnalyzerEngine) -> None:
    text = "  12.345.678/0001-95  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNPJ])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "12.345.678/0001-95"


def test_unformatted_cnpj_detected(analyzer: AnalyzerEngine) -> None:
    text = "12345678000195"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNPJ])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 14


def test_cnpj_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "nosso cnpj é 45.678.901/0001-75 para nota fiscal"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNPJ])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "45.678.901/0001-75"


def test_multiple_cnpjs_in_text(analyzer: AnalyzerEngine) -> None:
    text = "matriz 12.345.678/0001-95 e filial 11.222.333/0001-81 no cadastro"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CNPJ])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"12.345.678/0001-95", "11.222.333/0001-81"}
