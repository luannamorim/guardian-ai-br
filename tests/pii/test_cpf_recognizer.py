"""Tests for the CpfRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_CPF
from guardian_br.pii.recognizers.cpf import CpfRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = CpfRecognizer()
    assert BR_CPF in recognizer.supported_entities


def test_valid_cpf_detected(analyzer: AnalyzerEngine, valid_cpfs: list[str]) -> None:
    for cpf in valid_cpfs:
        results = analyzer.analyze(text=cpf, language="pt", entities=[BR_CPF])
        assert len(results) == 1, f"Expected 1 detection for {cpf!r}, got {len(results)}"
        assert results[0].entity_type == BR_CPF


def test_invalid_cpf_not_detected(analyzer: AnalyzerEngine, invalid_cpfs: list[str]) -> None:
    for cpf in invalid_cpfs:
        results = analyzer.analyze(text=cpf, language="pt", entities=[BR_CPF])
        assert len(results) == 0, (
            f"Expected 0 detections for invalid CPF {cpf!r}, got {len(results)}"
        )


def test_span_covers_digits_only(analyzer: AnalyzerEngine) -> None:
    text = "  123.456.789-09  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CPF])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "123.456.789-09"


def test_unformatted_cpf_detected(analyzer: AnalyzerEngine) -> None:
    text = "56789012303"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CPF])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 11


def test_cpf_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "oi meu cpf eh 123.456.789-09 ajuda"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CPF])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "123.456.789-09"


def test_multiple_cpfs_in_text(analyzer: AnalyzerEngine) -> None:
    text = "primeiro 123.456.789-09 e segundo 987.654.321-00 no mesmo texto"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_CPF])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"123.456.789-09", "987.654.321-00"}
