"""Tests for the RgRecognizer Presidio integration."""

from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_RG
from guardian_br.pii.recognizers.rg import RgRecognizer


def test_recognizer_entity_name_matches_constant() -> None:
    recognizer = RgRecognizer()
    assert BR_RG in recognizer.supported_entities


def test_valid_rg_detected(analyzer: AnalyzerEngine, valid_rgs_sp: list[str]) -> None:
    for rg in valid_rgs_sp:
        text = f"rg {rg}"
        results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
        assert len(results) == 1, f"Expected 1 detection for {rg!r}, got {len(results)}"
        assert results[0].entity_type == BR_RG


def test_invalid_rg_not_detected(analyzer: AnalyzerEngine, invalid_rgs_sp: list[str]) -> None:
    for rg in invalid_rgs_sp:
        results = analyzer.analyze(text=rg, language="pt", entities=[BR_RG])
        assert len(results) == 0, f"Expected 0 detections for invalid RG {rg!r}, got {len(results)}"


def test_span_covers_full_match(analyzer: AnalyzerEngine) -> None:
    text = "  123456789  "
    results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "123456789"


def test_unformatted_rg_detected(analyzer: AnalyzerEngine) -> None:
    text = "123456789"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
    assert len(results) == 1
    assert results[0].start == 0
    assert results[0].end == 9


def test_formatted_rg_with_dots_and_dash_detected(analyzer: AnalyzerEngine) -> None:
    text = "12.345.678-9"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
    assert len(results) == 1
    detected = text[results[0].start : results[0].end]
    assert detected == "12.345.678-9"


def test_rg_with_x_dv_detected(analyzer: AnalyzerEngine) -> None:
    for rg_text in ("50000000X", "50.000.000-X"):
        text = f"rg {rg_text}"
        results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
        assert len(results) == 1, f"Expected 1 detection for {rg_text!r}, got {len(results)}"
        detected = text[results[0].start : results[0].end]
        assert detected == rg_text


def test_rg_in_sentence_detected(analyzer: AnalyzerEngine) -> None:
    text = "meu RG é 123456789 da SSP"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
    assert len(results) == 1
    assert text[results[0].start : results[0].end] == "123456789"


def test_multiple_rgs_in_text(analyzer: AnalyzerEngine) -> None:
    text = "identidade 123456789 e outro rg 987654322 no sistema"
    results = analyzer.analyze(text=text, language="pt", entities=[BR_RG])
    assert len(results) == 2
    spans = {text[r.start : r.end] for r in results}
    assert spans == {"123456789", "987654322"}
