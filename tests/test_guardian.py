"""Integration tests for Guardian.scan()."""

import pytest
from pydantic import ValidationError

from guardian_br import Guardian, ScanResult
from guardian_br.core.entities import BR_CNPJ, BR_CPF


def test_scan_returns_scan_result() -> None:
    result = Guardian().scan("nenhum dado sensível aqui")
    assert isinstance(result, ScanResult)
    assert result.detections == []
    assert result.redacted_text == "nenhum dado sensível aqui"


def test_scan_detects_cpf() -> None:
    result = Guardian().scan("meu cpf eh 123.456.789-09")
    assert len(result.detections) == 1
    det = result.detections[0]
    assert det.entity_type == BR_CPF
    assert det.lgpd_article is not None


def test_scan_redacted_text_single_cpf() -> None:
    text = "meu cpf eh 123.456.789-09"
    result = Guardian().scan(text)
    assert result.redacted_text == "meu cpf eh <BR_CPF>"


def test_scan_redacted_text_two_cpfs() -> None:
    text = "primeiro 123.456.789-09 e segundo 987.654.321-00 no mesmo texto"
    result = Guardian().scan(text)
    assert result.redacted_text == "primeiro <BR_CPF> e segundo <BR_CPF> no mesmo texto"


def test_scan_redacted_text_invalid_cpf_untouched() -> None:
    text = "cpf inválido 123.456.789-00 não deve ser mascarado"
    result = Guardian().scan(text)
    assert result.redacted_text == text
    assert result.detections == []


def test_scan_result_is_frozen() -> None:
    result = Guardian().scan("123.456.789-09")
    with pytest.raises(ValidationError):
        result.text = "mutated"  # type: ignore[misc]


def test_scan_preserves_original_text() -> None:
    text = "meu cpf eh 123.456.789-09"
    result = Guardian().scan(text)
    assert result.text == text


def test_lgpd_article_populated() -> None:
    result = Guardian().scan("123.456.789-09")
    assert len(result.detections) == 1
    assert result.detections[0].lgpd_article == "Art. 5º, I"


def test_scan_detects_cpf_and_cnpj_together() -> None:
    text = "CPF 123.456.789-09 e CNPJ 11.222.333/0001-81"
    result = Guardian().scan(text)
    assert len(result.detections) == 2
    types = {d.entity_type for d in result.detections}
    assert types == {BR_CPF, BR_CNPJ}
    assert result.redacted_text == "CPF <BR_CPF> e CNPJ <BR_CNPJ>"
