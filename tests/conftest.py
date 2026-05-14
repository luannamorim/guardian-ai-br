import json
from pathlib import Path

import pytest
from presidio_analyzer import AnalyzerEngine

from guardian_br.pii.registry import build_analyzer_engine


@pytest.fixture(scope="session")
def analyzer() -> AnalyzerEngine:
    return build_analyzer_engine()


@pytest.fixture
def valid_cpfs() -> list[str]:
    return [
        "123.456.789-09",
        "987.654.321-00",
        "345.678.901-75",
        "678.901.234-69",
        "789.012.345-05",
        "456.789.012-49",
        "56789012303",  # unformatted
        "234.567.890-92",
        # Mathematically valid synthetic sequences — must be detected as PII
        # (SPEC Failure Mode #2: masking is content-blind by design).
        "111.111.111-11",
        "000.000.000-00",
    ]


@pytest.fixture
def invalid_cpfs() -> list[str]:
    return [
        "123.456.789-00",  # last digit off by 9
        "987.654.321-01",  # last digit off by 1
        "000.000.000-01",  # non-zero digit on otherwise all-zero sequence
        "111.111.111-12",  # wrong check digit
        "12345678",  # too short
        "123456789012",  # too long (12 digits)
        "abc.def.ghi-jk",  # non-digits
        "999.999.999-00",  # wrong checksum
        "000.000.000-10",  # wrong checksum
        "123.456.789-99",  # wrong checksum
    ]


@pytest.fixture
def valid_cnpjs() -> list[str]:
    return [
        "12.345.678/0001-95",
        "11.222.333/0001-81",
        "45.678.901/0001-75",
        "98.765.432/0001-98",
        "67.890.123/0001-16",
        "34.567.890/0001-30",
        "56.789.012/0001-00",
        "12345678000195",  # unformatted
        # Mathematically valid synthetic sequences — must be detected as PII
        # (SPEC Failure Mode #2: masking is content-blind by design).
        "00.000.000/0000-00",
        "11.111.111/1111-80",
    ]


@pytest.fixture
def invalid_cnpjs() -> list[str]:
    return [
        "12.345.678/0001-96",  # last digit off by 1
        "12.345.678/0001-94",  # last digit off by -1
        "11.222.333/0001-82",  # wrong check digit
        "00.000.000/0000-01",  # non-zero digit breaks synthetic all-zero checksum
        "11.111.111/1111-81",  # wrong last digit
        "98.765.432/0001-99",  # wrong checksum
        "1234567800019",  # 13 digits — too short
        "123456780001958",  # 15 digits — too long
        "ab.cde.fgh/0001-95",  # non-digit prefix
        "45.678.901/0001-76",  # wrong checksum
    ]


@pytest.fixture
def valid_pis() -> list[str]:
    return [
        "123.45678.90-0",
        "987.65432.10-3",
        "111.11111.10-8",  # all-ones base with computed check digit
        "234.56789.01-3",
        "345.67890.12-5",
        "456.78901.23-6",
        "56789012346",  # unformatted
        "678.90123.45-5",
        "789.01234.56-3",
        "890.12345.67-0",
    ]


@pytest.fixture
def invalid_pis() -> list[str]:
    return [
        "123.45678.90-1",  # last digit off by 1
        "123.45678.90-9",  # last digit wrong
        "987.65432.10-4",  # wrong check digit
        "000.00000.00-1",  # non-zero digit breaks synthetic all-zero checksum
        "111.11111.10-9",  # wrong check digit
        "456.78901.23-7",  # wrong checksum
        "1234567890",  # 10 digits — too short
        "123456789000",  # 12 digits — too long
        "abc.defgh.ij-k",  # non-digit prefix
        "345.67890.12-6",  # wrong checksum
    ]


@pytest.fixture
def valid_cnhs() -> list[str]:
    return [
        "98765432109",  # dsc=2 branch (DV1 saturates)
        "23456789029",  # dsc=0 branch
        "34567890157",  # dsc=0 branch
        "45678901294",
        "56789012330",
        "67890123496",
        "78901234550",
        "13579246882",
        # Mathematically valid synthetic sequences — must be detected as PII
        # (SPEC Failure Mode #2: masking is content-blind by design).
        "11111111111",
        "55555555555",
    ]


@pytest.fixture
def invalid_cnhs() -> list[str]:
    return [
        "98765432108",  # last digit off by -1
        "23456789020",  # last digit wrong
        "98765432100",  # wrong DV2
        "45678901295",  # wrong last digit
        "00000000001",  # breaks all-zero synthetic checksum
        "1234567890",  # 10 digits — too short
        "123456789000",  # 12 digits — too long
        "abcdefghijk",  # non-digits
        "98765432107",  # wrong checksum
        "34567890158",  # wrong checksum
    ]


@pytest.fixture
def valid_titulos_eleitor() -> list[str]:
    return [
        "123456780191",  # state=01 SP, clean (dv1=9, dv2=1)
        "111111110116",  # state=01 SP, SP/MG clamp applied (raw dv1=0 → 1)
        "123456780299",  # state=02 MG, clean (dv1=9, dv2=9)
        "111111110213",  # state=02 MG, SP/MG clamp applied (raw dv1=0 → 1)
        "000000230302",  # state=03 RJ, dv1=10 → 0
        "123456780493",  # state=04 RS, clean
        "987654320523",  # state=05 BA, clean
        "112233440795",  # state=07 CE, clean
        "556677881090",  # state=10 GO, clean (dv2=0, non-clamp state)
        "123456002020",  # state=20 DF, clean
    ]


@pytest.fixture
def invalid_titulos_eleitor() -> list[str]:
    return [
        "123456780192",  # SP wrong DV2 (last digit +1)
        "111111110117",  # SP clamp wrong DV2
        "123456780290",  # MG wrong DV2
        "000000230303",  # RJ wrong DV2
        "111111110106",  # SP, DV1=0 (not clamped to 1) — SP/MG clamp regression pin
        "111111110203",  # MG, DV1=0 (not clamped to 1) — SP/MG clamp regression pin
        "123456789901",  # invalid state code 99
        "123456780001",  # invalid state code 00
        "1234567801",  # 10 digits — too short
        "abcdefghijkl",  # non-digits
    ]


@pytest.fixture
def tmp_corpus(tmp_path: Path) -> Path:
    rows = [
        {
            "text": "123.456.789-09",
            "labels": [{"type": "BR_CPF", "start": 0, "end": 14}],
            "category": "cpf",
        },
        {
            "text": "987.654.321-00",
            "labels": [{"type": "BR_CPF", "start": 0, "end": 14}],
            "category": "cpf",
        },
        {
            "text": "123.456.789-00",
            "labels": [],
            "category": "cpf",
        },
    ]
    corpus_file = tmp_path / "corpus.jsonl"
    corpus_file.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return corpus_file
