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
    corpus_file.write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8"
    )
    return corpus_file
