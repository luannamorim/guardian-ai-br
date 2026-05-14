"""Unit tests for the CPF mod-11 checksum validator.

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched CPF candidates that are
not genuine CPF numbers (CLAUDE.md §Conventions, SPEC FR #2).
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_cpf


@pytest.mark.parametrize(
    "cpf",
    [
        "123.456.789-09",
        "987.654.321-00",
        "345.678.901-75",
        "678.901.234-69",
        "789.012.345-05",
        "456.789.012-49",
        "56789012303",  # unformatted, no separators
        "234.567.890-92",
        "567.890.123-03",
    ],
)
def test_valid_cpf_passes(cpf: str) -> None:
    assert validate_cpf(cpf) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic CPFs must pass validation.

    Sequences like 111.111.111-11 and 000.000.000-00 satisfy the mod-11
    algorithm by construction. Guardian-BR reports them as PII — masking is
    content-blind by design. Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.
    """
    assert validate_cpf("111.111.111-11") is True
    assert validate_cpf("11111111111") is True
    assert validate_cpf("000.000.000-00") is True
    assert validate_cpf("00000000000") is True


@pytest.mark.parametrize(
    "cpf",
    [
        "123.456.789-00",  # last digit wrong
        "987.654.321-01",  # last digit wrong
        "000.000.000-01",
        "111.111.111-12",
        "999.999.999-00",
        "123.456.789-99",
        "000.000.000-10",
    ],
)
def test_invalid_cpf_rejected(cpf: str) -> None:
    assert validate_cpf(cpf) is False


@pytest.mark.parametrize(
    "bad_input",
    [
        "12345678",  # too short
        "123456789012",  # too long
        "",  # empty
        "abc.def.ghi-jk",  # non-digits
        "123.456.789",  # missing check digits
    ],
)
def test_wrong_length_or_non_digit_rejected(bad_input: str) -> None:
    assert validate_cpf(bad_input) is False


def test_strips_separators_before_checking() -> None:
    formatted = "123.456.789-09"
    unformatted = "12345678909"
    assert validate_cpf(formatted) == validate_cpf(unformatted)
