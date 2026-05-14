"""Unit tests for the CNPJ mod-11 checksum validator.

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched CNPJ candidates that are
not genuine CNPJ numbers (CLAUDE.md §Conventions, SPEC FR #2).
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_cnpj


@pytest.mark.parametrize(
    "cnpj",
    [
        "12.345.678/0001-95",
        "11.222.333/0001-81",
        "45.678.901/0001-75",
        "98.765.432/0001-98",
        "67.890.123/0001-16",
        "34.567.890/0001-30",
        "56.789.012/0001-00",
        "12345678000195",  # unformatted, no separators
    ],
)
def test_valid_cnpj_passes(cnpj: str) -> None:
    assert validate_cnpj(cnpj) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic CNPJs must pass validation.

    00.000.000/0000-00 (all zeros) and 11.111.111/1111-80 (all-ones base
    with computed check digits) satisfy the mod-11 algorithm by construction.
    Guardian-BR reports them as PII — masking is content-blind by design.
    Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.
    """
    assert validate_cnpj("00.000.000/0000-00") is True
    assert validate_cnpj("00000000000000") is True
    assert validate_cnpj("11.111.111/1111-80") is True
    assert validate_cnpj("11111111111180") is True


@pytest.mark.parametrize(
    "cnpj",
    [
        "12.345.678/0001-96",  # last digit wrong by 1
        "12.345.678/0001-94",  # last digit wrong by -1
        "11.222.333/0001-82",  # wrong check digit
        "00.000.000/0000-01",  # breaks all-zero synthetic checksum
        "11.111.111/1111-81",  # wrong last digit
        "98.765.432/0001-99",  # wrong checksum
        "45.678.901/0001-76",  # wrong checksum
    ],
)
def test_invalid_cnpj_rejected(cnpj: str) -> None:
    assert validate_cnpj(cnpj) is False


@pytest.mark.parametrize(
    "bad_input",
    [
        "1234567800019",  # 13 digits — too short
        "123456780001958",  # 15 digits — too long
        "",  # empty
        "ab.cde.fgh/0001-95",  # non-digits in prefix
        "12.345.678/0001",  # missing check digits
    ],
)
def test_wrong_length_or_non_digit_rejected(bad_input: str) -> None:
    assert validate_cnpj(bad_input) is False


def test_strips_separators_before_checking() -> None:
    formatted = "12.345.678/0001-95"
    unformatted = "12345678000195"
    assert validate_cnpj(formatted) == validate_cnpj(unformatted)
