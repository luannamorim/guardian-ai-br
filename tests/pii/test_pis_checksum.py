"""Unit tests for the PIS/PASEP/NIS mod-11 checksum validator.

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched PIS candidates that are
not genuine PIS numbers (CLAUDE.md §Conventions, SPEC FR #2).
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_pis


@pytest.mark.parametrize(
    "pis",
    [
        "123.45678.90-0",
        "987.65432.10-3",
        "111.11111.10-8",
        "234.56789.01-3",
        "345.67890.12-5",
        "456.78901.23-6",
        "56789012346",  # unformatted, no separators
        "678.90123.45-5",
    ],
)
def test_valid_pis_passes(pis: str) -> None:
    assert validate_pis(pis) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic PIS numbers must pass validation.

    00000000000 (all zeros) satisfies the mod-11 algorithm by construction.
    Guardian-BR reports it as PII — masking is content-blind by design.
    Note: 00000000000 also satisfies the CPF checksum; when both recognizers
    fire both detections are emitted (emit-both policy).
    Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.
    """
    assert validate_pis("00000000000") is True
    assert validate_pis("000.00000.00-0") is True


@pytest.mark.parametrize(
    "pis",
    [
        "123.45678.90-1",  # last digit wrong by 1
        "123.45678.90-9",  # last digit wrong
        "987.65432.10-4",  # wrong check digit
        "000.00000.00-1",  # breaks all-zero synthetic checksum
        "111.11111.10-9",  # wrong check digit
        "456.78901.23-7",  # wrong checksum
        "345.67890.12-6",  # wrong checksum
    ],
)
def test_invalid_pis_rejected(pis: str) -> None:
    assert validate_pis(pis) is False


@pytest.mark.parametrize(
    "bad_input",
    [
        "1234567890",  # 10 digits — too short
        "123456789000",  # 12 digits — too long
        "",  # empty
        "abc.defgh.ij-k",  # non-digits
        "123.45678",  # missing check digit
    ],
)
def test_wrong_length_or_non_digit_rejected(bad_input: str) -> None:
    assert validate_pis(bad_input) is False


def test_strips_separators_before_checking() -> None:
    formatted = "123.45678.90-0"
    unformatted = "12345678900"
    assert validate_pis(formatted) == validate_pis(unformatted)
