"""Unit tests for the CNH mod-11 checksum validator (DENATRAN descontador rule).

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched CNH candidates that are
not genuine CNH numbers (CLAUDE.md §Conventions, SPEC FR #2).
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_cnh


@pytest.mark.parametrize(
    "cnh",
    [
        "98765432109",  # dsc=2 branch (DV1 saturates >= 10)
        "23456789029",  # dsc=0 branch
        "34567890157",  # dsc=0 branch
        "45678901294",
        "56789012330",
        "67890123496",
        "78901234550",
        "13579246882",
    ],
)
def test_valid_cnh_passes(cnh: str) -> None:
    assert validate_cnh(cnh) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic CNH numbers must pass validation.

    11111111111 and 55555555555 satisfy the DENATRAN mod-11 algorithm by
    construction. Guardian-BR reports them as PII — masking is content-blind
    by design. Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.

    Note: 00000000000 also satisfies the CPF and PIS checksums — all three
    recognizers fire (triple-collision / emit-all policy).
    """
    assert validate_cnh("11111111111") is True
    assert validate_cnh("55555555555") is True
    assert validate_cnh("00000000000") is True


@pytest.mark.parametrize(
    "cnh",
    [
        "98765432108",  # last digit wrong by -1
        "23456789020",  # last digit wrong
        "98765432100",  # wrong DV2
        "45678901295",  # wrong last digit
        "00000000001",  # breaks all-zero synthetic checksum
    ],
)
def test_invalid_cnh_rejected(cnh: str) -> None:
    assert validate_cnh(cnh) is False


@pytest.mark.parametrize(
    "bad_input",
    [
        "1234567890",  # 10 digits — too short
        "123456789000",  # 12 digits — too long
        "",  # empty
        "abcdefghijk",  # non-digits
        "12345678",  # missing check digits
    ],
)
def test_wrong_length_or_non_digit_rejected(bad_input: str) -> None:
    assert validate_cnh(bad_input) is False


def test_strips_separators_before_checking() -> None:
    bare = "98765432109"
    with_separators = "987.654.321-09"
    assert validate_cnh(bare) == validate_cnh(with_separators)
