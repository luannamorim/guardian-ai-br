"""Unit tests for the SP RG SSP/SP mod-11 checksum validator.

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched candidates that are not
genuine SP-issued RGs (CLAUDE.md §Conventions, SPEC FR #2).

Key algorithm properties under test:
- 8 base digits × weights [2..9] left-to-right, sum mod 11.
- DV is the digit 0-9, except remainder 10 becomes the letter 'X'.
- Dots and dashes in formatted input are stripped before validation.
- Lowercase 'x' is accepted as DV and normalized to uppercase internally.
- v1 scope is SP only — other states have no public checksum.
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_rg_sp


@pytest.mark.parametrize(
    "rg",
    [
        "000000000",  # DV=0 (sum=0, 0%11=0)
        "123456789",  # DV=9 (sum=240, 240%11=9)
        "987654322",  # DV=2 (sum=200, 200%11=2)
        "600000001",  # DV=1 (sum=12, 12%11=1)
        "50000000X",  # DV=X (sum=10, 10%11=10 → 'X')
        "010000003",  # DV=3 (sum=3, 3%11=3)
        "001000004",  # DV=4 (sum=4, 4%11=4)
    ],
)
def test_valid_rg_passes(rg: str) -> None:
    assert validate_rg_sp(rg) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic RGs must pass validation.

    All-zero and all-same bases that happen to satisfy the SP mod-11
    algorithm are reported as PII — masking is content-blind by design.
    Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.
    """
    assert validate_rg_sp("111111110") is True  # sum=44, 44%11=0, DV=0


@pytest.mark.parametrize(
    "rg",
    [
        "000000001",  # DV should be '0', not '1'
        "123456788",  # DV should be '9', not '8'
        "987654321",  # DV should be '2', not '1'
        "600000002",  # DV should be '1', not '2'
    ],
)
def test_invalid_rg_rejected(rg: str) -> None:
    assert validate_rg_sp(rg) is False


@pytest.mark.parametrize(
    "valid, invalid",
    [
        ("50000000X", "500000009"),  # sum=10 → DV='X'; wrong if '9'
        ("20001000X", "200010009"),  # sum=2*2+1*6=10 → DV='X'; wrong if '9'
    ],
)
def test_x_branch_pins(valid: str, invalid: str) -> None:
    """DV == 10 must map to the character 'X', not '10' or any digit.

    This is the contract pin for the 'X' if dv_num == 10 else str(dv_num)
    branch. A validator that drops this branch would accept '500000009'
    (a wrong DV) and reject '50000000X' (the correct DV).
    """
    assert validate_rg_sp(valid) is True
    assert validate_rg_sp(invalid) is False


def test_lowercase_x_accepted() -> None:
    """Lowercase 'x' as DV must be accepted (normalized to 'X' internally)."""
    assert validate_rg_sp("50000000x") is True


@pytest.mark.parametrize(
    "bad_input",
    [
        "12345678",  # 8 chars — too short
        "1234567890",  # 10 digits — too long
        "",  # empty
        "12345678Y",  # invalid DV char
        "X23456789",  # X in non-DV position
        "abcdefghi",  # non-digits
    ],
)
def test_wrong_length_or_bad_chars_rejected(bad_input: str) -> None:
    assert validate_rg_sp(bad_input) is False


def test_strips_separators_before_checking() -> None:
    bare = "123456789"
    with_dots_and_dash = "12.345.678-9"
    with_dash_only = "12345678-9"
    with_dots_only = "12.345.6789"
    assert validate_rg_sp(bare) is True
    assert validate_rg_sp(with_dots_and_dash) == validate_rg_sp(bare)
    assert validate_rg_sp(with_dash_only) == validate_rg_sp(bare)
    assert validate_rg_sp(with_dots_only) == validate_rg_sp(bare)
