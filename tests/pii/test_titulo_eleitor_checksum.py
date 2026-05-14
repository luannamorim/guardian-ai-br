"""Unit tests for the título de eleitor TSE checksum validator.

All tests here are pure — no Presidio, no I/O. The checksum function is
the single gatekeeper that silences regex-matched candidates that are not
genuine voter IDs (CLAUDE.md §Conventions, SPEC FR #2).

Key algorithm properties under test:
- State-code gate: digits 9-10 must be in 01-28; values outside this range
  are rejected before any checksum arithmetic runs.
- SP/MG clamp: for states 01 (SP) and 02 (MG), a computed DV of 0 is
  forced to 1. This is the most common source of maintainer confusion —
  test_sp_mg_clamp_pins is the contract pin for this rule.
- dv1 == 10 branch: when sum mod 11 == 10, dv1 clamps to 0 (ordinary mod-11
  behavior, distinct from the SP/MG clamp).
"""

import pytest

from guardian_br.pii.recognizers._checksums import validate_titulo_eleitor


@pytest.mark.parametrize(
    "titulo",
    [
        "123456780191",  # state=01 SP, clean
        "111111110116",  # state=01 SP, SP/MG clamp applied (raw dv1=0 → 1)
        "123456780299",  # state=02 MG, clean
        "000000230302",  # state=03 RJ, dv1=10 → 0
        "123456780493",  # state=04 RS, clean
        "987654320523",  # state=05 BA, clean
        "556677881090",  # state=10 GO, dv2=0 (non-clamp state, dv2=0 is valid)
    ],
)
def test_valid_titulo_passes(titulo: str) -> None:
    assert validate_titulo_eleitor(titulo) is True


def test_documented_synthetic_quirk_is_still_flagged() -> None:
    """Mathematically valid synthetic títulos must pass validation.

    Near-zero and all-same bases that happen to satisfy the TSE mod-11
    algorithm are reported as PII — masking is content-blind by design.
    Do NOT add a rejection rule for these sequences.
    See SPEC §Failure Modes #2 and CLAUDE.md §Gotchas.
    """
    assert validate_titulo_eleitor("000000010191") is True  # near-zero base, SP state
    assert validate_titulo_eleitor("111111110116") is True  # all-ones base, SP clamp


@pytest.mark.parametrize(
    "titulo",
    [
        "123456780192",  # SP wrong DV2 (last digit +1)
        "111111110117",  # SP clamp wrong DV2
        "123456780290",  # MG wrong DV2
        "000000230303",  # RJ wrong DV2
    ],
)
def test_invalid_titulo_rejected(titulo: str) -> None:
    assert validate_titulo_eleitor(titulo) is False


@pytest.mark.parametrize(
    "titulo",
    [
        "123456789901",  # state=99 — above valid range
        "123456780001",  # state=00 — below valid range
        "123456782901",  # state=29 — one above the valid maximum (28)
    ],
)
def test_invalid_state_code_rejected(titulo: str) -> None:
    assert validate_titulo_eleitor(titulo) is False


@pytest.mark.parametrize(
    "valid, invalid",
    [
        ("111111110116", "111111110106"),  # SP: clamped DV1=1 vs un-clamped DV1=0
        ("111111110213", "111111110203"),  # MG: clamped DV1=1 vs un-clamped DV1=0
    ],
)
def test_sp_mg_clamp_pins(valid: str, invalid: str) -> None:
    """SP (01) and MG (02) must never have DV equal to 0; clamp forces 1.

    This is the regression pin for the SP/MG zero-clamp rule. A validator
    that drops the clamp branch would incorrectly reject valid SP/MG títulos
    AND accept known-invalid ones — both assertions would fail.
    """
    assert validate_titulo_eleitor(valid) is True
    assert validate_titulo_eleitor(invalid) is False


@pytest.mark.parametrize(
    "bad_input",
    [
        "1234567801",  # 10 digits — too short
        "1234567801919",  # 13 digits — too long
        "",  # empty
        "abcdefghijkl",  # non-digits
        "12345678",  # only base digits, no state/DV
    ],
)
def test_wrong_length_or_non_digit_rejected(bad_input: str) -> None:
    assert validate_titulo_eleitor(bad_input) is False


def test_strips_separators_before_checking() -> None:
    bare = "123456780191"
    with_spaces = "1234 5678 0191"
    with_dots = "1234.5678.0191"
    assert validate_titulo_eleitor(bare) is True
    assert validate_titulo_eleitor(with_spaces) == validate_titulo_eleitor(bare)
    assert validate_titulo_eleitor(with_dots) == validate_titulo_eleitor(bare)
