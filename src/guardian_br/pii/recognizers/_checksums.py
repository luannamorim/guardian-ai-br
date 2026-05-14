_CNPJ_W1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_CNPJ_W2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_PIS_WEIGHTS = [3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_CNH_W1 = [9, 8, 7, 6, 5, 4, 3, 2, 1]
_CNH_W2 = [1, 2, 3, 4, 5, 6, 7, 8, 9]


def _digits_only(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def validate_cnpj(digits: str) -> bool:
    """Return True if *digits* is a mod-11 valid CNPJ.

    Strips any non-digit characters before checking. Returns False for inputs
    that, after stripping, are not exactly 14 digits.

    Mathematically valid synthetic sequences such as 00000000000000 or
    11111111111180 pass this check intentionally — masking is content-blind
    by design (SPEC Failure Mode #2). Do NOT add a rejection rule for them.
    """
    d = _digits_only(digits)
    if len(d) != 14:
        return False

    def _check(d: str, n: int, weights: list[int]) -> bool:
        total = sum(int(d[i]) * weights[i] for i in range(n))
        remainder = total % 11
        expected = 0 if remainder < 2 else 11 - remainder
        return int(d[n]) == expected

    return _check(d, 12, _CNPJ_W1) and _check(d, 13, _CNPJ_W2)


def validate_cpf(digits: str) -> bool:
    """Return True if *digits* is a mod-11 valid CPF.

    Strips any non-digit characters before checking. Returns False for inputs
    that, after stripping, are not exactly 11 digits.

    Mathematically valid synthetic sequences such as 00000000000 or
    11111111111 pass this check intentionally — masking is content-blind
    by design (SPEC Failure Mode #2). Do NOT add a rejection rule for them.
    """
    d = _digits_only(digits)
    if len(d) != 11:
        return False

    def _check(d: str, n: int) -> bool:
        weight = n + 1
        total = sum(int(d[i]) * (weight - i) for i in range(n))
        remainder = total % 11
        expected = 0 if remainder < 2 else 11 - remainder
        return int(d[n]) == expected

    return _check(d, 9) and _check(d, 10)


def validate_pis(digits: str) -> bool:
    """Return True if *digits* is a mod-11 valid PIS/PASEP/NIS.

    Strips any non-digit characters before checking. Returns False for inputs
    that, after stripping, are not exactly 11 digits.

    Mathematically valid synthetic sequences such as 00000000000 pass this
    check intentionally — masking is content-blind by design (SPEC Failure
    Mode #2). Do NOT add a rejection rule for them.

    Note: 00000000000 also satisfies the CPF checksum. When both fire, both
    detections are emitted — see CLAUDE.md §Conventions on emit-both policy.
    """
    d = _digits_only(digits)
    if len(d) != 11:
        return False

    def _check(d: str, n: int, weights: list[int]) -> bool:
        total = sum(int(d[i]) * weights[i] for i in range(n))
        remainder = total % 11
        expected = 0 if remainder < 2 else 11 - remainder
        return int(d[n]) == expected

    return _check(d, 10, _PIS_WEIGHTS)


def validate_cnh(digits: str) -> bool:
    """Return True if *digits* is a mod-11 valid CNH per the DENATRAN rule.

    CNH differs from CPF/CNPJ/PIS in one place: when the first check digit's
    (sum mod 11) >= 10, dv1 clamps to 0 AND a descontador `dsc = 2` is
    subtracted from the second check digit's modulus. This carry rule is
    why CNH has its own validator rather than reusing the _check helper
    used by CPF/PIS.

    Per SPEC Failure Mode #2: mathematically valid synthetic CNHs such as
    11111111111 are intentionally accepted — masking is content-blind. Do
    NOT add rejection rules for synthetic sequences here.
    """
    d = _digits_only(digits)
    if len(d) != 11:
        return False

    s1 = sum(int(d[i]) * _CNH_W1[i] for i in range(9))
    dv1 = s1 % 11
    dsc = 0
    if dv1 >= 10:
        dv1 = 0
        dsc = 2
    if int(d[9]) != dv1:
        return False

    s2 = sum(int(d[i]) * _CNH_W2[i] for i in range(9))
    dv2 = s2 % 11 - dsc
    if dv2 < 0:
        dv2 += 11
    if dv2 >= 10:
        dv2 = 0
    return int(d[10]) == dv2
