def validate_cpf(digits: str) -> bool:
    """Return True if *digits* is a mod-11 valid CPF.

    Strips any non-digit characters before checking. Returns False for inputs
    that, after stripping, are not exactly 11 digits.

    Mathematically valid synthetic sequences such as 00000000000 or
    11111111111 pass this check intentionally — masking is content-blind
    by design (SPEC Failure Mode #2). Do NOT add a rejection rule for them.
    """
    d = "".join(c for c in digits if c.isdigit())
    if len(d) != 11:
        return False

    def _check(d: str, n: int) -> bool:
        weight = n + 1
        total = sum(int(d[i]) * (weight - i) for i in range(n))
        remainder = total % 11
        expected = 0 if remainder < 2 else 11 - remainder
        return int(d[n]) == expected

    return _check(d, 9) and _check(d, 10)
