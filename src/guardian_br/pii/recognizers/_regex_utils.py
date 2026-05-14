import regex

# Backtrack timeout applied at match time (e.g. finditer(text, timeout=TIMEOUT)).
# regex.compile() does not accept a timeout — it's a runtime argument.
REGEX_TIMEOUT: float = 0.1  # seconds; single tuning point for ReDoS budget


def compile_pattern(pattern: str) -> regex.Pattern[str]:
    """Compile a pattern using the `regex` library (never stdlib `re`).

    The `regex` library supports backtrack timeouts at match time via the
    `timeout=REGEX_TIMEOUT` argument to .finditer()/.search()/.match().
    All recognizers MUST go through this function; direct regex.compile
    calls elsewhere are a security-reviewer Blocker.
    """
    return regex.compile(pattern)
