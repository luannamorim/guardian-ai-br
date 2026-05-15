"""Parse Llama Guard 3 output from Ollama.

No I/O, no logging, no print — pure function, safe in hot paths.
Uses `regex` library (not stdlib `re`) per CLAUDE.md — supports timeout= for
ReDoS protection.
"""

from __future__ import annotations

import regex

from guardian_br.adversarial.errors import AdversarialParseError

_UNSAFE_RE = regex.compile(
    r"^unsafe\s*[\r\n]+\s*(?P<cats>S\d{1,2}(?:\s*,\s*S\d{1,2})*)\s*$",
    flags=regex.IGNORECASE,
)

_TIMEOUT_S = 0.05


def parse_llama_guard(content: str) -> tuple[str, list[str]]:
    """Parse Llama Guard 3 output into (primary_label, categories).

    Returns:
        ("safe", []) for safe responses.
        ("S1", ["S1", "S5"]) for unsafe responses with categories.

    Raises:
        AdversarialParseError: if the output format is unrecognized.
    """
    stripped = content.strip()
    if stripped.lower() == "safe":
        return "safe", []
    m = _UNSAFE_RE.match(stripped, timeout=_TIMEOUT_S)
    if not m:
        raise AdversarialParseError(
            f"unparseable Llama Guard output: len={len(stripped)} prefix={stripped[:16]!r}"
        )
    cats = [c.strip().upper() for c in m.group("cats").split(",")]
    primary = cats[0] if cats else "S0"
    return primary, cats
