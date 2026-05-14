from __future__ import annotations

from typing import ClassVar

import regex
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.entity_recognizer import EntityRecognizer

from guardian_br.pii.recognizers._regex_utils import REGEX_TIMEOUT

# Presidio elevates this to ≥0.5 when context words match; we sit below that
# threshold so checksum-only matches require context confirmation to reach
# high confidence.
_BASE_SCORE: float = 0.4


class ChecksumValidatedRecognizer(PatternRecognizer):
    """Base class for BR identifier recognizers gated by mod-11 checksum.

    Subclasses MUST define the four ClassVars below and implement
    `validate_result`. The base class handles:

    - PatternRecognizer wiring (entity, patterns, context, language)
    - Injection of the regex-lib compiled pattern (Presidio stores stdlib
      `re` by default; we need `regex` for backtrack timeout support)
    - The `_analyze_patterns_in_text` override that applies REGEX_TIMEOUT
      at match time and silences regex-only matches that fail the checksum.

    Regex compilation goes through `_regex_utils.compile_pattern` (never
    stdlib `re`). See SPEC §Failure Modes #2 — synthetic-but-mathematically-
    valid identifiers are intentionally detected; subclass validators must
    NOT add rejection rules for them.
    """

    SUPPORTED_ENTITY: ClassVar[str]
    PATTERNS: ClassVar[list[Pattern]]
    CONTEXT: ClassVar[list[str]]
    COMPILED_PATTERN: ClassVar[regex.Pattern[str]]

    def __init__(self, supported_language: str = "pt") -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def _analyze_patterns_in_text(
        self, text: str, flags: int | None = None
    ) -> list[RecognizerResult]:
        results: list[RecognizerResult] = []
        for pattern in self.patterns:  # type: ignore[has-type]
            try:
                matches = (
                    self.COMPILED_PATTERN.finditer(text, flags, timeout=REGEX_TIMEOUT)
                    if flags
                    else self.COMPILED_PATTERN.finditer(text, timeout=REGEX_TIMEOUT)
                )
            except regex.error:
                # Backtrack timeout or malformed pattern — skip silently.
                continue

            for match in matches:
                start, end = match.span()
                current_match = text[start:end]
                if not current_match:
                    continue

                validation_result = self.validate_result(current_match)
                score = pattern.score if validation_result else EntityRecognizer.MIN_SCORE

                results.append(
                    RecognizerResult(
                        entity_type=self.supported_entities[0],
                        start=start,
                        end=end,
                        score=score,
                    )
                )
        return results
