from __future__ import annotations

import regex
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.entity_recognizer import EntityRecognizer

from guardian_br.core.entities import BR_CPF
from guardian_br.pii.recognizers._checksums import validate_cpf
from guardian_br.pii.recognizers._regex_utils import REGEX_TIMEOUT, compile_pattern

_CPF_COMPILED = compile_pattern(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")


class CpfRecognizer(PatternRecognizer):
    """Presidio recognizer for Brazilian CPF (Cadastro de Pessoas Físicas).

    Uses a single regex pattern (base score 0.4) gated by mod-11 checksum
    validation. Regex-only matches that fail the checksum are silenced
    (score → EntityRecognizer.MIN_SCORE = 0).

    See SPEC Failure Mode #2: mathematically valid synthetic CPFs such as
    111.111.111-11 are intentionally reported as PII — masking is content-blind.

    The regex is compiled via `_regex_utils.compile_pattern` (never stdlib `re`)
    and backtrack timeout is applied at match time in `_analyze_patterns_in_text`.
    """

    PATTERNS = [Pattern("CPF_PATTERN", _CPF_COMPILED.pattern, 0.4)]
    CONTEXT = ["cpf", "documento", "cadastro"]

    def __init__(self, supported_language: str = "pt") -> None:
        super().__init__(
            supported_entity=BR_CPF,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
        )
        for p in self.patterns:  # type: ignore[has-type]  # inject regex-lib version for timeout support
            p.compiled_pattern = _CPF_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_cpf(pattern_text)

    def _analyze_patterns_in_text(
        self, text: str, flags: int | None = None
    ) -> list[RecognizerResult]:
        """Override Presidio's default to apply backtrack timeout at match time."""
        results: list[RecognizerResult] = []
        for pattern in self.patterns:  # type: ignore[has-type]
            try:
                matches = (
                    pattern.compiled_pattern.finditer(text, flags, timeout=REGEX_TIMEOUT)
                    if flags
                    else pattern.compiled_pattern.finditer(text, timeout=REGEX_TIMEOUT)
                )
            except regex.error:
                # Backtrack timeout or malformed pattern — skip silently.
                continue

            for match in matches:
                start, end = match.span()
                current_match = text[start:end]
                if not current_match:
                    continue

                score = pattern.score
                validation_result = self.validate_result(current_match)

                score = max(score, 0.4) if validation_result else EntityRecognizer.MIN_SCORE

                results.append(
                    RecognizerResult(
                        entity_type=self.supported_entities[0],
                        start=start,
                        end=end,
                        score=score,
                    )
                )
        return results
