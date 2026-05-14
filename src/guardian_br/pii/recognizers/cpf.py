from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_CPF
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_cpf
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_CPF_COMPILED = compile_pattern(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)")


class CpfRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian CPF (Cadastro de Pessoas Físicas).

    Uses a single regex pattern (base score 0.4) gated by mod-11 checksum
    validation. Regex-only matches that fail the checksum are silenced
    (score → EntityRecognizer.MIN_SCORE = 0).

    See SPEC Failure Mode #2: mathematically valid synthetic CPFs such as
    111.111.111-11 are intentionally reported as PII — masking is content-blind.
    """

    SUPPORTED_ENTITY = BR_CPF
    PATTERNS = [Pattern("CPF_PATTERN", _CPF_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["cpf", "documento", "cadastro"]
    COMPILED_PATTERN = _CPF_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_cpf(pattern_text)
