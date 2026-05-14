from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_PIS
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_pis
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_PIS_COMPILED = compile_pattern(r"(?<!\d)\d{3}\.?\d{5}\.?\d{2}-?\d{1}(?!\d)")


class PisRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian PIS/PASEP/NIS.

    Uses a single regex pattern (base score 0.4) gated by mod-11 checksum
    validation with weights [3,2,9,8,7,6,5,4,3,2] over the first 10 digits.
    Regex-only matches that fail the checksum are silenced (score →
    EntityRecognizer.MIN_SCORE = 0).

    See SPEC Failure Mode #2: mathematically valid synthetic PIS numbers such
    as 000.00000.00-0 are intentionally reported as PII — masking is
    content-blind. Note: 00000000000 also satisfies the CPF checksum; when
    both recognizers fire on the same span, both detections are emitted
    (emit-both policy, never deduplicated).
    """

    SUPPORTED_ENTITY = BR_PIS
    PATTERNS = [Pattern("PIS_PATTERN", _PIS_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["pis", "pasep", "nis"]
    COMPILED_PATTERN = _PIS_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_pis(pattern_text)
