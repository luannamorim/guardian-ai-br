from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_CNH
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_cnh
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_CNH_COMPILED = compile_pattern(r"(?<!\d)\d{11}(?!\d)")


class CnhRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian CNH (Carteira Nacional de Habilitação).

    11-digit unformatted register number, gated by mod-11 checksum with the
    DENATRAN descontador rule (when DV1 saturates >= 10, dv1 → 0 and dsc=2
    is subtracted from DV2's modulus). Regex-only matches that fail the
    checksum are silenced (score → EntityRecognizer.MIN_SCORE = 0).

    Pattern is unformatted-only (\\d{11}); CNH has no established separator
    convention. A bare 11-digit run will also match the CPF and PIS regexes
    — when more than one mod-11 checksum passes on the same span, all
    matching detections are emitted (emit-both/three policy, never
    deduplicated).

    See SPEC Failure Mode #2: mathematically valid synthetic CNHs such as
    11111111111 are intentionally reported as PII — masking is content-blind.
    """

    SUPPORTED_ENTITY = BR_CNH
    PATTERNS = [Pattern("CNH_PATTERN", _CNH_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["cnh", "habilitação", "habilitacao", "carteira"]
    COMPILED_PATTERN = _CNH_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_cnh(pattern_text)
