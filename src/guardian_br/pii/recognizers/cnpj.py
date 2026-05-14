from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_CNPJ
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_cnpj
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_CNPJ_COMPILED = compile_pattern(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)")


class CnpjRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica).

    Uses a single regex pattern (base score 0.4) gated by mod-11 checksum
    validation with two weight sequences. Regex-only matches that fail the
    checksum are silenced (score → EntityRecognizer.MIN_SCORE = 0).

    See SPEC Failure Mode #2: mathematically valid synthetic CNPJs such as
    00.000.000/0000-00 are intentionally reported as PII — masking is
    content-blind.
    """

    SUPPORTED_ENTITY = BR_CNPJ
    PATTERNS = [Pattern("CNPJ_PATTERN", _CNPJ_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["cnpj", "empresa", "cadastro"]
    COMPILED_PATTERN = _CNPJ_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_cnpj(pattern_text)
