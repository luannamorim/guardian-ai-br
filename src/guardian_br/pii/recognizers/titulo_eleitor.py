from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_TITULO_ELEITOR
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_titulo_eleitor
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_TITULO_COMPILED = compile_pattern(r"(?<!\d)\d{4}[\s.]?\d{4}[\s.]?\d{4}(?!\d)")


class TituloEleitorRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian título de eleitor (TSE voter ID).

    12-digit identifier where digits 9-10 encode the issuing state (01-28)
    and digits 11-12 are check digits. Gated by the TSE checksum, which adds
    a state-code lookup AND a "DV cannot be zero" clamp for SP (01) and MG
    (02). Regex-only matches that fail validation are silenced.

    Pattern accepts the canonical 4-4-4 form with optional space or dot
    separators, plus the unbroken 12-digit form. Distinct length from
    CPF/PIS/CNH (11) and CNPJ (14) — no emit-both overlap with existing
    recognizers.

    See SPEC Failure Mode #2: mathematically valid synthetic títulos are
    intentionally reported as PII — masking is content-blind. Do NOT add
    rejection rules for synthetic sequences here.
    """

    SUPPORTED_ENTITY = BR_TITULO_ELEITOR
    PATTERNS = [Pattern("TITULO_ELEITOR_PATTERN", _TITULO_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["título", "titulo", "eleitor", "tse", "zona", "seção", "secao"]
    COMPILED_PATTERN = _TITULO_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_titulo_eleitor(pattern_text)
