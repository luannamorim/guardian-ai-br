from __future__ import annotations

from presidio_analyzer import Pattern

from guardian_br.core.entities import BR_RG
from guardian_br.pii.recognizers._base import _BASE_SCORE, ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._checksums import validate_rg_sp
from guardian_br.pii.recognizers._regex_utils import compile_pattern

_RG_SP_COMPILED = compile_pattern(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}-?[\dXx](?!\d)")


class RgRecognizer(ChecksumValidatedRecognizer):
    """Presidio recognizer for Brazilian RG (Registro Geral) — SP only in v1.

    9-character identifier (8 base digits + 1 check digit, where the DV may
    be 0-9 or the letter 'X' meaning 10). Gated by the SSP/SP mod-11
    checksum. Regex-only matches that fail validation are silenced.

    v1 scope: SP-issued RG only. Other Brazilian states have heterogeneous
    formats with no public checksum standard, so a regex-only match would
    fire on any 9-digit run (phones, order IDs, etc.) — that violates
    CLAUDE.md's "no checksum → no detection" rule. Per-state validators are
    deferred to v1.1.

    See SPEC Failure Mode #2: mathematically valid synthetic RGs are
    intentionally reported as PII — masking is content-blind. Do NOT add
    rejection rules for synthetic sequences here.
    """

    SUPPORTED_ENTITY = BR_RG
    PATTERNS = [Pattern("RG_SP_PATTERN", _RG_SP_COMPILED.pattern, _BASE_SCORE)]
    CONTEXT = ["rg", "registro geral", "identidade", "ssp", "cédula"]
    COMPILED_PATTERN = _RG_SP_COMPILED

    def validate_result(self, pattern_text: str) -> bool:
        return validate_rg_sp(pattern_text)
