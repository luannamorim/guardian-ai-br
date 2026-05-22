"""Pydantic-typed plugin interface for custom recognizers.

SPEC FR 12: company-specific identifiers (internal account numbers, ticket
IDs, contract codes) can be registered without subclassing Presidio APIs.

Custom recognizers run in the same pipeline as built-in BR recognizers:

- Regex compiled via ``regex`` library (never stdlib ``re``) with backtrack
  timeout enforced at match time (REGEX_TIMEOUT)
- Optional validator callable to gate matches (e.g. a custom checksum)
- Optional ``lgpd_article`` override surfaced in ``Detection.lgpd_article``

Usage::

    from guardian_br import Guardian, CustomRecognizerSpec

    spec = CustomRecognizerSpec(
        entity_type="ACME_ACCOUNT_ID",
        patterns=[r"ACME-\\d{6}"],
        context=["conta", "account"],
        lgpd_article="Art. 5º, I",
    )
    g = Guardian(custom_recognizers=[spec])
    g.scan("minha conta ACME-123456").redacted_text
    # → "minha conta <ACME_ACCOUNT_ID>"
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from presidio_analyzer import Pattern, RecognizerResult
from presidio_analyzer.entity_recognizer import EntityRecognizer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from regex import error as RegexError

from guardian_br.pii.recognizers._base import ChecksumValidatedRecognizer
from guardian_br.pii.recognizers._regex_utils import REGEX_TIMEOUT, compile_pattern


class CustomRecognizerSpec(BaseModel):
    """Declarative spec for a user-supplied PII recognizer.

    The ``validator`` field is excluded from serialization because callables
    cannot round-trip through JSON. Specs without a validator emit every
    regex match; specs with one only emit matches the callable accepts.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    entity_type: Annotated[str, Field(min_length=1, pattern=r"^[A-Z][A-Z0-9_]*$")]
    patterns: Annotated[list[str], Field(min_length=1)]
    context: list[str] = []
    score: Annotated[float, Field(ge=0.0, le=1.0)] = 0.4
    lgpd_article: str | None = None
    validator: Callable[[str], bool] | None = Field(default=None, exclude=True)

    @field_validator("patterns")
    @classmethod
    def _validate_patterns_compile(cls, v: list[str]) -> list[str]:
        for p in v:
            try:
                compile_pattern(p)
            except RegexError as e:
                raise ValueError(f"invalid regex pattern {p!r}: {e}") from e
        return v


class _CustomPatternRecognizer(ChecksumValidatedRecognizer):
    """Adapter from a CustomRecognizerSpec to a Presidio recognizer.

    Borrows the ChecksumValidatedRecognizer base so custom recognizers
    inherit the regex-library + ReDoS-timeout path used by the built-ins.
    """

    def __init__(self, spec: CustomRecognizerSpec) -> None:
        # ChecksumValidatedRecognizer reads these as ClassVars during
        # super().__init__; setting them per-instance is deliberate so a
        # single Python process can host many independent custom recognizers.
        self.SUPPORTED_ENTITY = spec.entity_type  # type: ignore[misc]
        self.PATTERNS = [  # type: ignore[misc]
            Pattern(f"{spec.entity_type}_PATTERN_{i}", p, spec.score)
            for i, p in enumerate(spec.patterns)
        ]
        self.CONTEXT = spec.context  # type: ignore[misc]
        self._compiled_patterns = [compile_pattern(p) for p in spec.patterns]
        self.COMPILED_PATTERN = self._compiled_patterns[0]  # type: ignore[misc]
        self._spec = spec
        super().__init__()

    def validate_result(self, pattern_text: str) -> bool:
        if self._spec.validator is None:
            return True
        try:
            return bool(self._spec.validator(pattern_text))
        except Exception:
            return False

    def _analyze_patterns_in_text(
        self, text: str, flags: int | None = None
    ) -> list[RecognizerResult]:
        results: list[RecognizerResult] = []
        for pattern_meta, compiled in zip(self.PATTERNS, self._compiled_patterns, strict=True):
            try:
                matches = (
                    compiled.finditer(text, flags, timeout=REGEX_TIMEOUT)
                    if flags
                    else compiled.finditer(text, timeout=REGEX_TIMEOUT)
                )
            except RegexError:
                continue

            for match in matches:
                start, end = match.span()
                current = text[start:end]
                if not current:
                    continue
                ok = self.validate_result(current)
                score = pattern_meta.score if ok else EntityRecognizer.MIN_SCORE
                results.append(
                    RecognizerResult(
                        entity_type=self.supported_entities[0],
                        start=start,
                        end=end,
                        score=score,
                    )
                )
        return results


def build_custom_recognizer(spec: CustomRecognizerSpec) -> _CustomPatternRecognizer:
    return _CustomPatternRecognizer(spec)
