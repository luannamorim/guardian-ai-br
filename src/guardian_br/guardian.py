from presidio_analyzer import AnalyzerEngine

from guardian_br.core.entities import BR_ENTITIES
from guardian_br.core.schemas import Detection, ScanResult
from guardian_br.lgpd.loader import load_lgpd_mapping


class Guardian:
    """Entry point for Guardian-BR PII detection.

    Example::

        result = Guardian().scan("meu cpf eh 123.456.789-09")
        print(result.redacted_text)  # "meu cpf eh <BR_CPF>"
    """

    def __init__(self, *, analyzer: AnalyzerEngine | None = None) -> None:
        self._analyzer = analyzer

    def _get_analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            from guardian_br.pii.registry import build_analyzer_engine

            self._analyzer = build_analyzer_engine()
        return self._analyzer

    def scan(self, text: str) -> ScanResult:
        """Scan *text* for BR PII and return a frozen ScanResult.

        Detections include only entities with checksums that pass validation.
        The returned ``redacted_text`` replaces each detected span with
        ``<ENTITY_TYPE>`` (e.g. ``<BR_CPF>``).
        """
        analyzer = self._get_analyzer()
        mapping = load_lgpd_mapping()

        results = analyzer.analyze(
            text=text,
            language="pt",
            entities=list(BR_ENTITIES),
        )

        detections: list[Detection] = []
        for r in results:
            rule = mapping.rules.get(r.entity_type)
            lgpd_article = rule.lgpd_articles[0].article if rule else None
            detections.append(
                Detection(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=r.score,
                    lgpd_article=lgpd_article,
                )
            )

        redacted_text = _redact(text, detections)
        return ScanResult(text=text, detections=detections, redacted_text=redacted_text)


def _redact(text: str, detections: list[Detection]) -> str:
    """Replace detected spans back-to-front so positions stay valid."""
    result = text
    for det in sorted(detections, key=lambda d: d.start, reverse=True):
        placeholder = f"<{det.entity_type}>"
        result = result[: det.start] + placeholder + result[det.end :]
    return result
