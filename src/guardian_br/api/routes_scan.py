import time

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from guardian_br.api import metrics as m
from guardian_br.api.auth import Principal, get_principal
from guardian_br.api.dependencies import get_guardian
from guardian_br.api.schemas import ScanRequest
from guardian_br.core.errors import BlockedError
from guardian_br.core.schemas import ScanResult
from guardian_br.guardian import Guardian

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
async def scan_endpoint(
    request: Request,
    body: ScanRequest,
    principal: Principal = Depends(get_principal),
    guardian: Guardian = Depends(get_guardian),
) -> ScanResult:
    """Scan text for BR PII and adversarial content.

    - mode=REDACT (default): replaces each span with ``<ENTITY_TYPE>``
    - mode=REVERSIBLE_REDACT: replaces with ``<RDX:{handle}>`` and stores
      the encrypted original for later retrieval via POST /v1/unmask
    - mode=BLOCK: returns 422 if any PII or adversarial content is detected

    Set ``skip_adversarial=true`` to bypass Llama Guard classification.
    Authenticate via ``X-API-Key`` header.
    """
    effective_mode = body.mode
    t0 = time.perf_counter()
    try:
        result = await run_in_threadpool(
            guardian.scan,
            body.text,
            mode=effective_mode,
            skip_adversarial=body.skip_adversarial,
        )
        elapsed = time.perf_counter() - t0
        mode_label = result.mode.value
        m.SCAN_TOTAL.labels(mode=mode_label, outcome="ok").inc()
        m.SCAN_LATENCY.labels(mode=mode_label).observe(elapsed)
        for det in result.detections:
            m.DETECTION_TOTAL.labels(
                entity_type=det.entity_type,
                lgpd_article=det.lgpd_article or "unknown",
            ).inc()
        if result.adversarial is not None:
            adv = result.adversarial
            m.ADVERSARIAL_TOTAL.labels(label=adv.label, source=adv.source).inc()
            m.ADVERSARIAL_LATENCY.labels(source=adv.source).observe(adv.latency_ms / 1000)
        return result
    except BlockedError as exc:
        elapsed = time.perf_counter() - t0
        mode_label = (effective_mode or guardian.mode_default).value
        m.SCAN_TOTAL.labels(mode=mode_label, outcome="blocked").inc()
        m.SCAN_LATENCY.labels(mode=mode_label).observe(elapsed)
        if exc.adversarial is not None:
            adv = exc.adversarial
            m.ADVERSARIAL_TOTAL.labels(label=adv.label, source=adv.source).inc()
            m.ADVERSARIAL_LATENCY.labels(source=adv.source).observe(adv.latency_ms / 1000)
        raise
    except Exception:
        elapsed = time.perf_counter() - t0
        mode_label = (effective_mode or guardian.mode_default).value
        m.SCAN_TOTAL.labels(mode=mode_label, outcome="error").inc()
        m.SCAN_LATENCY.labels(mode=mode_label).observe(elapsed)
        raise
