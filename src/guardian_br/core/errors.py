from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian_br.core.schemas import Detection


class GuardianError(Exception):
    pass


class BlockedError(GuardianError):
    """Raised by Guardian.scan when mode=BLOCK and PII is detected.

    Library callers: use try/except BlockedError.
    FastAPI layer maps this to HTTP 422.
    The detections attribute lists what triggered the block.
    """

    def __init__(self, detections: list[Detection]) -> None:
        self.detections = detections
        super().__init__(f"scan blocked: {len(detections)} detection(s)")


class HandleNotFound(GuardianError):
    """Raised internally; Guardian.unmask returns None instead of propagating."""

    pass


class HandleExpired(HandleNotFound):
    pass


class HandleTampered(HandleNotFound):
    pass
