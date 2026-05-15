from __future__ import annotations

from typing import TYPE_CHECKING

from guardian_br.core.adversarial import AdversarialResult

if TYPE_CHECKING:
    from guardian_br.core.schemas import Detection


class GuardianError(Exception):
    pass


class BlockedError(GuardianError):
    """Raised by Guardian.scan when mode=BLOCK and PII or adversarial unsafe is detected.

    Library callers: use try/except BlockedError.
    FastAPI layer maps this to HTTP 422.
    `detections` lists what PII triggered the block (may be empty if only adversarial).
    `adversarial` carries the adversarial classification when it contributed to the block.
    """

    def __init__(
        self,
        detections: list[Detection],
        *,
        adversarial: AdversarialResult | None = None,
    ) -> None:
        self.detections = detections
        self.adversarial = adversarial
        if detections and adversarial and adversarial.unsafe:
            reason = "PII + adversarial"
        elif adversarial and adversarial.unsafe:
            reason = "adversarial"
        else:
            reason = "PII"
        super().__init__(f"scan blocked ({reason}): {len(detections)} detection(s)")


class HandleNotFound(GuardianError):
    """Raised internally; Guardian.unmask returns None instead of propagating."""

    pass


class HandleExpired(HandleNotFound):
    pass


class HandleTampered(HandleNotFound):
    pass
