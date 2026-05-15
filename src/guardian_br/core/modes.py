from enum import StrEnum


class Mode(StrEnum):
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    REVERSIBLE_REDACT = "REVERSIBLE_REDACT"
