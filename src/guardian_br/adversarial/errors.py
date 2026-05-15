"""Adversarial classifier error hierarchy."""

from __future__ import annotations


class AdversarialError(Exception):
    pass


class AdversarialTimeoutError(AdversarialError):
    pass


class AdversarialConnectionError(AdversarialError):
    pass


class AdversarialParseError(AdversarialError):
    pass
