"""Build the default AdversarialClassifier from Settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from guardian_br.core.adversarial import AdversarialClassifier

if TYPE_CHECKING:
    from guardian_br.api.settings import Settings


def build_default_classifier(settings: Settings) -> AdversarialClassifier:
    """Return a configured classifier based on *settings*.

    Returns a no-op stub when adversarial_enabled=False so the rest of the
    codebase never needs to branch on the enabled flag.
    """
    from guardian_br.adversarial.ollama_classifier import (
        OllamaClassifier,
        _DisabledClassifier,
    )

    if not settings.adversarial_enabled:
        return _DisabledClassifier()

    return OllamaClassifier(
        base_url=settings.ollama_base_url,
        model=settings.llama_guard_model,
        prompt_name=settings.adversarial_prompt,
        timeout_s=settings.adversarial_timeout_s,
        cache_ttl_s=settings.adversarial_cache_ttl_s,
        cache_max=settings.adversarial_cache_max,
        fail_open=settings.adversarial_fail_open,
    )
