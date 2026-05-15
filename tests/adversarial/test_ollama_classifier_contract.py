"""Run contract tests against OllamaClassifier with MockTransport."""

from __future__ import annotations

import httpx
import pytest

from guardian_br.adversarial.ollama_classifier import OllamaClassifier
from tests.adversarial.contract import AdversarialClassifierContractTests


def _make_smart_transport() -> httpx.MockTransport:
    """Transport that returns 'safe' for safe phrases, 'unsafe\nS14' for injection."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama-guard3:8b"}]})
        if request.url.path == "/api/chat":
            import json

            body = json.loads(request.content)
            full = body["messages"][0]["content"]
            user_input = full.split("## Message to Evaluate\n\n", 1)[-1].strip()
            content = "unsafe\nS14" if "Ignore" in user_input else "safe"
            return httpx.Response(
                200,
                json={"model": "llama-guard3:8b", "message": {"role": "assistant", "content": content}, "done": True},
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


class TestOllamaClassifierContract(AdversarialClassifierContractTests):
    @pytest.fixture
    def classifier(self) -> OllamaClassifier:  # type: ignore[override]
        clf = OllamaClassifier()
        clf._client = httpx.Client(
            transport=_make_smart_transport(), base_url="http://mock"
        )
        return clf
