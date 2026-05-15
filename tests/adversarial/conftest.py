"""Shared fixtures for adversarial tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from guardian_br.core.adversarial import AdversarialResult


def _make_ollama_response(content: str) -> dict[str, Any]:
    return {
        "model": "llama-guard3:8b",
        "message": {"role": "assistant", "content": content},
        "done": True,
    }


def _make_tags_response(model: str = "llama-guard3:8b") -> dict[str, Any]:
    return {"models": [{"name": model}]}


class _MockOllamaTransport(httpx.MockTransport):
    def __init__(self, classify_response: str = "safe") -> None:
        self._classify_response = classify_response

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json=_make_tags_response(),
                headers={"content-type": "application/json"},
            )
        if request.url.path == "/api/chat":
            return httpx.Response(
                200,
                json=_make_ollama_response(self._classify_response),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(404)


@pytest.fixture
def safe_transport() -> _MockOllamaTransport:
    return _MockOllamaTransport("safe")


@pytest.fixture
def unsafe_s14_transport() -> _MockOllamaTransport:
    return _MockOllamaTransport("unsafe\nS14")


@pytest.fixture
def unsafe_multi_transport() -> _MockOllamaTransport:
    return _MockOllamaTransport("unsafe\nS1,S14")


class FakeClassifier:
    """Injectable fake classifier for Guardian integration tests."""

    def __init__(self, result: AdversarialResult) -> None:
        self._result = result
        self.call_count = 0

    def classify(self, text: str) -> AdversarialResult:
        self.call_count += 1
        return self._result

    def ping(self) -> bool:
        return True


def make_safe_result() -> AdversarialResult:
    return AdversarialResult(
        label="safe",
        unsafe=False,
        latency_ms=1.0,
        model_version="llama-guard3:8b|prompt:test@00000000",
        source="ollama",
    )


def make_unsafe_result(label: str = "S14") -> AdversarialResult:
    return AdversarialResult(
        label=label,
        unsafe=True,
        categories=[label],
        latency_ms=1.0,
        model_version="llama-guard3:8b|prompt:test@00000000",
        source="ollama",
    )
