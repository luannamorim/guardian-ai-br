"""Sync Llama Guard 3 classifier via Ollama HTTP API.

Uses sync httpx.Client — caller is responsible for running in a thread if
needed (e.g., starlette.concurrency.run_in_threadpool in FastAPI routes).

Logging policy: errors may log reason + cardinality metadata but NEVER the
raw input text (it may contain PII).
"""

from __future__ import annotations

import hashlib
import logging
import time

import httpx

from guardian_br.adversarial.errors import (
    AdversarialConnectionError,
    AdversarialParseError,
    AdversarialTimeoutError,
)
from guardian_br.adversarial.ollama_parser import parse_llama_guard
from guardian_br.core.adversarial import AdversarialResult, AdversarialSource
from guardian_br.core.ttl_cache import TTLLRUCache
from guardian_br.prompts.loader import load_prompt

logger = logging.getLogger(__name__)

_SKIPPED_VERSION = "disabled"


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _DisabledClassifier:
    """No-op classifier returned when adversarial_enabled=False."""

    def classify(self, text: str) -> AdversarialResult:
        return AdversarialResult(
            label="safe",
            unsafe=False,
            latency_ms=0.0,
            model_version=_SKIPPED_VERSION,
            source="skipped",
        )

    def ping(self) -> bool:
        return True


class OllamaClassifier:
    """Sync Llama Guard 3 classifier via Ollama."""

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        model: str = "llama-guard3:8b",
        prompt_name: str = "llama_guard_ptbr_v1",
        timeout_s: float = 1.5,
        cache_ttl_s: int = 300,
        cache_max: int = 1024,
        fail_open: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s
        self._fail_open = fail_open
        prompt_text, digest = load_prompt(prompt_name)
        self._system_prompt = prompt_text
        self._model_version = f"{model}|prompt:{prompt_name}@{digest}"
        self._cache: TTLLRUCache[str, AdversarialResult] = TTLLRUCache(
            ttl_s=cache_ttl_s, max_size=cache_max
        )
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout_s)

    def _build_user_text(self, text: str) -> str:
        return self._system_prompt.replace("{text}", text)

    def _fallback_result(self, elapsed_ms: float) -> AdversarialResult:
        return AdversarialResult(
            label="safe",
            unsafe=False,
            latency_ms=elapsed_ms,
            model_version=self._model_version,
            source="fallback",
        )

    def classify(self, text: str) -> AdversarialResult:
        cache_key = _cache_key(text)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.model_copy(update={"source": "cached"})

        t0 = time.perf_counter()
        try:
            resp = self._client.post(
                "/api/chat",
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "user", "content": self._build_user_text(text)},
                    ],
                    "stream": False,
                    "options": {
                        "num_predict": 32,
                        "temperature": 0.0,
                        "top_p": 1.0,
                    },
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            label, categories = parse_llama_guard(content)
            source: AdversarialSource = "ollama"
        except httpx.TimeoutException as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("adversarial_classify_timeout elapsed_ms=%.1f", elapsed_ms)
            if not self._fail_open:
                raise AdversarialTimeoutError("Ollama timed out") from exc
            return self._fallback_result(elapsed_ms)
        except (
            httpx.ConnectError,
            httpx.ReadError,
            httpx.RemoteProtocolError,
            httpx.HTTPStatusError,
        ) as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("adversarial_classify_connection_error elapsed_ms=%.1f", elapsed_ms)
            if not self._fail_open:
                raise AdversarialConnectionError("Ollama unreachable") from exc
            return self._fallback_result(elapsed_ms)
        except AdversarialParseError:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("adversarial_classify_parse_error elapsed_ms=%.1f", elapsed_ms)
            if not self._fail_open:
                raise
            return self._fallback_result(elapsed_ms)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        result = AdversarialResult(
            label=label,
            unsafe=(label != "safe"),
            categories=categories,
            latency_ms=elapsed_ms,
            model_version=self._model_version,
            source=source,
        )
        self._cache.put(cache_key, result)
        return result

    def ping(self) -> bool:
        try:
            resp = self._client.get("/api/tags", timeout=0.5)
            resp.raise_for_status()
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            return any(self._model in name for name in models)
        except Exception:
            return False

    @property
    def cache_size(self) -> int:
        return len(self._cache)
