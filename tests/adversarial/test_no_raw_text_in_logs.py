"""Assert that raw input text never appears in log output when OllamaClassifier.classify() is called."""

from __future__ import annotations

import logging

import httpx
import pytest

from guardian_br.adversarial.ollama_classifier import OllamaClassifier

_INPUT_TEXT = "cpf 123.456.789-09 secreto"


def _make_classifier(transport: httpx.MockTransport, fail_open: bool = True) -> OllamaClassifier:
    clf = OllamaClassifier(fail_open=fail_open)
    clf._client = httpx.Client(transport=transport, base_url="http://mock")
    return clf


def test_happy_path_no_raw_text_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "llama-guard3:8b",
                "message": {"role": "assistant", "content": "safe"},
                "done": True,
            },
        )

    clf = _make_classifier(httpx.MockTransport(handler))

    with caplog.at_level(logging.DEBUG):
        clf.classify(_INPUT_TEXT)

    for record in caplog.records:
        msg = record.getMessage()
        assert _INPUT_TEXT not in msg, f"Raw input text found in log: {msg!r}"


def test_timeout_error_no_raw_text_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    clf = _make_classifier(httpx.MockTransport(handler), fail_open=True)

    with caplog.at_level(logging.DEBUG):
        clf.classify(_INPUT_TEXT)

    for record in caplog.records:
        msg = record.getMessage()
        assert _INPUT_TEXT not in msg, f"Raw input text found in log: {msg!r}"


def test_connection_error_no_raw_text_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    clf = _make_classifier(httpx.MockTransport(handler), fail_open=True)

    with caplog.at_level(logging.DEBUG):
        clf.classify(_INPUT_TEXT)

    for record in caplog.records:
        msg = record.getMessage()
        assert _INPUT_TEXT not in msg, f"Raw input text found in log: {msg!r}"


def test_parse_error_no_raw_text_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "llama-guard3:8b",
                "message": {"role": "assistant", "content": "I am not sure about this"},
                "done": True,
            },
        )

    clf = _make_classifier(httpx.MockTransport(handler), fail_open=True)

    with caplog.at_level(logging.DEBUG):
        clf.classify(_INPUT_TEXT)

    for record in caplog.records:
        msg = record.getMessage()
        assert _INPUT_TEXT not in msg, f"Raw input text found in log: {msg!r}"
