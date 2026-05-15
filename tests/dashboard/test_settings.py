"""Tests for dashboard/settings.py."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from guardian_br.dashboard.settings import DashboardSettings


def test_settings_loads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_URL", "http://localhost:8000")
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_KEY", "test-key")
    cfg = DashboardSettings()  # type: ignore[call-arg]
    assert str(cfg.api_url).rstrip("/") == "http://localhost:8000"
    assert cfg.api_key.get_secret_value() == "test-key"


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_URL", "http://x:8000")
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_KEY", "k")
    cfg = DashboardSettings()  # type: ignore[call-arg]
    assert cfg.default_days == 7
    assert cfg.max_rows == 5000
    assert cfg.request_timeout_s == 10.0


def test_settings_missing_api_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_URL", "http://x:8000")
    monkeypatch.delenv("GUARDIAN_BR_DASHBOARD_API_KEY", raising=False)
    with pytest.raises(ValidationError):
        DashboardSettings()  # type: ignore[call-arg]


def test_settings_missing_api_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIAN_BR_DASHBOARD_API_URL", raising=False)
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_KEY", "k")
    with pytest.raises(ValidationError):
        DashboardSettings()  # type: ignore[call-arg]


def test_settings_api_key_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_URL", "http://x:8000")
    monkeypatch.setenv("GUARDIAN_BR_DASHBOARD_API_KEY", "super-secret-value")
    cfg = DashboardSettings()  # type: ignore[call-arg]
    assert "super-secret-value" not in repr(cfg)
