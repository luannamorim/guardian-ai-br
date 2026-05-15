"""Assert that raw PII never appears in log output during a scan."""

import base64
import logging
import secrets

import pytest

from guardian_br import Guardian, Mode
from guardian_br.core.kms import EnvKMSProvider
from guardian_br.core.sqlite_redact_store import SQLiteRedactStore

_CPF = "123.456.789-09"
_CNPJ = "11.222.333/0001-81"


@pytest.fixture(autouse=True)
def _kms_env(monkeypatch: pytest.MonkeyPatch) -> None:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("GUARDIAN_BR_KEK_v1", key)
    monkeypatch.setenv("GUARDIAN_BR_KEK_CURRENT_ID", "v1")


def test_reversible_redact_no_pii_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    store = SQLiteRedactStore(":memory:")
    kms = EnvKMSProvider()
    g = Guardian(redact_store=store, kms=kms, mode_default=Mode.REVERSIBLE_REDACT)

    with caplog.at_level(logging.DEBUG):
        result = g.scan(f"cpf {_CPF} cnpj {_CNPJ}")

    for record in caplog.records:
        msg = record.getMessage()
        assert _CPF not in msg, f"Raw CPF found in log: {msg!r}"
        assert _CNPJ not in msg, f"Raw CNPJ found in log: {msg!r}"

    assert len(result.detections) == 2
