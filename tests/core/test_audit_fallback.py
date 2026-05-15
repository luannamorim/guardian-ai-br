"""Tests for core/audit_fallback.py."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from guardian_br.core.audit_fallback import FallbackAuditWriter
from guardian_br.core.redact_store import AuditRow

_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _tmp_path() -> Path:
    return Path(tempfile.mktemp(suffix=".jsonl"))


def test_append_writes_one_json_line() -> None:
    path = _tmp_path()
    writer = FallbackAuditWriter(path)
    row = AuditRow(id="abc", timestamp=_TS, event_type="scan", principal_id="p1")
    writer.append(row)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["id"] == "abc"
    assert data["event_type"] == "scan"
    path.unlink(missing_ok=True)


def test_append_multiple_rows() -> None:
    path = _tmp_path()
    writer = FallbackAuditWriter(path)
    for i in range(3):
        writer.append(AuditRow(id=str(i), timestamp=_TS, event_type="scan"))
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3
    path.unlink(missing_ok=True)


def test_append_line_is_valid_json() -> None:
    path = _tmp_path()
    writer = FallbackAuditWriter(path)
    writer.append(AuditRow(id="x", timestamp=_TS, event_type="auth_failure"))
    line = path.read_text().strip()
    data = json.loads(line)
    assert isinstance(data, dict)
    path.unlink(missing_ok=True)


def test_default_path_parent_created(tmp_path: Path) -> None:
    nested = tmp_path / "deep" / "dir" / "out.jsonl"
    writer = FallbackAuditWriter(nested)
    writer.append(AuditRow(id="y", timestamp=_TS, event_type="unmask"))
    assert nested.exists()
