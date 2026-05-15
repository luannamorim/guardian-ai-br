"""Fallback JSONL writer for when the primary audit store is unreachable.

This module must NOT log or print any values derived from user input.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

from guardian_br.core.redact_store import AuditRow

_DEFAULT_PATH = Path.home() / ".guardian_br" / "audit_fallback.jsonl"


class FallbackAuditWriter:
    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, row: AuditRow) -> None:
        line = json.dumps(row.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
