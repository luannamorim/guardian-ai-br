"""Tests for the CI eval gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian_br.eval.gate import main


def test_gate_passes_on_full_recall_corpus(tmp_corpus: Path, tmp_path: Path) -> None:
    report = tmp_path / "gate.json"
    rc = main(
        [
            "--corpus",
            str(tmp_corpus),
            "--category",
            "cpf",
            "--min-pii-recall",
            "0.99",
            "--report",
            str(report),
        ]
    )
    assert rc == 0
    data = json.loads(report.read_text())
    assert data["pii_recall"] == 1.0
    assert data["failures"] == []


def test_gate_fails_on_impossible_threshold(tmp_corpus: Path) -> None:
    rc = main(
        [
            "--corpus",
            str(tmp_corpus),
            "--category",
            "cpf",
            "--min-pii-recall",
            "1.5",  # impossible
        ]
    )
    assert rc == 1


def test_gate_missing_corpus_exits_two(tmp_path: Path) -> None:
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(SystemExit) as excinfo:
        main(["--corpus", str(missing)])
    assert excinfo.value.code == 2
