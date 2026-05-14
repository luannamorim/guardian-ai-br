"""Smoke test for the benchmark runner."""
from pathlib import Path

from guardian_br.eval.runner import main


def test_runner_produces_report(tmp_corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "eval_report.md"
    history = tmp_path / "history"

    rc = main(
        [
            "--corpus", str(tmp_corpus),
            "--category", "cpf",
            "--out", str(out),
            "--history-dir", str(history),
        ]
    )
    assert rc == 0
    assert out.exists()

    content = out.read_text(encoding="utf-8")
    assert "## PII Results" in content
    assert "## Adversarial Results" in content
    assert "## Latency" in content


def test_runner_archives_snapshot(tmp_corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "eval_report.md"
    history = tmp_path / "history"

    main(
        [
            "--corpus", str(tmp_corpus),
            "--category", "cpf",
            "--out", str(out),
            "--history-dir", str(history),
        ]
    )

    snapshots = list(history.glob("eval_report_*.md"))
    assert len(snapshots) == 1


def test_runner_reports_recall(tmp_corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "eval_report.md"
    history = tmp_path / "history"

    main(
        [
            "--corpus", str(tmp_corpus),
            "--category", "cpf",
            "--out", str(out),
            "--history-dir", str(history),
        ]
    )

    content = out.read_text(encoding="utf-8")
    assert "BR_CPF" in content
    assert "100.0%" in content  # both positive rows detected → 100% recall
