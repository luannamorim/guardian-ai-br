"""CI eval gate.

SPEC Eval Strategy: "Block PRs where PII recall drops below 99% or adversarial
recall drops > 3pp." This module aggregates the runner's stats and exits
non-zero when thresholds breach.

Usage::

    python -m guardian_br.eval.gate --corpus evals/pii_corpus.jsonl \\
        --min-pii-recall 0.99

The adversarial gate is opt-in via ``--gate-adversarial`` because CI
images typically don't have Ollama. Library callers can still drive
this from local benchmark runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from guardian_br.eval.runner import (
    _aggregate_adv,
    _aggregate_pii,
    _detect_corpus_kind,
    _load_corpus,
    _score_adv_baseline,
    _score_pii_baseline,
)


def _load_rows(corpus: Path, category: str) -> list[dict[str, Any]]:
    if not corpus.exists():
        print(f"Error: corpus file not found: {corpus}", file=sys.stderr)
        sys.exit(2)
    return _load_corpus(corpus, category)


def _evaluate(
    rows: list[dict[str, Any]],
    *,
    gate_adversarial: bool,
) -> tuple[float | None, float | None]:
    from guardian_br.eval.baselines import GuardianBaseline

    baseline = GuardianBaseline()
    kind = _detect_corpus_kind(rows)
    pii_recall: float | None = None
    adv_recall: float | None = None

    if kind in ("pii", "mixed"):
        stats, _ = _score_pii_baseline(rows, baseline)
        tp, fn, _fp = _aggregate_pii(stats)
        pii_recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    if gate_adversarial and kind in ("adversarial", "mixed"):
        stats_adv, _ = _score_adv_baseline(rows, baseline)
        tp, fn, _fp, _tn = _aggregate_adv(stats_adv)
        adv_recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    return pii_recall, adv_recall


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian-BR eval gate")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--category", default="all")
    parser.add_argument("--min-pii-recall", type=float, default=0.99)
    parser.add_argument("--min-adv-recall", type=float, default=0.50)
    parser.add_argument("--gate-adversarial", action="store_true")
    parser.add_argument(
        "--report", type=Path, default=None, help="Write a tiny JSON report of the gate run"
    )
    args = parser.parse_args(argv)

    rows = _load_rows(args.corpus, args.category)
    if not rows:
        print(f"Error: no rows in corpus {args.corpus} (category={args.category!r})", file=sys.stderr)
        return 2

    pii_recall, adv_recall = _evaluate(rows, gate_adversarial=args.gate_adversarial)

    failures: list[str] = []
    if pii_recall is not None:
        print(f"PII recall: {pii_recall:.1%} (min {args.min_pii_recall:.1%})")
        if pii_recall < args.min_pii_recall:
            failures.append(
                f"PII recall {pii_recall:.1%} below threshold {args.min_pii_recall:.1%}"
            )

    if args.gate_adversarial and adv_recall is not None:
        print(f"Adversarial recall: {adv_recall:.1%} (min {args.min_adv_recall:.1%})")
        if adv_recall < args.min_adv_recall:
            failures.append(
                f"Adversarial recall {adv_recall:.1%} below threshold {args.min_adv_recall:.1%}"
            )

    if args.report:
        args.report.write_text(
            json.dumps(
                {
                    "corpus": str(args.corpus),
                    "category": args.category,
                    "pii_recall": pii_recall,
                    "adv_recall": adv_recall,
                    "failures": failures,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    if failures:
        for f in failures:
            print(f"GATE FAIL: {f}", file=sys.stderr)
        return 1

    print("GATE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
