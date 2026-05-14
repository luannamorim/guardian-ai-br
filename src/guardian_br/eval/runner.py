"""Guardian-BR evaluation runner.

Usage::

    python -m guardian_br.eval --corpus evals/pii_corpus.jsonl --category cpf
    make eval-quick CATEGORY=cpf
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _load_corpus(corpus_path: Path, category: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with corpus_path.open(encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            row: dict[str, Any] = json.loads(stripped)
            if category != "all" and row.get("category") != category:
                continue
            rows.append(row)
    return rows


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _score_corpus(
    rows: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, int]], list[float]]:
    """Compute TP/FN/FP counts and per-row latency for *rows*."""
    from guardian_br.guardian import Guardian

    guardian = Guardian()
    guardian.scan("aquecimento")  # warm up analyzer lazy-init

    stats: dict[str, dict[str, int]] = {}
    latencies: list[float] = []

    for row in rows:
        text: str = row["text"]
        gold_labels: list[dict[str, Any]] = row.get("labels", [])

        t0 = time.perf_counter()
        result = guardian.scan(text)
        latencies.append((time.perf_counter() - t0) * 1000)

        predicted = result.detections

        # TPs and FNs from gold perspective
        for gold in gold_labels:
            etype = gold["type"]
            entry = stats.setdefault(etype, {"tp": 0, "fn": 0, "fp": 0})
            matched = any(
                d.entity_type == etype
                and _spans_overlap(d.start, d.end, gold["start"], gold["end"])
                for d in predicted
            )
            if matched:
                entry["tp"] += 1
            else:
                entry["fn"] += 1

        # FPs from prediction perspective
        for det in predicted:
            etype = det.entity_type
            entry = stats.setdefault(etype, {"tp": 0, "fn": 0, "fp": 0})
            gold_match = any(
                lbl["type"] == etype
                and _spans_overlap(det.start, det.end, lbl["start"], lbl["end"])
                for lbl in gold_labels
            )
            if not gold_match:
                entry["fp"] += 1

    return stats, latencies


def _format_report(
    stats: dict[str, dict[str, int]],
    latencies: list[float],
    category: str,
    corpus_path: Path,
) -> str:
    lines: list[str] = []
    lines.append("# Guardian-BR Eval Report")
    lines.append("")
    lines.append(f"- Corpus: `{corpus_path}`")
    lines.append(f"- Category filter: `{category}`")
    lines.append(f"- Rows evaluated: {len(latencies)}")
    lines.append(f"- Generated: {datetime.now(UTC).isoformat()}")
    lines.append("")

    lines.append("## PII Results")
    lines.append("")
    lines.append("| Type | TP | FN | FP | Recall | Precision |")
    lines.append("|------|----|----|-----|--------|-----------|")
    for etype, s in sorted(stats.items()):
        tp, fn, fp = s["tp"], s["fn"], s["fp"]
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        lines.append(
            f"| {etype} | {tp} | {fn} | {fp} | {recall:.1%} | {precision:.1%} |"
        )
    lines.append("")

    lines.append("## Adversarial Results")
    lines.append("")
    lines.append("| Category | Recall | Precision |")
    lines.append("|----------|--------|-----------|")
    lines.append("| (not evaluated in this run) | n/a | n/a |")
    lines.append("")

    if latencies:
        lines.append("## Latency")
        lines.append("")
        p50 = statistics.median(latencies)
        sorted_lat = sorted(latencies)
        n = len(sorted_lat)
        p95 = sorted_lat[min(n - 1, int(n * 0.95))]
        p99 = sorted_lat[min(n - 1, int(n * 0.99))]
        lines.append(f"- p50: {p50:.1f} ms")
        lines.append(f"- p95: {p95:.1f} ms")
        lines.append(f"- p99: {p99:.1f} ms")
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian-BR benchmark runner")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("evals/pii_corpus.jsonl"),
        help="Path to JSONL corpus file",
    )
    parser.add_argument(
        "--category",
        default="all",
        help="Filter corpus rows by category (e.g. cpf). Default: all",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("eval_report.md"),
        help="Output report path",
    )
    parser.add_argument(
        "--history-dir",
        type=Path,
        default=Path("evals/history"),
        help="Directory to archive timestamped report snapshots",
    )
    args = parser.parse_args(argv)

    if not args.corpus.exists():
        print(f"Error: corpus file not found: {args.corpus}", file=sys.stderr)
        return 1

    rows = _load_corpus(args.corpus, args.category)
    if not rows:
        print(f"Warning: no rows matched category={args.category!r}", file=sys.stderr)

    print(f"Scoring {len(rows)} rows (category={args.category!r})...")
    stats, latencies = _score_corpus(rows)

    report = _format_report(stats, latencies, args.category, args.corpus)
    args.out.write_text(report, encoding="utf-8")
    print(f"Report written to {args.out}")

    args.history_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    snapshot = args.history_dir / f"eval_report_{ts}.md"
    snapshot.write_text(report, encoding="utf-8")
    print(f"Snapshot archived to {snapshot}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
