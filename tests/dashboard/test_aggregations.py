"""Tests for dashboard/aggregations.py — pure Python, no I/O."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pandas as pd

from guardian_br.core.redact_store import AuditRow
from guardian_br.dashboard.aggregations import (
    by_adversarial_label,
    by_lgpd_article,
    by_pii_type,
    summary_stats,
    violations_over_time,
)

_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _row(
    id: str = "r",
    event_type: str = "scan",
    *,
    detections: list[dict[str, str]] | None = None,
    **kwargs: object,
) -> AuditRow:
    return AuditRow(  # type: ignore[call-arg]
        id=id,
        timestamp=_TS,
        event_type=event_type,
        detections=detections or [],
        **kwargs,
    )


# ── violations_over_time ──────────────────────────────────────────────────────


def test_violations_over_time_empty_input() -> None:
    df = violations_over_time([])
    assert isinstance(df, pd.DataFrame)
    assert df.empty


def test_violations_over_time_counts_scan_rows() -> None:
    rows = [_row(str(i), event_type="scan") for i in range(3)]
    df = violations_over_time(rows)
    assert df["count"].sum() == 3


def test_violations_over_time_excludes_non_scan() -> None:
    rows = [_row("a", event_type="auth_failure"), _row("b", event_type="scan")]
    df = violations_over_time(rows)
    assert df["count"].sum() == 1


def test_violations_over_time_bucket_day() -> None:
    rows = [_row("a"), _row("b")]
    df = violations_over_time(rows, bucket="day")
    assert len(df) == 1
    assert df.iloc[0]["count"] == 2


def test_violations_over_time_bucket_hour_separates() -> None:
    ts1 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    ts2 = datetime(2026, 1, 1, 11, 0, tzinfo=UTC)
    rows = [
        AuditRow(id="r1", timestamp=ts1, event_type="scan"),
        AuditRow(id="r2", timestamp=ts2, event_type="scan"),
    ]
    df = violations_over_time(rows, bucket="hour")
    assert len(df) == 2


def test_violations_over_time_sorted_ascending() -> None:
    base = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        AuditRow(id=str(i), timestamp=base + timedelta(days=i), event_type="scan")
        for i in [2, 0, 1]
    ]
    df = violations_over_time(rows)
    buckets = df["timestamp_bucket"].tolist()
    assert buckets == sorted(buckets)


# ── by_pii_type ───────────────────────────────────────────────────────────────


def test_by_pii_type_empty_input() -> None:
    assert by_pii_type([]).empty


def test_by_pii_type_no_detections() -> None:
    assert by_pii_type([_row("a")]).empty


def test_by_pii_type_counts_detections() -> None:
    rows = [
        _row("a", detections=[{"entity_type": "BR_CPF", "lgpd_article": "Art. 5º, I"}]),
        _row(
            "b",
            detections=[
                {"entity_type": "BR_CPF", "lgpd_article": "Art. 5º, I"},
                {"entity_type": "BR_CNPJ", "lgpd_article": "Art. 5º, I"},
            ],
        ),
    ]
    df = by_pii_type(rows)
    cpf_count = df[df["entity_type"] == "BR_CPF"]["count"].iloc[0]
    assert cpf_count == 2


def test_by_pii_type_sorted_descending() -> None:
    rows = [
        _row("a", detections=[{"entity_type": "BR_CPF", "lgpd_article": "x"}] * 5),
        _row("b", detections=[{"entity_type": "BR_CNPJ", "lgpd_article": "x"}] * 2),
    ]
    df = by_pii_type(rows)
    assert df.iloc[0]["entity_type"] == "BR_CPF"


# ── by_lgpd_article ───────────────────────────────────────────────────────────


def test_by_lgpd_article_empty_input() -> None:
    assert by_lgpd_article([]).empty


def test_by_lgpd_article_excludes_unknown() -> None:
    rows = [_row("a", detections=[{"entity_type": "X", "lgpd_article": "unknown"}])]
    assert by_lgpd_article(rows).empty


def test_by_lgpd_article_counts_articles() -> None:
    rows = [
        _row("a", detections=[{"entity_type": "X", "lgpd_article": "Art. 5º, I"}]),
        _row("b", detections=[{"entity_type": "Y", "lgpd_article": "Art. 5º, I"}]),
        _row("c", detections=[{"entity_type": "Z", "lgpd_article": "Art. 11"}]),
    ]
    df = by_lgpd_article(rows)
    art5_count = df[df["lgpd_article"] == "Art. 5º, I"]["count"].iloc[0]
    assert art5_count == 2


def test_by_lgpd_article_sorted_descending() -> None:
    rows = [
        _row("a", detections=[{"entity_type": "X", "lgpd_article": "Art. 5º, I"}] * 3),
        _row("b", detections=[{"entity_type": "Y", "lgpd_article": "Art. 11"}]),
    ]
    df = by_lgpd_article(rows)
    assert df.iloc[0]["lgpd_article"] == "Art. 5º, I"


# ── by_adversarial_label ──────────────────────────────────────────────────────


def test_by_adversarial_label_empty_input() -> None:
    assert by_adversarial_label([]).empty


def test_by_adversarial_label_safe_excluded() -> None:
    rows = [_row("a", adversarial_unsafe=False, adversarial_label="safe")]
    assert by_adversarial_label(rows).empty


def test_by_adversarial_label_only_unsafe_counted() -> None:
    rows = [
        _row("a", adversarial_unsafe=True, adversarial_label="S1"),
        _row("b", adversarial_unsafe=False, adversarial_label="safe"),
        _row("c", adversarial_unsafe=True, adversarial_label="S1"),
    ]
    df = by_adversarial_label(rows)
    assert len(df) == 1
    assert df.iloc[0]["adversarial_label"] == "S1"
    assert df.iloc[0]["count"] == 2


def test_by_adversarial_label_null_label_excluded() -> None:
    rows = [_row("a", adversarial_unsafe=True, adversarial_label=None)]
    assert by_adversarial_label(rows).empty


# ── summary_stats ─────────────────────────────────────────────────────────────


def test_summary_stats_empty() -> None:
    stats = summary_stats([])
    assert stats == {"total": 0, "blocked": 0, "unsafe": 0, "auth_failures": 0}


def test_summary_stats_counts() -> None:
    rows = [
        _row("a", event_type="scan", blocked=True, adversarial_unsafe=True),
        _row("b", event_type="scan", blocked=False, adversarial_unsafe=False),
        _row("c", event_type="auth_failure"),
    ]
    stats = summary_stats(rows)
    assert stats == {"total": 3, "blocked": 1, "unsafe": 1, "auth_failures": 1}
