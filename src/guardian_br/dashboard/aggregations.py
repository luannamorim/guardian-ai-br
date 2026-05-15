from __future__ import annotations

from collections import Counter
from datetime import UTC
from typing import Literal

import pandas as pd

from guardian_br.core.redact_store import AuditRow


def violations_over_time(
    rows: list[AuditRow],
    bucket: Literal["hour", "day"] = "day",
) -> pd.DataFrame:
    """Return a DataFrame [timestamp_bucket, count] for scan events only."""
    counts: Counter[str] = Counter()
    for r in rows:
        if r.event_type != "scan":
            continue
        ts = r.timestamp.astimezone(UTC)
        key = ts.strftime("%Y-%m-%d %H:00") if bucket == "hour" else ts.strftime("%Y-%m-%d")
        counts[key] += 1
    if not counts:
        return pd.DataFrame(columns=["timestamp_bucket", "count"])
    return (
        pd.DataFrame({"timestamp_bucket": list(counts.keys()), "count": list(counts.values())})
        .sort_values("timestamp_bucket")
        .reset_index(drop=True)
    )


def by_pii_type(rows: list[AuditRow]) -> pd.DataFrame:
    """Return a DataFrame [entity_type, count] across all detections."""
    counts: Counter[str] = Counter()
    for r in rows:
        for d in r.detections:
            et = d.get("entity_type")
            if et:
                counts[et] += 1
    if not counts:
        return pd.DataFrame(columns=["entity_type", "count"])
    return (
        pd.DataFrame({"entity_type": list(counts.keys()), "count": list(counts.values())})
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )


def by_lgpd_article(rows: list[AuditRow]) -> pd.DataFrame:
    """Return a DataFrame [lgpd_article, count], excluding 'unknown'."""
    counts: Counter[str] = Counter()
    for r in rows:
        for d in r.detections:
            art = d.get("lgpd_article")
            if art and art != "unknown":
                counts[art] += 1
    if not counts:
        return pd.DataFrame(columns=["lgpd_article", "count"])
    return (
        pd.DataFrame({"lgpd_article": list(counts.keys()), "count": list(counts.values())})
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )


def by_adversarial_label(rows: list[AuditRow]) -> pd.DataFrame:
    """Return a DataFrame [adversarial_label, count] for rows where adversarial_unsafe is True."""
    counts: Counter[str] = Counter()
    for r in rows:
        if r.adversarial_unsafe and r.adversarial_label:
            counts[r.adversarial_label] += 1
    if not counts:
        return pd.DataFrame(columns=["adversarial_label", "count"])
    return (
        pd.DataFrame({"adversarial_label": list(counts.keys()), "count": list(counts.values())})
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )


def summary_stats(rows: list[AuditRow]) -> dict[str, int]:
    return {
        "total": len(rows),
        "blocked": sum(1 for r in rows if r.blocked),
        "unsafe": sum(1 for r in rows if r.adversarial_unsafe),
        "auth_failures": sum(1 for r in rows if r.event_type == "auth_failure"),
    }
