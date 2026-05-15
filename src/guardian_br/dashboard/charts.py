from __future__ import annotations

from typing import Any

import altair as alt
import pandas as pd


def violations_over_time_chart(df: pd.DataFrame) -> Any:
    if df.empty:
        df = pd.DataFrame({"timestamp_bucket": [], "count": []})
    return (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X("timestamp_bucket:O", title="Data"),
            y=alt.Y("count:Q", title="Ocorrências"),
        )
        .properties(title="Violações ao longo do tempo")
    )


def by_pii_type_chart(df: pd.DataFrame) -> Any:
    if df.empty:
        df = pd.DataFrame({"entity_type": [], "count": []})
    return (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("count:Q", title="Ocorrências"),
            y=alt.Y("entity_type:N", sort="-x", title="Tipo PII"),
            color=alt.Color("entity_type:N", legend=None),
        )
        .properties(title="Por tipo de PII")
    )


def by_lgpd_article_chart(df: pd.DataFrame) -> Any:
    if df.empty:
        df = pd.DataFrame({"lgpd_article": [], "count": []})
    return (
        alt.Chart(df)
        .mark_bar(color="#2ca02c")
        .encode(
            x=alt.X("count:Q", title="Ocorrências"),
            y=alt.Y("lgpd_article:N", sort="-x", title="Artigo LGPD"),
        )
        .properties(title="Por artigo LGPD")
    )


def by_adversarial_label_chart(df: pd.DataFrame) -> Any:
    if df.empty:
        df = pd.DataFrame({"adversarial_label": [], "count": []})
    return (
        alt.Chart(df)
        .mark_bar(color="#d62728")
        .encode(
            x=alt.X("count:Q", title="Ocorrências"),
            y=alt.Y("adversarial_label:N", sort="-x", title="Categoria adversarial"),
        )
        .properties(title="Top categorias adversariais")
    )
