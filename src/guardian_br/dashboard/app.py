"""Guardian-BR — Painel de auditoria (Streamlit).

Run via: guardian-br-dashboard
Or directly: streamlit run app.py
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import streamlit as st

from guardian_br.core.redact_store import AuditRow
from guardian_br.dashboard.aggregations import (
    by_adversarial_label,
    by_lgpd_article,
    by_pii_type,
    summary_stats,
    violations_over_time,
)
from guardian_br.dashboard.charts import (
    by_adversarial_label_chart,
    by_lgpd_article_chart,
    by_pii_type_chart,
    violations_over_time_chart,
)
from guardian_br.dashboard.client import AuditClient, DashboardAuthError
from guardian_br.dashboard.settings import DashboardSettings


@st.cache_data(ttl=60)
def _load_rows(
    api_url: str,
    api_key: str,
    since_iso: str,
    until_iso: str,
    max_rows: int,
    timeout_s: float,
) -> list[dict[str, Any]]:
    since = datetime.fromisoformat(since_iso)
    until = datetime.fromisoformat(until_iso)
    with AuditClient(api_url, api_key, timeout_s=timeout_s) as client:
        rows = client.fetch(since=since, until=until, max_rows=max_rows)
    return [r.model_dump(mode="json") for r in rows]


def main() -> None:
    st.set_page_config(
        page_title="Guardian-BR — Painel de auditoria",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("🛡️ Guardian-BR — Painel de auditoria")

    try:
        cfg = DashboardSettings()  # type: ignore[call-arg]
    except Exception as exc:
        st.error(
            f"Erro de configuração: {exc}\n\n"
            "Defina `GUARDIAN_BR_DASHBOARD_API_URL` e `GUARDIAN_BR_DASHBOARD_API_KEY`."
        )
        st.stop()
        return

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("Filtros")
        now = datetime.now(UTC)
        default_since = now - timedelta(days=cfg.default_days)

        since_date = st.date_input("Desde", value=default_since.date())
        until_date = st.date_input("Até", value=now.date())

        since = datetime(since_date.year, since_date.month, since_date.day, tzinfo=UTC)
        until = datetime(until_date.year, until_date.month, until_date.day, 23, 59, 59, tzinfo=UTC)

        include_auth_failures = st.checkbox("Incluir falhas de autenticação", value=False)
        bucket: Literal["hour", "day"] = st.selectbox("Granularidade", ["day", "hour"], index=0)
        max_rows: int = st.slider("Máx. linhas", 100, cfg.max_rows, min(1000, cfg.max_rows))
        refresh = st.button("🔄 Atualizar")

    if refresh:
        st.cache_data.clear()

    # ── Fetch ─────────────────────────────────────────────────────────────────
    try:
        raw = _load_rows(
            str(cfg.api_url),
            cfg.api_key.get_secret_value(),
            since.isoformat(),
            until.isoformat(),
            max_rows,
            cfg.request_timeout_s,
        )
    except DashboardAuthError as exc:
        st.error(
            f"Autenticação falhou (HTTP {exc.status_code}). "
            "A chave da API precisa ter o escopo `audit:read`.\n\n"
            "Formato correto: `sha256:<hash>:audit:read` em `GUARDIAN_BR_API_KEYS_HASHED`."
        )
        st.stop()
        return
    except Exception as exc:
        st.error(f"Erro ao buscar dados da API: {exc}")
        st.stop()
        return

    rows: list[AuditRow] = [AuditRow.model_validate(r) for r in raw]
    if not include_auth_failures:
        rows = [r for r in rows if r.event_type != "auth_failure"]

    # ── Summary metrics ───────────────────────────────────────────────────────
    stats = summary_stats(rows)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total de eventos", stats["total"])
    c2.metric("Bloqueados", stats["blocked"])
    c3.metric("Adversariais inseguros", stats["unsafe"])
    c4.metric("Falhas de autenticação", stats["auth_failures"])

    # ── Charts ────────────────────────────────────────────────────────────────
    col_left, col_right = st.columns(2)
    with col_left:
        st.altair_chart(
            violations_over_time_chart(violations_over_time(rows, bucket=bucket)),
            use_container_width=True,
        )
        st.altair_chart(
            by_lgpd_article_chart(by_lgpd_article(rows)),
            use_container_width=True,
        )
    with col_right:
        st.altair_chart(
            by_pii_type_chart(by_pii_type(rows)),
            use_container_width=True,
        )
        st.altair_chart(
            by_adversarial_label_chart(by_adversarial_label(rows)),
            use_container_width=True,
        )

    if not rows:
        st.info("Nenhum evento encontrado no período selecionado.")


if __name__ == "__main__":
    main()
