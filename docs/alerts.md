# Guardian-BR — Prometheus alert recipes

These are **examples**, not bundled rules. Guardian-BR ships the metrics
in `api/metrics.py`; teams plug them into their existing Alertmanager
the way they prefer. Each rule below names the metric it depends on, so
you can grep `api/metrics.py` if a label changes between releases.

The metrics surface at `GET /v1/metrics` in Prometheus exposition
format. Authentication can be relaxed for this endpoint via
`GUARDIAN_BR_METRICS_REQUIRE_AUTH=false`.

## SLO recipes

Drop the snippet below into a `prometheus.rules.yml` referenced from
`prometheus.yml`:

```yaml
groups:
- name: guardian-br-slo
  interval: 30s
  rules:
  # SPEC Success Criteria: p95 PII+adversarial < 50ms steady-state.
  - alert: GuardianBRLatencyP95High
    expr: |
      histogram_quantile(
        0.95,
        sum by (le, mode) (
          rate(guardian_scan_latency_seconds_bucket[5m])
        )
      ) > 0.050
    for: 5m
    labels:
      severity: warning
      slo: latency
    annotations:
      summary: "Guardian-BR p95 scan latency above 50ms"
      description: |
        Mode {{ $labels.mode }} p95 = {{ $value | humanizeDuration }} (target < 50ms).
        Check Llama Guard warm state, Ollama GPU/CPU saturation, and audit-log lag.

  - alert: GuardianBRLatencyP95Critical
    expr: |
      histogram_quantile(
        0.95,
        sum by (le, mode) (
          rate(guardian_scan_latency_seconds_bucket[5m])
        )
      ) > 0.200
    for: 5m
    labels:
      severity: critical
      slo: latency
    annotations:
      summary: "Guardian-BR p95 scan latency above 200ms hard ceiling"
      description: |
        SPEC Non-Functional Requirements: any scan exceeding 200ms is an SLO breach.

  # SPEC §Observability: error-rate alert > 1%.
  - alert: GuardianBRErrorRateHigh
    expr: |
      (
        sum(rate(guardian_scan_total{outcome="error"}[5m]))
        /
        clamp_min(sum(rate(guardian_scan_total[5m])), 1e-9)
      ) > 0.01
    for: 5m
    labels:
      severity: warning
      slo: error-rate
    annotations:
      summary: "Guardian-BR scan error rate above 1%"
      description: |
        Total error rate = {{ $value | humanizePercentage }} over 5m.
        Check container logs and Ollama health (/v1/healthz).

  # SPEC §Failure Modes #5: audit-log backend down → fallback active.
  - alert: GuardianBRAuditFallbackActive
    expr: |
      increase(guardian_audit_log_fallback_total[5m]) > 0
    for: 1m
    labels:
      severity: warning
      compliance: audit
    annotations:
      summary: "Guardian-BR audit log fell back to JSONL file"
      description: |
        Reason: {{ $labels.reason }}. The primary RedactStore is unreachable.
        Replay buffered rows once the store recovers; see README §Audit log.

  # SPEC §Failure Modes #1: Llama Guard cold start.
  - alert: GuardianBRAdversarialColdStart
    expr: |
      max_over_time(guardian_ollama_cold_start_seconds[15m]) > 5
    labels:
      severity: info
      slo: cold-start
    annotations:
      summary: "Guardian-BR Llama Guard cold start exceeded 5s"
      description: |
        Cold-start is excluded from the warm steady-state SLO but tracked
        for capacity planning. See SPEC §Resolved Decisions #2.

  # Sustained auth failures may indicate a credential-stuffing attempt.
  - alert: GuardianBRAuthFailureBurst
    expr: |
      sum by (reason) (rate(guardian_auth_failures_total[5m])) > 1
    for: 10m
    labels:
      severity: warning
      security: auth
    annotations:
      summary: "Guardian-BR auth failures > 1 rps for 10 minutes"
      description: |
        Reason: {{ $labels.reason }}. Check API key rotation status and
        review the audit log for principal=unknown rows.

  # SPEC §Resolved Decisions #6: handle TTL default 24h. A sudden spike
  # in unmask failures may indicate handle expiry storm or key drift.
  - alert: GuardianBRUnmaskFailureRateHigh
    expr: |
      (
        sum(rate(guardian_unmask_total{result="failure"}[5m]))
        /
        clamp_min(sum(rate(guardian_unmask_total[5m])), 1e-9)
      ) > 0.10
    for: 5m
    labels:
      severity: warning
      slo: unmask
    annotations:
      summary: "Guardian-BR unmask failure rate above 10%"
      description: |
        Check KEK rotation status and handle TTL configuration.

  # Shadow-block traffic that operators may want to graduate to BLOCK.
  - alert: GuardianBRShadowBlockRising
    expr: |
      sum(rate(guardian_scan_total{outcome="shadow_block"}[1h])) > 0
    for: 1h
    labels:
      severity: info
      rollout: shadow-mode
    annotations:
      summary: "Guardian-BR shadow mode would have blocked scans in the last hour"
      description: |
        Use the dashboard /v1/audit query to investigate would_block rows
        before flipping shadow_mode=false.
```

## Tuning notes

- The latency rule queries by `mode` because `BLOCK`/`REDACT`/`REVERSIBLE_REDACT`
  have different cost profiles; alerting on the aggregate hides the
  REVERSIBLE_REDACT envelope-encryption tail. Drop the `mode` label
  grouping if you prefer a single alert.
- The error-rate rule clamps the denominator to avoid the "no traffic =
  perpetually firing" foot-gun.
- `guardian_audit_log_fallback_total` is incremented every time a row
  flows to the JSONL fallback. A single increment is enough signal to
  page on-call — adjust `for:` if you accept transient blips.

## Where to send these alerts

The metrics here are operator-level (latency, errors). Detection-level
counts (`guardian_detection_total{entity_type, lgpd_article}`) are
intentionally **not** alertable: that's an audit signal, surfaced by the
Streamlit dashboard for the DPO, not a pager signal. Resist the urge to
page on "CPFs detected per minute" — it's normal traffic.
