---
name: eval-runner
description: Run Guardian-BR's benchmark suite (PII recall, adversarial precision/recall, latency) on a given corpus and interpret the results against SPEC thresholds and Presidio/Llama Guard baselines.
---

# Eval Runner

Packages the eval invocation and result interpretation logic as reusable expertise. The `/eval` command is the user-facing orchestrator; this skill supplies the interpretation layer that the `eval-impact-analyzer` agent also calls.

## Invocation patterns

Full suite:
```
make eval CORPUS=evals/pii_corpus.jsonl
make eval CORPUS=evals/adversarial_corpus.jsonl
```

Targeted subset:
```
make eval-quick CATEGORY=<name>
```
Valid categories: `cpf`, `cnpj`, `rg`, `cnh`, `titulo`, `pis`, `adversarial`, `latency`, `lgpd_coverage`

Custom corpus:
```
make eval CORPUS=<path-to-jsonl>
```
JSONL format: one object per line with `text` (string) and `labels` (list of `{type, start, end}` for PII; `{adversarial: true/false}` for adversarial cases).

## Reading eval_report.md

After `make eval` completes, `eval_report.md` is written to the project root. Key sections:

```
## PII Results
| Type | Recall | Precision | FP_rate |

## Adversarial Results
| Metric    | Guardian-BR | Llama Guard baseline | Delta |

## Latency (p50 / p95 / p99)
PII:          12ms / 41ms / 58ms
Adversarial:  18ms / 47ms / 71ms
```

## SPEC threshold table

| Metric | Target | Hard stop? |
|---|---|---|
| PII recall (any BR category) | 100% | Yes |
| False positive rate | < 2% | Yes |
| Adversarial recall | >= baseline + 10pp | Yes |
| Adversarial precision | >= 0.90 | Yes |
| p95 latency PII | < 50ms | Yes |
| p95 latency adversarial | < 50ms | Yes |
| Throughput | >= 50 RPS @ 4 vCPU/8GB | Soft (tracked, not CI-gated) |

Hard stop = PR cannot merge until threshold is restored.

## Interpreting deltas

When `evals/history/` contains a previous report, compute per-metric deltas:
- Recall regression of any magnitude → Blocker (even if above threshold — indicates flakiness)
- FP rate increase > 0.5pp → Warning
- Latency p95 increase > 5ms → Warning; > 10ms → Blocker

## Baseline comparison

The adversarial recall baseline is the score of plain Llama Guard 3 8B on the same corpus with no Guardian-BR wrapping. Baseline stored in `evals/baselines/llama_guard_baseline.json`. If absent, report absolute score only and note that the baseline is not established.
