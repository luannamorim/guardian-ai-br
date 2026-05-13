# /eval

Run Guardian-BR's benchmark suite and surface results against SPEC thresholds before opening a PR.

## When to use

- Before opening a PR that touches PII recognizers, the adversarial classifier, the redact pipeline, or anything in `guardian_br.core`
- When asked "how are we doing on PII recall?" or "did this change break anything in eval?"
- After a corpus annotation batch to verify new examples are correctly handled

## What I'll do

1. **Detect corpus paths.** Default: `evals/pii_corpus.jsonl` + `evals/adversarial_corpus.jsonl`. Honor a `CORPUS=<path>` argument if provided.

2. **Run the eval suite.**
   ```
   make eval CORPUS=<path>
   ```
   Warn if `make` or the corpus file is not found — and surface the exact error so you can fix it.

3. **Read `eval_report.md`.** Parse the current run's output. If a previous report exists in `evals/history/`, load it for delta comparison.

4. **Surface results per SPEC thresholds:**

   | Metric | SPEC target | Result | Status |
   |--------|-------------|--------|--------|
   | PII recall (per category) | 100% | — | — |
   | False positive rate | < 2% | — | — |
   | Adversarial recall | ≥ Llama Guard baseline + 10pp | — | — |
   | Adversarial precision | ≥ 0.90 | — | — |
   | p95 latency (PII + adversarial) | < 50ms | — | — |

5. **Flag SPEC breaches** as blockers — any metric below threshold is a hard stop, not a warning.

6. **Show delta vs. previous run** for each metric (↑ / ↓ / →). A regression in recall is always a blocker even if still above threshold.

## Output

```
Eval run: 2026-05-14T10:23:44
Corpus: evals/pii_corpus.jsonl (500 messages) + evals/adversarial_corpus.jsonl (200 cases)

PII recall
  CPF          100.0%  ✅  (→ no change)
  CNPJ         100.0%  ✅  (↑ +2.1pp from 97.9%)
  CNH           98.0%  ❌  BREACH — target 100%
  ...

False positives:  1.4%  ✅  (↓ -0.3pp)
Adversarial recall: 73.2%  ✅  (+12.1pp over baseline)
Adversarial precision: 0.91  ✅
p95 latency:  48ms  ✅  (↑ +3ms)

❌ 1 SPEC breach — do not open PR until CNH recall reaches 100%.
```

## Notes

- For inner-loop iteration use `make eval-quick CATEGORY=<name>` — it runs a subset and is much faster.
- The eval suite requires Ollama + Llama Guard to be running. If Ollama is down, the adversarial section will fail with a connection error.
- Corpus files are in `evals/` — annotate new messages there, not inline.
