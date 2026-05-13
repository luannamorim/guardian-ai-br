---
name: lgpd-rule-add
description: Walk through adding a new PII recognizer to Guardian-BR end-to-end, ensuring recognizer, LGPD mapping, corpus annotation, metrics, dashboard, and regression test all land in the same PR.
disable-model-invocation: true
---

# LGPD Rule Add

Adding a new PII recognizer is cross-cutting across 6 files in Guardian-BR. This skill walks through the checklist so nothing ships without its LGPD mapping, corpus coverage, and dashboard support.

## When to use

Invoke /lgpd-rule-add when adding a new Brazilian identifier (passaporte, cartao SUS, etc.) or a new format variant for an existing one. Not for adversarial, redact store, KMS, or API changes.

## Checklist

### 1. Recognizer code

File: src/guardian_br/pii/recognizers/<type>.py

Use the PatternRecognizer base class from Presidio. Import regex (not stdlib re). Implement validate_result(self, pattern_text: str) -> bool with the checksum algorithm for the identifier type. Returning False for a checksum failure is mandatory — the security-reviewer agent flags any missing validation as a Blocker.

### 2. LGPD mapping

File: lgpd_mapping.yaml

Add an entry for BR_<TYPE> with: description, lgpd_article (Art. 5 I for personal data, Art. 5 II for sensitive), sensitivity level, applicable Art. 7 purpose bases, and any retention note. The lgpd_coverage eval check fails without this entry.

### 3. Corpus annotation

File: evals/pii_corpus.jsonl (append)

Minimum: 5 positive examples (valid format + passing checksum), 3 negative examples (failing checksum or near-miss format), 2 in-sentence examples (realistic customer service message context). Each line: {"text": "...", "labels": [{"type": "BR_<TYPE>", "start": N, "end": M}]}. Negatives use "labels": [].

### 4. Prometheus metric label

File: src/guardian_br/core/metrics.py

Add "BR_<TYPE>" to the ENTITY_TYPES list so per-type detection counters and latency histograms include the new type.

### 5. Dashboard category

File: src/guardian_br/dashboard/app.py (or its category config dict)

Register the new entity type with a display label and color so it appears in the violations breakdown.

### 6. Regression test

File: tests/pii/test_<type>_recognizer.py

Write parametrized pytest cases covering: valid detection, invalid checksum rejection, near-miss format rejection. Run with: uv run pytest tests/pii/test_<type>_recognizer.py -v

## Done when

- [ ] Recognizer file with validate_result implemented
- [ ] lgpd_mapping.yaml entry present
- [ ] Corpus has 10+ annotated examples (5+ positive, 3+ negative, 2+ in-sentence)
- [ ] Prometheus label registered
- [ ] Dashboard category added
- [ ] Regression test passes
- [ ] Eval subset passes: make eval-quick CATEGORY=<type>
- [ ] security-reviewer run with no Blockers
