# Guardian-BR Evaluation Corpus

License: CC-BY 4.0 — see `evals/LICENSE`.

## Line schema (`pii_corpus.jsonl`)

Each line is a JSON object:

```json
{
  "text": "the raw input string",
  "labels": [
    {"type": "BR_CPF", "start": 14, "end": 28}
  ],
  "category": "cpf"
}
```

- `labels` is an empty list for negative examples (text contains no PII).
- `start`/`end` are Python string slice indices (character-based, not byte-based).
- `category` matches the `--category` filter accepted by `make eval-quick`.

## Running

```bash
make eval-quick CATEGORY=cpf        # fast subset, writes eval_report.md
make eval CORPUS=evals/pii_corpus.jsonl   # full run with custom corpus path
```

Results land in `eval_report.md`; a timestamped snapshot is saved to
`evals/history/`.
