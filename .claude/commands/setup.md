# /setup

Walk through Day-1 environment setup: Python deps, Ollama, Llama Guard model, SQLite redact store, and a smoke test of the full pipeline.

## When to use

- First time cloning this repo on a new machine
- After a major dependency update to verify the full stack still works
- When a teammate reports stack issues — run this to diagnose where it breaks

## What I'll do

1. **Verify Python 3.11+** — stop with instructions if older.

2. **Install dependencies.**
   ```
   uv sync
   ```
   Fall back to `pip install -e ".[dev]"` if `uv` is not installed.

3. **Check Ollama** — if not installed, surface OS-specific instructions (do not auto-install).

4. **Pull Llama Guard 3 8B** (~5GB — ask before pulling).
   ```
   ollama pull llama-guard3:8b
   ```

5. **Initialize the SQLite redact store.**
   ```
   python -m guardian_br.core.redact_store init
   ```
   Skip gracefully if the module is not yet importable.

6. **Smoke-test the install.**
   ```
   uv run pytest -q --tb=short
   ```

7. **Smoke-test the full pipeline.**
   ```
   make eval-quick CATEGORY=cpf
   ```
   Validates PII detection + Llama Guard + redact store end-to-end.

## Output

```
Python 3.11.9     OK
uv sync           OK  (47 packages)
Ollama 0.3.12     OK
llama-guard3:8b   OK  (pulled)
redact.db         OK  (initialized)
pytest            OK  (0 failures)
eval-quick cpf    OK  (recall 100%, p95 42ms)

Setup complete. Run: docker compose up guardian-br
```

## Notes

- `settings.json` does NOT auto-approve `ollama pull` — you'll see a permission prompt. Promote `Bash(ollama:*)` to `settings.local.json` if you want it silent going forward.
- The SQLite redact store lives at `.guardian_br/redact.db` by default (gitignored). Override via `GUARDIAN_REDACT_STORE_URL`.
- Postgres adapter setup: `pip install guardrails-br-postgres` — not in core extras.
