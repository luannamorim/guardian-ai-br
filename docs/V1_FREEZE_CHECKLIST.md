# Guardian-BR — V1 freeze checklist

> Handoff doc. Read this if you're picking up the project on a new
> machine and the user asks "o projeto está pronto?". The SPEC's 14
> FRs are implemented and tested (PR1–PR13 on `main`), but several
> SPEC §Success Criteria still need empirical validation before a
> v1 freeze can be claimed. Each item below is independently
> committable.

State as of last update (commit `25e6c82` — PR13 / docs/alerts.md):

- 512 tests pass; `ruff check` and `mypy src/` clean
- PII gate (`make eval-gate`) green at 100% recall on the *current*
  corpus
- Adversarial path runs but is gated off in CI (Ollama not present)

## Open items

### 1. Expand `evals/pii_corpus.jsonl` to ~500 rows (SPEC §Eval Strategy)

**Why it matters.** SPEC promises "500 PT-BR customer-service messages,
register-matched to real CS interactions." `wc -l evals/pii_corpus.jsonl`
is 61 today — the recall claim ("100% on a 500-message corpus") is not
yet provable.

**Acceptance:**
- `wc -l evals/pii_corpus.jsonl` ≥ 480
- Each category (`cpf`, `cnpj`, `pis`, `cnh`, `titulo_eleitor`, `rg`) has
  ≥ 40 positive rows + ≥ 20 negatives with non-PII numbers that look
  like identifiers (phone numbers, order IDs, dates)
- `make eval-gate` (default `--min-pii-recall 0.99`) still green
- Sources documented in `evals/README.md` (Consumidor.gov.br + CGU +
  C-ORAL-BRASIL, per SPEC §Resolved Decisions #3 — no Reclame Aqui)

**Tooling.** The `eval-impact-analyzer` agent can surface coverage gaps
once new rows land. The `/lgpd-rule-add` skill is for new rule types,
not for expanding corpora — corpus rows are pure data.

### 2. Latency benchmark on `m6i.xlarge`-class hardware (SPEC §Success Criteria)

**Why it matters.** SPEC: "p95 < 15ms (PII only), p95 < 50ms (PII +
adversarial)" — explicit target "to be validated by benchmark on
`m6i.xlarge`-class hardware before v1 freeze." Today there are no
recorded numbers from comparable hardware.

**Acceptance:**
- `eval_report.md` from a single run on 4 vCPU / 8GB RAM host shows
  p95 PII < 15ms and p95 PII+adv < 50ms (warm)
- Cold-start latency (`guardian_ollama_cold_start_seconds`) recorded
  separately — does **not** gate the SLO per SPEC §Resolved Decisions #2
- Snapshot archived under `evals/history/` so the number is greppable

**Fallback path.** If warm p95 > 50ms, SPEC §Resolved Decisions #2 says
the default adversarial path downgrades to embedding-similarity (m-e5-small)
and Llama Guard becomes opt-in via config. That code path does *not*
exist yet — add it under `adversarial/` only if the benchmark forces it.

### 3. Throughput benchmark — sustained 50 RPS on single container

**Why it matters.** SPEC §Non-Functional Requirements. Without numbers,
the "drop-in sidecar" pitch is unverified.

**Acceptance:**
- A short Locust/`wrk`/`vegeta` script lives at `scripts/load_test.*`
  (pick one tool; commit the harness)
- README documents how to reproduce
- `eval_report.md` or a sibling report includes the achieved RPS and
  the latency profile at that RPS

### 4. Adapter packages: `guardrails-br-postgres`, `guardrails-br-redis`

**Why it matters.** SPEC explicitly treats these as *separate optional
packages*, so they are not strictly v1 core blockers. But the
"production audit retention (LGPD Art. 37)" narrative requires Postgres,
and DPOs will ask. Status today: zero — only the SQLite impl in core
exists.

**Acceptance:**
- A new sibling package directory (could be a sibling repo, or a
  `packages/` subtree inside this repo with its own `pyproject.toml`)
- Implements `RedactStore` from `guardian_br.core.redact_store`
- Passes the full contract suite in `tests/redact_store/contract.py`
  (re-used unchanged — no fork)
- Published under `guardrails-br-postgres` on PyPI (or at least
  buildable: `uv build` clean)

Same shape for the Redis adapter (short-TTL hot mapping cache).

### 5. KMS extras: `guardrails-br[aws]`, `guardrails-br[gcp]`

**Why it matters.** SPEC §Resolved Decisions #7: v1.0 extras. AWS and
GCP dominate the BR fintech market; today `core/kms.py` only ships
`EnvKMSProvider` and `FileKMSProvider`.

**Acceptance:**
- `[aws]` extra in `pyproject.toml` pulls `boto3`; provides
  `AWSKMSProvider` wrapping `GenerateDataKey` / `Decrypt`
- `[gcp]` extra pulls `google-cloud-kms`; provides `GCPKMSProvider`
  with the equivalent ops
- Each impl wired into a thin integration test using `moto` (AWS) and
  GCP's emulator (or fakes) — full credentials are not required in CI
- KEK rotation path tested: a new wrap uses the new key version while
  unwraps with the old version still succeed

Vault is v1.1 per SPEC and stays out of scope.

### 6. Manual smoke of the Streamlit dashboard

**Why it matters.** Unit tests cover aggregation and the HTTP client.
The actual rendered UI has no tests. Regressions in `dashboard/app.py`
or `dashboard/charts.py` can ship green.

**Acceptance:**
- Start the API + dashboard via `docker compose up`, point dashboard at
  the API with a valid `audit:read` key
- Verify: violations-over-time chart renders, PII-type breakdown shows
  detected types, LGPD-article breakdown is populated, top-adversarial-
  categories panel handles the empty-state cleanly
- A short screencast or screenshot lives under `docs/screenshots/`
  (referenced from README) so contributors have a reference image

## What v1 freeze means

Once items 1–3 are done with reproducible artifacts, the SPEC's
"published numbers come from the exact code users run" claim is
genuine. Items 4–5 are blockers only if the project is positioning
itself for fintech adoption out-of-the-gate; for a portfolio v1 they
can ship as v1.1. Item 6 is cheap enough to do immediately on any
machine that has Docker.

## Notes for the next LLM picking this up

- The `eval-impact-analyzer` agent is wired in `.claude/` — use it
  before touching recognizers or expanding the corpus to predict the
  regression surface.
- `/eval` runs the full benchmark; `make eval-quick CATEGORY=<name>`
  is the inner-loop equivalent.
- The `security-reviewer` agent is the gate for diffs touching PII,
  KMS, auth, audit, or rate limiting — invoke it before opening a PR
  that touches any of those.
- Commits in this project follow `feat:` / `docs:` / `ci:` / `fix:`
  prefixes with a single short summary line and a `PR<N>` tag in the
  parenthetical. See `git log --oneline` for the existing pattern.
