# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Guardian-BR

Brazilian-focused LLM guardrails layer: detects and masks BR PII (CPF, CNPJ, RG, CNH, título de eleitor, PIS), classifies PT-BR adversarial prompts, and maps every guardrail to its LGPD article. Distributed as a `pip install` library and a Docker REST API sidecar. See [`SPEC.md`](./SPEC.md) for the full product specification.

## Stack

- Language: Python 3.11
- Package manager: `uv`
- Test runner: `pytest`
- Linter / formatter: `ruff` + `mypy`
- PII engine: Microsoft Presidio + custom BR recognizers
- Safety classifier: Llama Guard 3 8B Q4_K_M via Ollama
- API framework: FastAPI + Pydantic v2
- Dashboard: Streamlit
- Observability: OpenTelemetry + Prometheus

## Tooling already wired

- `/commit`, `/commit-push-pr`, `/clean_gone` come from the `commit-commands` plugin — don't generate a local commit script.
- `context7` MCP is enabled for live library docs (Presidio, FastAPI, Pydantic). Prefer it over WebSearch for SDK questions.
- `security-guidance` plugin is enabled; consult before introducing new auth / KMS / secrets handling.
- Custom local agents: `security-reviewer`, `eval-impact-analyzer`. Custom local skills: `eval-runner` (model-invocable), `lgpd-rule-add` (user-only via `/lgpd-rule-add`).
- Hooks: PreToolUse blocks writes to `.env`/`secrets/`/`*.pem`/`*.key`; PostToolUse runs `ruff format` + `ruff check --fix` on edited Python files.

## Key commands

```bash
uv sync                                          # install deps (dev extras)
uv run pytest                                    # run full test suite
uv run pytest -q -x                             # fast: stop on first failure
uv run pytest tests/pii/test_cpf_recognizer.py -v   # single test file
uv run pytest -k "cpf" -v                       # filter by name
uv run uvicorn guardian_br.api.app:app --reload  # API dev mode (no Docker)
uv run ruff check .                             # lint
uv run ruff format .                            # format
uv run mypy src/                                # type-check
make eval CORPUS=evals/pii_corpus.jsonl         # full eval (slow, ≥30s)
make eval-quick CATEGORY=cpf                    # fast subset for inner loop
docker compose up guardian-br                   # start API sidecar
ollama pull llama-guard3:8b                     # pull safety model (~5GB)
```

## Conventions (apply when code lands)

> Project is pre-implementation as of 2026-05-13. Rules below are SPEC-derived and must be enforced as soon as the corresponding modules exist. The `security-reviewer` agent encodes the same rules for diff review.

- All public schemas live in `guardian_br.core.schemas`. Breaking schema changes require a major version bump and a deprecation notice in the PR description.
- PII recognizers **must** validate checksums (CPF mod-11, CNPJ mod-11, CNH, PIS) before emitting a detection. A regex match that fails checksum is not a detection — silence it.
- Every new PII type **must** have a corresponding entry in `lgpd_mapping.yaml` before the PR can merge. Use `/lgpd-rule-add` to walk the checklist.
- Reversible-redact handles are opaque UUIDs — never JWTs or any format that leaks type or length information. See SPEC §Resolved Decisions #6.
- Use the `regex` library (not stdlib `re`) for **all** recognizer and caller-supplied patterns. Stdlib `re` has no backtrack timeout; `regex` supports `timeout=`. ReDoS is a denial-of-service vector in a guardrails product.
- Use `secrets.compare_digest` for every token/key comparison (constant-time). Plain `==` on API keys is not acceptable.
- The audit log stores salted hashes of detections — raw PII must never appear in any log row. Any `logger.*` or `print(` call inside a PII-handling code path is a bug; flag it in review.

## Gotchas

- **Llama Guard cold start > 2s.** The `/healthz` readiness probe blocks until the model is warm. Do not write tests that race a cold container — always wait for the probe.
- **Audit log writes are synchronous on the request thread; fallback to JSONL file when store is unreachable.** Override via `app.state.auditor` in tests — pass a `_DisabledAuditor()` to avoid file I/O in unit tests.
- **`/v1/audit` requires `audit:read` scope.** Extend API-key format: `sha256:<hex>:audit:read` (comma-separated scopes after the hash). Scan/unmask keys (no suffix) never grant this scope.
- **Dashboard reads `/v1/audit` over HTTP**, not the local SQLite file — set `GUARDIAN_BR_DASHBOARD_API_KEY` to a key whose hash in `GUARDIAN_BR_API_KEYS_HASHED` carries the `:audit:read` suffix. A scan-only key returns 403 in the UI.
- **Adversarial unit tests use `httpx.MockTransport`; real Ollama integration tests gated by `OLLAMA_INTEGRATION=1`.** The `OllamaClassifier` accepts an injected `_client` attribute for testing — never hit a real daemon in CI.
- **`regex.compile()` does not accept `timeout=`** — pass `timeout=` to the `.match()` / `.search()` / `.findall()` call, not to `compile()`. The module constant `_TIMEOUT_S = 0.05` lives near the match site.
- **`RedactStore` Protocol contract suite is authoritative.** Adapter packages (`guardrails-br-postgres`, `guardrails-br-redis`) must pass the full contract test suite in `tests/redact_store/`. There is no partial compliance.
- **OTel traces are no-ops when `GUARDIAN_BR_OTLP_ENDPOINT` is unset.** `opentelemetry-api` is in base deps (ultra-lightweight, no-op by default); the SDK + OTLP exporter are in the `[api]` extra. `FastAPIInstrumentor` is installed unconditionally in `create_app()` but emits nothing without a configured provider.
- **`make eval` is slow (≥30s on CPU).** Use `make eval-quick CATEGORY=<name>` during development. Run the full suite before opening a PR via `/eval`.
- **Reclame Aqui was dropped as a corpus source.** Primary source is Consumidor.gov.br (Decreto 8.573/2015, federal public data) + CGU ouvidoria + C-ORAL-BRASIL. RA may be referenced only for stylistic inspiration when generating synthetic data — never republished verbatim. See SPEC §Resolved Decisions #3.
- **PyPI package family: `guardrails-br-*`** (core: `guardrails-br`; adapters: `guardrails-br-postgres`, `guardrails-br-redis`; extras: `guardrails-br[aws]`, `guardrails-br[gcp]`, `guardrails-br[dashboard]`). "Guardian-BR" is the human-readable brand only. See SPEC §Resolved Decisions #1.

## Layout

```
guardian-ai-br/
├── src/
│   └── guardian_br/
│       ├── core/           # schemas, entities
│       ├── data/           # lgpd_mapping.yaml (packaged into wheel)
│       ├── pii/            # Presidio recognizers for BR identifiers
│       │   └── recognizers/
│       ├── lgpd/           # LGPD mapping loader
│       ├── eval/           # benchmark runner (make eval / make eval-quick)
│       ├── adversarial/    # Llama Guard wrapper + PT-BR classifier
│       ├── api/            # FastAPI app, routes, auth dependency
│       ├── dashboard/      # Streamlit dashboard (guardrails-br[dashboard])
│       └── prompts/        # prompt files for Llama Guard context
├── tests/
│   ├── redact_store/       # RedactStore Protocol contract suite
│   ├── pii/
│   └── adversarial/
├── evals/
│   ├── pii_corpus.jsonl
│   ├── adversarial_corpus.jsonl
│   └── history/            # previous eval_report.md snapshots
├── docs/
│   ├── ARCHITECTURE.md     # [to be written]
│   └── LGPD_MAPPING.md     # [to be written]
├── Makefile
├── docker-compose.yml
├── pyproject.toml
├── SPEC.md
└── CLAUDE.md               # this file
```

## Architecture

`guardian_br.core` is the single source of truth. The pip library exposes it directly; the Docker container wraps it in FastAPI. The benchmark suite imports the same core — published eval numbers come from the exact code users run.

**Request flow (happy path):**
1. Caller → `Guardian.scan(text)` (library) or `POST /v1/scan` (REST)
2. `core.pii` runs Presidio + BR recognizers synchronously (~5-15ms). Checksum failures are silenced before the result propagates.
3. If mode includes adversarial classification, `core.adversarial` calls Ollama (Llama Guard 3 8B Q4) — the slow path (~35ms warm, >2s cold).
4. `core.audit_log` appends a row to the `RedactStore` backend (salted hashes only, never raw PII).
5. If `REVERSIBLE_REDACT`: `core.kms` wraps a fresh DEK, `core.redact_store` persists the encrypted original, returns a UUID handle.

**Protocol extension points** (all defined in `guardian_br.core`):
- `RedactStore` — `put / get / delete / query_audit`. SQLite impl in core (dev/CI default); `guardrails-br-postgres` and `guardrails-br-redis` are separate packages that pass the contract-test suite in `tests/redact_store/`.
- `KMSProvider` — `wrap(dek) / unwrap(wrapped_dek)`. `env` and `file` impls in core; `aws_kms`/`gcp_kms` as v1.0 optional extras; `vault` in v1.1.
- `Principal` resolver — a FastAPI `Depends` callable. Override via `app.dependency_overrides[get_principal]` to plug in JWT/OIDC without forking.

Adapter packages never live in core; core stays slim and importable without cloud SDKs.

## References

- Specification: [`SPEC.md`](./SPEC.md)
- Architecture: [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) (to be written)
- LGPD mapping: [`docs/LGPD_MAPPING.md`](./docs/LGPD_MAPPING.md) (to be written)
- Eval corpus: `evals/pii_corpus.jsonl` + `evals/adversarial_corpus.jsonl`
