# Guardian-BR — Architecture

> One core, one wire format, pluggable everywhere it matters.

This document describes how Guardian-BR is laid out and why. It is the
companion to [`SPEC.md`](../SPEC.md): the spec says *what* and *why*,
this document says *where it lives* and *how the pieces talk*.

## 1. Distribution shape

Guardian-BR ships in two forms that share the same `guardian_br.core`:

| Surface              | Package                          | When to use                                              |
|----------------------|----------------------------------|----------------------------------------------------------|
| Python library       | `pip install guardrails-br`      | Embed inside an existing Python app, no extra process    |
| REST API sidecar     | `docker run … guardrails-br`     | Sit in front of a chatbot in any language, drop-in       |
| Streamlit dashboard  | `guardrails-br[dashboard]` extra | Visualize audit log violations + LGPD article coverage   |
| Adapter packages     | `guardrails-br-postgres`/`-redis` | Production audit retention / hot mapping cache          |

The PyPI family is `guardrails-br-*`; "Guardian-BR" is the human-readable
brand. See SPEC §Resolved Decisions #1.

## 2. Source layout

```
src/guardian_br/
├── core/           Schemas, modes, KMS protocol, RedactStore protocol, auditor
│   ├── adversarial.py        AdversarialClassifier protocol + result types
│   ├── audit_chain.py        HMAC chain helpers for append-only tamper detection
│   ├── audit_fallback.py     JSONL fallback writer when the store is unreachable
│   ├── auditor.py            Orchestrates per-scan audit persistence
│   ├── crypto.py             AES-256-GCM envelope (DEK cache + encrypt/decrypt)
│   ├── kms.py                KMSProvider protocol + env/file impls
│   ├── modes.py              Mode enum (BLOCK / REDACT / REVERSIBLE_REDACT)
│   ├── redact_store.py       RedactStore protocol + RedactRecord/AuditRow
│   ├── schemas.py            Detection + ScanResult (versioned Pydantic)
│   └── sqlite_redact_store.py  SQLite impl of RedactStore (zero-config default)
├── data/lgpd_mapping.yaml  Per-entity LGPD article references (packaged in wheel)
├── pii/
│   ├── custom.py             CustomRecognizerSpec (FR 12)
│   ├── registry.py           Presidio AnalyzerEngine assembly
│   └── recognizers/          CPF/CNPJ/CNH/PIS/título/RG + ChecksumValidatedRecognizer base
├── lgpd/loader.py            Strongly-typed LGPDMapping loader
├── adversarial/              Ollama + Llama Guard 3 wrapper, PT-BR prompt loader
├── eval/                     Benchmark runner, baselines, CI gate
├── api/                      FastAPI app, routes, auth, settings, telemetry
├── dashboard/                Streamlit app (audit-log over HTTP)
├── prompts/                  Versioned Llama Guard prompts (PT-BR + plain)
└── guardian.py               The Guardian facade: scan / unmask
```

`guardian_br.core` is the single source of truth. The library exposes it
directly; the REST container wraps it in FastAPI; the benchmark suite
imports the same code so published numbers are produced by the exact
modules users run.

## 3. Request flow (happy path)

```
Caller ─► Guardian.scan(text)                         (library)
         │  or POST /v1/scan                          (REST)
         ▼
   ┌────────────────────────────────────────────┐
   │ guardian_br.core                           │
   │  1. pii: Presidio + BR recognizers (~5-15ms)│
   │     - checksum-fail matches are silenced   │
   │  2. adversarial: Llama Guard (~35ms warm)  │
   │     - skipped if skip_adversarial=true     │
   │  3. audit_log: salted-hash row append      │
   │     - SQLite default; pluggable adapter    │
   │  4. if REVERSIBLE_REDACT:                  │
   │     kms.wrap(dek) → store encrypted span   │
   │     → return UUIDv4 handle                 │
   └────────────────────────────────────────────┘
         ▼
   ScanResult (frozen Pydantic, schema-versioned)
```

Three operating modes:

- `BLOCK` — raise `BlockedError` (HTTP 422) on any PII or unsafe content
- `REDACT` — replace each detection with `<ENTITY_TYPE>`
- `REVERSIBLE_REDACT` — replace with `<RDX:{handle}>`, store the AES-256-GCM
  ciphertext, expose `unmask(handle)` to recover the original

`shadow_mode` short-circuits the `raise` in BLOCK mode and records
`would_block=True` in the audit log for safe rollout (SPEC FR 14).

## 4. Extension points (Protocols)

All protocols live in `guardian_br.core` so adapters import from there,
not from each other.

### 4.1 `RedactStore`

Defined in `core/redact_store.py`. Methods: `put / get / delete / ping /
append_audit / query_audit`. Implementations:

- **`SQLiteRedactStore`** (`core/sqlite_redact_store.py`) — in-core,
  zero-config, dev/CI default. WAL journal mode for concurrent reads.
- **`guardrails-br-postgres`** (separate package) — production audit
  retention (LGPD Art. 37).
- **`guardrails-br-redis`** (separate package) — short-TTL hot mapping.

All adapters must pass the contract suite in `tests/redact_store/contract.py`.
There is no partial compliance — every Protocol method has a contract test.

### 4.2 `KMSProvider`

Defined in `core/kms.py`. Methods: `wrap(dek) → WrappedDEK`,
`unwrap(wrapped_dek) → bytes`, `current_key_id() → str`.

| Impl             | Package             | Status                |
|------------------|---------------------|-----------------------|
| `EnvKMSProvider` | core                | v1.0 — dev/CI default |
| `FileKMSProvider`| core                | v1.0                  |
| `AWSKMSProvider` | `guardrails-br[aws]` | v1.0 extra            |
| `GCPKMSProvider` | `guardrails-br[gcp]` | v1.0 extra            |
| `VaultKMSProvider`| TBD                 | v1.1                  |

Envelope encryption is applied at the store-agnostic layer: a per-record
DEK encrypts the original value; the DEK is wrapped by the KEK. KEK
rotation does not require re-encrypting historical DEKs (new DEKs use
the new KEK; old DEKs remain decryptable while the old key version is
reachable).

### 4.3 `Principal` resolver

A FastAPI `Depends` callable defined in `api/auth.py`. The default
validates static `X-API-Key` headers against `GUARDIAN_BR_API_KEYS_HASHED`
using `secrets.compare_digest` and supports comma-separated active keys
for zero-downtime rotation. Production users override via:

```python
app.dependency_overrides[get_principal] = my_jwt_validator
```

See `examples/jwt_auth.py` for a worked example. The override pattern is
documented by SPEC FR 6 — no fork required.

### 4.4 `CustomRecognizerSpec`

Defined in `pii/custom.py`. Pydantic-typed declaration of company-specific
identifiers (e.g. internal account numbers). Patterns are compiled by the
`regex` library and inherit the ReDoS backtrack timeout; optional
validators gate match emissions; an optional `lgpd_article` references a
specific article in `Detection.lgpd_article`.

## 5. Schemas

Public schemas live in `core/schemas.py` and `core/redact_store.py`. They
are frozen Pydantic models. The wire format is versioned via
`SCHEMA_VERSION`; breaking changes require a major version bump per SPEC.

| Schema           | Fields                                                                              |
|------------------|-------------------------------------------------------------------------------------|
| `Detection`      | `entity_type, start, end, score, lgpd_article, redact_token`                        |
| `ScanResult`     | `schema_version, mode, blocked, shadow, would_block, text, detections, redacted_text, adversarial` |
| `AuditRow`       | `id, timestamp, event_type, principal_id, input_hash, mode, detections, blocked, would_block, …` |
| `LGPDRule`       | `description, sensitivity, lgpd_articles, art7_purpose_bases, retention_note, notes` |

## 6. Audit log

Every scan/unmask/auth-failure produces an append-only row. The audit
store **never** holds raw PII — only salted HMAC-SHA256 hashes of input,
plus the detection types and LGPD articles. Logging policy is enforced
by `tests/redact_store/test_no_raw_pii_logged.py`.

- **Salt rotation** is supported via `salt_key_id`: old rows are still
  queryable but only verifiable with the original salt.
- **HMAC chain** (`GUARDIAN_BR_AUDIT_HMAC_CHAIN=true`) gives per-row
  tamper detection. Single-writer only — chain is serialized per-process.
- **Fallback** to a JSONL file when the store is unreachable
  (`~/.guardian_br/audit_fallback.jsonl`), with a Prometheus counter
  `guardian_audit_log_fallback_total` for alerting.

## 7. Observability

- **Traces** — every `scan` opens a span via `opentelemetry-api`. The
  SDK + OTLP exporter live in the `[api]` extra and are no-ops unless
  `GUARDIAN_BR_OTLP_ENDPOINT` is set. `FastAPIInstrumentor` is always
  installed but emits nothing without a provider.
- **Metrics** — `api/metrics.py` defines a `CollectorRegistry` exposed
  at `/v1/metrics`. Includes per-mode scan counts (with `shadow_block`
  outcome), per-entity detection counts paired with LGPD article,
  adversarial labels, audit-log writes, fallback activations, and
  Llama Guard cold-start time.
- **Dashboard** — Streamlit (`guardrails-br[dashboard]`) reads
  `/v1/audit` over HTTP, never the local SQLite file directly.

## 8. Benchmark suite

The eval runner lives in `eval/runner.py`. It supports two corpus
shapes (PII and adversarial) detected by row schema, accepts arbitrary
CSV/JSONL via `--corpus`, and can compare Guardian-BR against
`plain-presidio` (no BR recognizers) and `plain-llama-guard` (no PT-BR
primer prompt) via `--baselines`.

A CI gate (`eval/gate.py`) blocks PRs whose aggregate PII recall drops
below 99% on the published corpus.

## 9. Where new code goes

| Change                                         | Lives in                                                            |
|------------------------------------------------|---------------------------------------------------------------------|
| New BR identifier (e.g. RG-MG checksum variant) | `pii/recognizers/` + entry in `data/lgpd_mapping.yaml`             |
| Company-specific identifier (consumer code)    | NOT in core — register via `CustomRecognizerSpec` in caller code    |
| New audit backend (e.g. ClickHouse)            | New package, implement `RedactStore`, pass the contract suite       |
| New cloud KMS                                  | New package or extra, implement `KMSProvider`                       |
| Auth scheme (JWT, OIDC, mTLS)                  | Caller code, via `app.dependency_overrides[get_principal]`          |
| New eval dimension (e.g. multilingual)         | `eval/baselines.py` + a corresponding corpus under `evals/`         |
