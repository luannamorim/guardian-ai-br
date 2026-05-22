# Guardian-BR

Brazilian LLM guardrails: detects and masks BR PII (CPF, CNPJ, RG, CNH, título de eleitor, PIS), classifies PT-BR adversarial prompts, and maps every guardrail to its LGPD article.

Distributed as `pip install guardrails-br` and a Docker REST API sidecar.

## Quick start

```bash
pip install guardrails-br
python -m spacy download en_core_web_sm   # NLP backend
```

```python
from guardian_br import Guardian

result = Guardian().scan("meu cpf eh 123.456.789-09, pode ajudar?")
print(result.redacted_text)
# → "meu cpf eh <BR_CPF>, pode ajudar?"
print(result.detections[0].lgpd_article)
# → "Art. 5º, I"
```

## REST API

```bash
# Generate keys
SCAN_KEY=my-scan-key
AUDIT_KEY=my-audit-key
SCAN_HASH=$(echo -n "$SCAN_KEY" | sha256sum | cut -d' ' -f1)
AUDIT_HASH=$(echo -n "$AUDIT_KEY" | sha256sum | cut -d' ' -f1)

export GUARDIAN_BR_API_KEYS_HASHED="sha256:$SCAN_HASH,sha256:$AUDIT_HASH:audit:read"
export GUARDIAN_BR_AUDIT_SALT="$(python -c 'import base64,secrets;print(base64.b64encode(secrets.token_bytes(32)).decode())')"

uv run uvicorn guardian_br.api.app:app --port 8000
```

```bash
# Scan text
curl -s -X POST http://localhost:8000/v1/scan \
  -H "X-API-Key: $SCAN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"meu cpf eh 123.456.789-09"}' | jq '.detections[].entity_type'

# Query the audit log (requires audit:read scope)
curl -s -H "X-API-Key: $AUDIT_KEY" \
  "http://localhost:8000/v1/audit?limit=10" | jq '.rows[].event_type'
```

### Audit log

Every scan, unmask, and auth failure produces an append-only audit row in SQLite. Rows store a salted HMAC-SHA256 hash of the input — never raw PII.

**Salt rotation:** `GUARDIAN_BR_AUDIT_SALT` identifies rows via `salt_key_id`. Old rows are still queryable after rotation but their `input_hash` is only verifiable with the original salt.

**HMAC chain:** Set `GUARDIAN_BR_AUDIT_HMAC_CHAIN=true` (default in Docker) and `GUARDIAN_BR_AUDIT_HMAC_SECRET` to enable per-row tamper detection. Requires single-worker deployment (SQLite is single-writer; chain is serialized per-process).

**Fallback file:** When SQLite is unreachable, rows are appended to `~/.guardian_br/audit_fallback.jsonl` (override with `GUARDIAN_BR_AUDIT_FALLBACK_PATH`). Re-ingest with `guardian-br audit replay <file>` (future CLI).

### API key scopes

| Key format | Grants access to |
|---|---|
| `sha256:<hex>` | `/v1/scan`, `/v1/unmask` |
| `sha256:<hex>:audit:read` | `/v1/audit` (also scan/unmask) |

## Custom recognizers

Register company-specific identifiers without subclassing Presidio:

```python
from guardian_br import Guardian, CustomRecognizerSpec

spec = CustomRecognizerSpec(
    entity_type="ACME_ACCOUNT",
    patterns=[r"ACME-\d{6}"],
    context=["conta", "account"],
    lgpd_article="Art. 5º, I",
)
g = Guardian(custom_recognizers=[spec])
g.scan("minha conta ACME-123456").redacted_text
# → "minha conta <ACME_ACCOUNT>"
```

Patterns are compiled with the `regex` library and inherit Guardian-BR's
ReDoS backtrack timeout. An optional `validator` callable gates emissions
(e.g. a company-internal checksum).

## Dashboard

Streamlit dashboard showing violations over time, by PII type, by LGPD article, and top adversarial categories.

```bash
pip install 'guardrails-br[dashboard]'

# Point at the running API (must have an audit:read key)
export GUARDIAN_BR_DASHBOARD_API_URL=http://localhost:8000
export GUARDIAN_BR_DASHBOARD_API_KEY=<your-audit-key>

guardian-br-dashboard   # opens http://localhost:8501
```

Or via Docker Compose alongside the API:

```bash
docker compose up guardian-br-dashboard
# opens http://localhost:8501
```

The dashboard reads `/v1/audit` over HTTP. `GUARDIAN_BR_DASHBOARD_API_KEY` must be a key whose hash in `GUARDIAN_BR_API_KEYS_HASHED` carries the `:audit:read` suffix (format: `sha256:<hash>:audit:read`).

## Status

`v0.1.0` — CPF, CNPJ, RG, CNH, título de eleitor, and PIS detection; reversible redact; adversarial classification; audit log persistence.

See [SPEC.md](SPEC.md) for the full product specification.
