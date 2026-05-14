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

## Status

`v0.1.0` — CPF detection only. CNPJ, RG, CNH, título de eleitor, PIS, REST API, and adversarial classification are in progress.

See [SPEC.md](SPEC.md) for the full product specification.
