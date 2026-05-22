# Guardian-BR — Mapping to LGPD

> **Best-effort engineering interpretation — not a legal opinion.**
> This document and the underlying [`lgpd_mapping.yaml`](../src/guardian_br/data/lgpd_mapping.yaml)
> are a *technical correspondence* by an engineer between Guardian-BR's
> guardrail rules and articles of **Lei nº 13.709/2018 (LGPD)**. They
> have **not** been reviewed by ANPD and are not legal advice. Community
> legal review is welcome via GitHub issues — see SPEC §Resolved
> Decisions #5.

The machine-readable source of truth is `src/guardian_br/data/lgpd_mapping.yaml`,
shipped with the wheel and loaded by `guardian_br.lgpd.loader`. This
document is the human-readable rendering of the same data, suitable for
inclusion in a Relatório de Impacto à Proteção de Dados (RIPD) draft or
for a DPO's first read.

## How to read this

Each rule maps one detector (e.g. CPF) to:

- **Sensitivity** — `personal` for `dado pessoal` in Art. 5º I.
- **LGPD articles** — the article(s) the detector helps an operator
  comply with, each with a short clause-level pointer.
- **Art. 7º purpose bases** — the bases under which processing is
  *typically* lawful for the data type. Roman numerals follow LGPD's
  Art. 7º list (I = consent; V = legitimate interest; etc.).
- **Retention note** — operational guidance for handling raw values.
- **Notes** — Guardian-BR–specific behavior (checksum gate, emit-both
  policy, etc.) that a reviewer should know.

## Coverage table

| Detector            | Sensitivity | Primary article | Secondary article | Checksum |
|---------------------|-------------|-----------------|-------------------|----------|
| `BR_CPF`            | personal    | Art. 5º, I      | Art. 6º           | mod-11   |
| `BR_CNPJ`           | personal    | Art. 5º, I      | Art. 6º           | mod-11 × 2 |
| `BR_PIS` (PASEP/NIS)| personal    | Art. 5º, I      | Art. 6º           | mod-11   |
| `BR_CNH`            | personal    | Art. 5º, I      | Art. 6º           | mod-11 (DENATRAN) |
| `BR_TITULO_ELEITOR` | personal    | Art. 5º, I      | Art. 6º           | TSE      |
| `BR_RG` (SP only v1)| personal    | Art. 5º, I      | Art. 6º           | SSP/SP mod-11 |

All detectors share the Art. 7º bases `I` (consent) and `V` (legitimate
interest). Raw values must be masked in transit and never persisted in
application logs — `tests/redact_store/test_no_raw_pii_logged.py`
enforces this.

## Per-rule details

### `BR_CPF` — Cadastro de Pessoas Físicas

- **Articles:** Art. 5º, I (`dado pessoal`); Art. 6º (`princípio da
  minimização`).
- **Checksum:** mod-11 validation before emission. A regex-only match
  that fails checksum is silenced (no `Detection`).
- **Behavior:** Mathematically valid synthetic CPFs (`111.111.111-11`)
  *are* reported as PII — masking is content-blind by design (SPEC
  Failure Mode #2). Do not add a rejection rule for synthetic sequences.

### `BR_CNPJ` — Cadastro Nacional da Pessoa Jurídica

- **Articles:** Art. 5º, I (`dado pessoal (pessoa jurídica tratada como
  pessoal pelo controlador quando reidentifica titular)`); Art. 6º.
- **Checksum:** two-pass mod-11 (positions 12 and 13).
- **Rationale for masking:** under LGPD a CNPJ is not always strictly
  "personal data" per se (the holder is a legal entity), but in
  customer-service logs it routinely co-occurs with — and helps
  re-identify — the natural persons operating those entities.
  Guardian-BR masks it on Art. 5º I via association.

### `BR_PIS` (PIS / PASEP / NIS)

- **Articles:** Art. 5º, I; Art. 6º.
- **Checksum:** mod-11 with weights `[3,2,9,8,7,6,5,4,3,2]` over the
  first 10 digits.
- **Cross-detector note:** an unformatted 11-digit string that satisfies
  *both* CPF and PIS checksums (~1/1331 of random 11-digit runs; exact
  for `00000000000`) is emitted as both `BR_CPF` and `BR_PIS`. Downstream
  consumers must not assume detection types are mutually exclusive.

### `BR_CNH` — Carteira Nacional de Habilitação

- **Articles:** Art. 5º, I; Art. 6º.
- **Checksum:** mod-11 with the DENATRAN `descontador` rule.
- **Cross-detector note:** the same 11-digit span may match `BR_CPF`,
  `BR_PIS`, and `BR_CNH` simultaneously — all matching detections are
  emitted (**emit-both policy**, never deduplicated). `00000000000`
  satisfies all three checksums.

### `BR_TITULO_ELEITOR` — Título de eleitor (TSE)

- **Articles:** Art. 5º, I; Art. 6º.
- **Checksum:** TSE check; state-code lookup (digits 9–10 must be 01–28);
  SP/MG "DV cannot be zero" clamp (for states 01 and 02 a computed DV
  of 0 is forced to 1).
- **Format:** 12 digits, optional `4-4-4` separators (space or dot).
  Distinct length from CPF/PIS/CNH (11) and CNPJ (14), so no emit-both
  overlap with existing BR recognizers.

### `BR_RG` — Registro Geral (SP-issued in v1)

- **Articles:** Art. 5º, I; Art. 6º.
- **Checksum:** SSP/SP mod-11 (DV may be `0-9` or the letter `X` meaning
  10), with optional dot and dash separators.
- **Scope limit:** v1 supports SP-issued RGs only. Brazilian state IDs
  are heterogeneous and only SP publishes a verifiable checksum. Other
  states' RGs are deliberately *not detected* by v1, because a regex-only
  match on a 9-digit run would fire on phone numbers and order IDs —
  violating Guardian-BR's "no checksum → no detection" rule. Per-state
  validators or a lower-confidence channel are deferred to v1.1.

## What this mapping does **not** cover

- **Art. 11** (sensitive personal data — origem racial, opinião política,
  saúde, etc.) — Guardian-BR detects identifiers, not data category. If
  your application also flows health or biometric data, the operator is
  responsible for layering additional detection (e.g. ICD-10 patterns,
  laboratory result strings) before the LLM call.
- **Art. 14** (children's data) — out of scope; Guardian-BR does not
  attempt age inference from text.
- **Art. 17–22** (data subject rights — access, deletion, portability).
  These are operator obligations, not detector outputs. The audit log
  with `query_audit` and the reversible-redact `unmask` primitive give
  operators the building blocks to satisfy access requests.
- **Cross-border transfer (Art. 33–36).** Guardian-BR is self-hosted and
  runs locally; the operator decides where to deploy.

## Updating the mapping

Add a new rule by appending to `src/guardian_br/data/lgpd_mapping.yaml`
and running `/lgpd-rule-add`, which walks the required-fields checklist.
Tests in `tests/test_lgpd_mapping.py` enforce that every detector
entity type registered in `guardian_br.core.entities` has a corresponding
rule.
