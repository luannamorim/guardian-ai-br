"""Tests for the LGPD mapping YAML and its Pydantic loader.

Uses importlib.resources exactly as a user would — no direct file-path reads.
This also validates that the YAML is packaged into the wheel correctly.
"""

from guardian_br.core.entities import BR_CNH, BR_CNPJ, BR_CPF, BR_PIS
from guardian_br.lgpd.loader import LGPDMapping, load_lgpd_mapping


def test_load_returns_lgpd_mapping() -> None:
    mapping = load_lgpd_mapping()
    assert isinstance(mapping, LGPDMapping)


def test_disclaimer_present() -> None:
    mapping = load_lgpd_mapping()
    assert mapping.disclaimer
    assert len(mapping.disclaimer) > 20


def test_br_cpf_rule_present() -> None:
    mapping = load_lgpd_mapping()
    assert BR_CPF in mapping.rules


def test_br_cpf_has_lgpd_articles() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CPF]
    assert len(rule.lgpd_articles) >= 1


def test_br_cpf_primary_article() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CPF]
    assert rule.lgpd_articles[0].article == "Art. 5º, I"


def test_br_cnpj_rule_present() -> None:
    mapping = load_lgpd_mapping()
    assert BR_CNPJ in mapping.rules


def test_br_cnpj_has_lgpd_articles() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CNPJ]
    assert len(rule.lgpd_articles) >= 1


def test_br_cnpj_primary_article() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CNPJ]
    assert rule.lgpd_articles[0].article == "Art. 5º, I"


def test_br_pis_rule_present() -> None:
    mapping = load_lgpd_mapping()
    assert BR_PIS in mapping.rules


def test_br_pis_has_lgpd_articles() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_PIS]
    assert len(rule.lgpd_articles) >= 1


def test_br_pis_primary_article() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_PIS]
    assert rule.lgpd_articles[0].article == "Art. 5º, I"


def test_br_cnh_rule_present() -> None:
    mapping = load_lgpd_mapping()
    assert BR_CNH in mapping.rules


def test_br_cnh_has_lgpd_articles() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CNH]
    assert len(rule.lgpd_articles) >= 1


def test_br_cnh_primary_article() -> None:
    mapping = load_lgpd_mapping()
    rule = mapping.rules[BR_CNH]
    assert rule.lgpd_articles[0].article == "Art. 5º, I"


def test_schema_version_is_int() -> None:
    mapping = load_lgpd_mapping()
    assert isinstance(mapping.schema_version, int)
    assert mapping.schema_version >= 1
