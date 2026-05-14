from typing import Final

BR_CPF: Final[str] = "BR_CPF"
BR_CNPJ: Final[str] = "BR_CNPJ"
BR_PIS: Final[str] = "BR_PIS"
BR_CNH: Final[str] = "BR_CNH"
BR_TITULO_ELEITOR: Final[str] = "BR_TITULO_ELEITOR"

BR_ENTITIES: frozenset[str] = frozenset({BR_CPF, BR_CNPJ, BR_PIS, BR_CNH, BR_TITULO_ELEITOR})
