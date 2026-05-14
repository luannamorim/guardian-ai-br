from typing import Final

BR_CPF: Final[str] = "BR_CPF"
BR_CNPJ: Final[str] = "BR_CNPJ"
BR_PIS: Final[str] = "BR_PIS"

BR_ENTITIES: frozenset[str] = frozenset({BR_CPF, BR_CNPJ, BR_PIS})
