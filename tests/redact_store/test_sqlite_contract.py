import pytest

from guardian_br.core.sqlite_redact_store import SQLiteRedactStore
from tests.redact_store.contract import RedactStoreContractTests


class TestSQLiteContract(RedactStoreContractTests):
    @pytest.fixture
    def store(self) -> SQLiteRedactStore:
        return SQLiteRedactStore(":memory:")
