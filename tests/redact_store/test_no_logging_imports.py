"""Static check: PII-handling modules must not import logging or use print()."""

import ast
from pathlib import Path

_PII_MODULES = [
    "src/guardian_br/core/redact_store.py",
    "src/guardian_br/core/sqlite_redact_store.py",
    "src/guardian_br/core/crypto.py",
    "src/guardian_br/core/kms.py",
]

_REPO_ROOT = Path(__file__).parent.parent.parent


def _get_source(rel_path: str) -> str:
    return (_REPO_ROOT / rel_path).read_text(encoding="utf-8")


def test_no_logging_imports() -> None:
    for rel in _PII_MODULES:
        src = _get_source(rel)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    assert name != "logging" and not name.startswith("logging."), (
                        f"{rel} imports logging — raw PII must never appear in logs"
                    )


def test_no_print_calls() -> None:
    for rel in _PII_MODULES:
        src = _get_source(rel)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                raise AssertionError(
                    f"{rel} contains a print() call — forbidden in PII-handling paths"
                )
