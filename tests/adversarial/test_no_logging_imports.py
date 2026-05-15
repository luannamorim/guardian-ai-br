"""Static check: adversarial modules that handle raw text must never log it.

Adversarial modules may import logging for error-level metadata (elapsed_ms,
error reason, etc.) but must never pass raw text as a logger call argument.
Core helpers (TTLLRUCache, parser, prompt loader) must not import logging at all.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent

# These modules handle raw input text → must not import logging
_NO_LOGGING_MODULES = [
    "src/guardian_br/core/ttl_cache.py",
    "src/guardian_br/prompts/loader.py",
    "src/guardian_br/adversarial/ollama_parser.py",
]

# These modules may import logging but must not pass raw text to log calls
_NO_RAW_TEXT_MODULES = [
    "src/guardian_br/adversarial/ollama_classifier.py",
]


def _get_source(rel_path: str) -> str:
    return (_REPO_ROOT / rel_path).read_text(encoding="utf-8")


def test_pure_helpers_have_no_logging_import() -> None:
    for rel in _NO_LOGGING_MODULES:
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
                        f"{rel} imports logging — pure helper must not use logging"
                    )


def test_no_print_calls_in_adversarial_modules() -> None:
    all_modules = _NO_LOGGING_MODULES + _NO_RAW_TEXT_MODULES
    for rel in all_modules:
        src = _get_source(rel)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                raise AssertionError(
                    f"{rel} contains a print() call — forbidden in adversarial-handling paths"
                )


def test_classifier_log_calls_never_pass_text_variable() -> None:
    """Check that logger.* calls in OllamaClassifier never pass the `text` variable.

    This is a conservative AST check: any Name node with id='text' appearing
    as a direct argument to a logger call is forbidden.
    """
    for rel in _NO_RAW_TEXT_MODULES:
        src = _get_source(rel)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match logger.warning(...), logger.error(...), logger.info(...), etc.
            if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
                continue
            if func.value.id != "logger":
                continue
            for arg in node.args:
                assert not (isinstance(arg, ast.Name) and arg.id == "text"), (
                    f"{rel}: logger.{func.attr}() passes raw `text` variable — "
                    "log only metadata (elapsed_ms, reason, length), never raw content"
                )
