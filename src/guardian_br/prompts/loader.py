"""Prompt file loader for adversarial classifiers.

No I/O side-effects at import time — safe to import in tests without Ollama.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=8)
def load_prompt(name: str = "llama_guard_ptbr_v1") -> tuple[str, str]:
    """Return (prompt_text, sha256_hex_prefix_8) for a named prompt file.

    The 8-char digest is embedded in AdversarialResult.model_version so eval
    reports can detect prompt drift between runs.
    """
    path = files("guardian_br").joinpath(f"prompts/{name}.md")
    raw = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    return raw, digest
