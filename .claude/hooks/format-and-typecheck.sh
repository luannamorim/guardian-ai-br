#!/usr/bin/env bash
# Why this exists: ruff format + ruff check after every Python edit keeps
# diffs clean and catches lint at write time. Mypy is intentionally NOT
# run here — it is project-aware and per-file runs miss cross-module
# errors. Run `uv run mypy src/` manually or via /review.

set -euo pipefail

file="${CLAUDE_TOOL_FILE_PATH:-}"
if [[ "$file" =~ \.py$ ]]; then
  uv run ruff format "$file" >/dev/null 2>&1 || true
  uv run ruff check --fix "$file" >/dev/null 2>&1 || true
fi
