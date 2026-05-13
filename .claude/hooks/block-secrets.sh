#!/usr/bin/env bash
# Why this exists: Guardian-BR handles KMS keys, hashed API keys, and DEK/KEK
# material. An accidental edit to .env or secrets/ that gets committed forces
# a full key rotation. This hook fails closed on any such write.

set -euo pipefail

file="${CLAUDE_TOOL_FILE_PATH:-}"
case "$file" in
  *.env|*/.env|*/.env.*|*/secrets/*|*.pem|*.key)
    echo "BLOCKED: writes to secret material are forbidden ($file). Edit by hand outside Claude." >&2
    exit 2
    ;;
esac
