# syntax=docker/dockerfile:1

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first for layer-cache efficiency
COPY pyproject.toml uv.lock ./

# Install production deps (api extra) into an in-project venv
RUN uv sync --frozen --no-dev --extra api

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/app/.venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN adduser --disabled-password --gecos "" --uid 1000 app

WORKDIR /app

# Bring in the pre-built venv from the builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy application source (recognizers, LGPD YAML, prompts, etc.)
COPY src/ ./src/

USER app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/v1/healthz || exit 1

CMD ["uvicorn", "guardian_br.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
