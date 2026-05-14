CORPUS ?= evals/pii_corpus.jsonl
CATEGORY ?= all

.PHONY: eval eval-quick test lint format typecheck

eval:
	uv run python -m guardian_br.eval --corpus $(CORPUS)

eval-quick:
	uv run python -m guardian_br.eval --corpus evals/pii_corpus.jsonl --category $(CATEGORY)

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

typecheck:
	uv run mypy src/
