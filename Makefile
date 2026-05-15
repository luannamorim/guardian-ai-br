CORPUS ?= evals/pii_corpus.jsonl
CATEGORY ?= all

.PHONY: eval eval-quick eval-adversarial eval-all test lint format typecheck

eval:
	uv run python -m guardian_br.eval --corpus $(CORPUS)

eval-quick:
	uv run python -m guardian_br.eval --corpus evals/pii_corpus.jsonl --category $(CATEGORY)

eval-adversarial:
	uv run python -m guardian_br.eval --corpus evals/adversarial_corpus.jsonl --mode adversarial

eval-all:
	uv run python -m guardian_br.eval --corpus evals/pii_corpus.jsonl --mode pii
	uv run python -m guardian_br.eval --corpus evals/adversarial_corpus.jsonl --mode adversarial --out eval_report_adversarial.md

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

typecheck:
	uv run mypy src/
