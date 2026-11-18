.PHONY: install test lint demo docker
install:
	pip install -e ".[dev]"
test:
	pytest -q
lint:
	ruff check src tests && mypy src
demo:
	soc-triage demo
docker:
	docker build -t soc-ai-alert-triage-pipeline . && docker run --rm soc-ai-alert-triage-pipeline
