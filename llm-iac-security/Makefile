.PHONY: install test lint format scan setup-kb evaluate

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	ruff check .
	mypy . --ignore-missing-imports

format:
	ruff format .

setup-kb:
	python scripts/setup_knowledge_base.py

scan:
	@if [ -z "$(TEMPLATE)" ]; then echo "Usage: make scan TEMPLATE=path/to/template.yaml"; exit 1; fi
	python scripts/run_scan.py $(TEMPLATE)

evaluate:
	python scripts/evaluate_results.py
