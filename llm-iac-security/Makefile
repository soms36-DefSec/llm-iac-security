.PHONY: install test lint format scan setup-kb evaluate clean

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
	python scripts/run_scan.py $(TEMPLATE) --mode $(or $(MODE),local)

evaluate:
	python scripts/evaluate_results.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage .chroma_db .cache
	rm -rf data/reports/generated/*
