# atalhos de desenvolvimento
# make test / make lint / make ci

PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest

.PHONY: help install install-dev test test-cov lint fmt ci clean

help:
	@echo "alvos disponiveis:"
	@echo "  make install       instala o bit2 (pip install -e .)"
	@echo "  make install-dev   instala com deps de dev"
	@echo "  make test          roda pytest"
	@echo "  make test-cov      pytest + cobertura"
	@echo "  make lint          valida sintaxe py + sh"
	@echo "  make fmt           roda black (se instalado)"
	@echo "  make ci            lint + test (o que a CI roda)"
	@echo "  make clean         limpa cache/coverage"

install:
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTEST) -q

test-cov:
	$(PYTEST) --cov=bit2 --cov-report=term-missing

lint:
	$(PYTHON) -m py_compile bit2.py bit2/*.py
	@if command -v bash >/dev/null 2>&1; then bash -n bit2.sh && echo "sh ok"; fi

fmt:
	@if command -v black >/dev/null 2>&1; then \
		black bit2/ tests/ bit2.py; \
	else \
		echo "black nao instalado, pulando (pip install black)"; \
	fi

ci: lint test

clean:
	rm -rf .pytest_cache .coverage htmlcov build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true