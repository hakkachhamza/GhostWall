.PHONY: help install install-dev test lint format security clean build docs run dry-run status report

PYTHON := python
PIP := pip
PACKAGE := ghostwall

help:
	@echo "GhostWall Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install        Install production dependencies"
	@echo "  install-dev    Install development dependencies"
	@echo "  install-all    Install with all optional extras"
	@echo "  test           Run pytest suite"
	@echo "  lint           Run flake8 and mypy"
	@echo "  format         Run black (check mode)"
	@echo "  format-fix     Run black (apply formatting)"
	@echo "  security       Run bandit and safety checks"
	@echo "  clean          Remove build artifacts"
	@echo "  build          Build wheel and source distribution"
	@echo "  docs           Placeholder for docs build"
	@echo "  run            Run GhostWall interactive menu"
	@echo "  dry-run        Run a local dry-run audit"
	@echo "  status         Show current security status"
	@echo "  report         Generate HTML report"

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"

install-all:
	$(PIP) install -e ".[all]"

test:
	$(PYTHON) -m pytest -v

lint:
	$(PYTHON) -m flake8 ghostwall tests
	$(PYTHON) -m mypy ghostwall

format:
	$(PYTHON) -m black --check ghostwall tests

format-fix:
	$(PYTHON) -m black ghostwall tests

security:
	$(PYTHON) -m bandit -r ghostwall
	$(PYTHON) -m safety check

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:
	$(PYTHON) -m build

docs:
	@echo "Documentation source lives in docs/"

run:
	$(PYTHON) -m ghostwall.cli

dry-run:
	$(PYTHON) -m ghostwall.cli --audit --dry-run

status:
	$(PYTHON) -m ghostwall.cli --status

report:
	$(PYTHON) -m ghostwall.cli --report
