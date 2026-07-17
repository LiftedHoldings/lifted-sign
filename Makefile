# Lifted Sign — developer task runner.
#
# Thin, self-documenting wrappers over the project's venv, pip, ruff, pytest,
# `python -m sign`, and docker compose. Works from bash on Linux/macOS and from
# Git Bash on Windows (the venv layout differs — resolved below).
#
#   make install   # create .venv and install the package with dev extras
#   make test      # run the test suite
#   make run       # boot the app locally (auto-generates SIGN_SECRET if unset)
#
# Run `make help` (the default) for the full list.

# --- venv / interpreter resolution ------------------------------------------
VENV := .venv
ifeq ($(OS),Windows_NT)
  VENV_PY := $(VENV)/Scripts/python.exe
else
  VENV_PY := $(VENV)/bin/python
endif

# Fall back to a system `python` when the venv doesn't exist yet (e.g. `make install`).
PYTHON := $(if $(wildcard $(VENV_PY)),$(VENV_PY),python)

# Everything runs through `python -m` so we never depend on console-script shims
# being on PATH.
RUFF   := $(PYTHON) -m ruff
PYTEST := $(PYTHON) -m pytest

# docker compose v2 (subcommand). Override with `make docker COMPOSE="docker-compose"`.
COMPOSE := docker compose

.DEFAULT_GOAL := help

.PHONY: help install dev test cov lint fmt run docker clean

help: ## Show this help
	@echo "Lifted Sign make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install the package with dev extras
	python -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e '.[dev]'

dev: install ## Alias for install (set up a full development environment)

test: ## Run the test suite
	SIGN_SECRET=$${SIGN_SECRET:-ci-only-not-a-real-secret-value-0123456789} \
		$(PYTEST) -q

cov: ## Run the suite with coverage (term-missing, fail under 80%)
	SIGN_SECRET=$${SIGN_SECRET:-ci-only-not-a-real-secret-value-0123456789} \
		$(PYTEST) -q --cov=sign --cov-report=term-missing --cov-fail-under=80

lint: ## Lint with ruff (check + format --check)
	$(RUFF) check sign tests
	$(RUFF) format --check .

fmt: ## Auto-fix and format with ruff
	$(RUFF) check --fix sign tests
	$(RUFF) format .

run: ## Boot the app locally on PORT (default 8080); auto-generates SIGN_SECRET if unset
	SIGN_SECRET=$${SIGN_SECRET:-$$($(PYTHON) -c 'import secrets; print(secrets.token_urlsafe(48))')} \
		$(PYTHON) -m sign

docker: ## Build and run the stack with docker compose (needs SIGN_SECRET in .env)
	$(COMPOSE) up --build

clean: ## Remove caches and build artifacts (keeps .venv and data/)
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	rm -rf build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
