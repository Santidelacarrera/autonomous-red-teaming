# Developer task runner. On Windows, run these under Git Bash or WSL, or use the
# equivalent PowerShell commands in the README. PY points at the project venv.
PY ?= .venv/Scripts/python.exe
IMAGE ?= art-sim:local

.DEFAULT_GOAL := help
.PHONY: help setup install test lint typecheck security audit fmt run \
        frontend-install frontend-test frontend-build frontend-lint \
        docker-build docker-scan compose-up compose-down seed e2e check clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup: ## Create venv and install runtime + dev dependencies
	py -3.12 -m venv .venv
	$(PY) -m pip install -r requirements.lock
	$(PY) -m pip install -e ".[dev]" --no-deps

install: ## Install project (editable, no deps)
	$(PY) -m pip install -e . --no-deps

test: ## Run the backend test suite
	$(PY) -m pytest -q

lint: ## Ruff lint
	$(PY) -m ruff check .

typecheck: ## Strict mypy
	$(PY) -m mypy .

security: ## Bandit SAST + pip-audit dependency scan
	$(PY) -m bandit -c pyproject.toml -r src
	$(PY) -m pip_audit -r requirements.lock

fmt: ## Auto-fix lint issues
	$(PY) -m ruff check --fix .

run: ## Run the dev API on :8080
	$(PY) -m uvicorn art_sim.api.main:app --reload --port 8080

frontend-install: ## Install frontend deps
	cd frontend && npm ci

frontend-test: ## Run frontend tests
	cd frontend && npm test

frontend-lint: ## Lint + typecheck frontend
	cd frontend && npm run lint && npm run typecheck

frontend-build: ## Build the production frontend (injects CSP)
	cd frontend && npm run build

docker-build: ## Build the hardened production image
	docker build -t $(IMAGE) .

docker-scan: ## Build and scan the image (grype, only-fixed high gate)
	docker build -t $(IMAGE) .
	grype $(IMAGE) --config .grype.yaml --fail-on high

compose-up: ## Start the local stack (add shadow profile for Neo4j)
	docker compose up --build

compose-down: ## Stop the local stack
	docker compose down

seed: ## Seed the Shadow Neo4j topology (requires configured .env)
	$(PY) scripts/seed_db.py

e2e: ## Run the Shadow end-to-end simulation (requires seeded Neo4j)
	$(PY) scripts/run_e2e.py

check: lint typecheck security test ## Run the full backend quality gate

clean: ## Remove caches and build artifacts
	rm -rf .mypy_cache .pytest_cache .ruff_cache dist frontend/dist
