# Supported Python versions
PYTHON_VERSIONS = 3.10 3.11 3.12 3.13
DEFAULT_PYTHON = 3.10

# Activate VEnv
.PHONY: activate
activate:
	@source .venv/bin/activate

# Install dependencies
.PHONY: install-deps
install-deps:
	@poetry install

# Update dependencies
.PHONY: update-deps
update-deps:
	@poetry lock

# Start example-app
.PHONY: start-example
start-example:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose up --build fastapi-guard-example

.PHONY: run-example
run-example:
	@COMPOSE_BAKE=true docker compose build fastapi-guard-example
	@docker compose up fastapi-guard-example

# Stop
.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v

# Restart
.PHONY: restart
restart: stop start-example

# Lint code
.PHONY: lint
lint:
	@COMPOSE_BAKE=true docker compose run --rm --no-deps fastapi-guard sh -c "ruff format . ; ruff check . ; mypy ."
	@$(MAKE) stop

# Fix code
.PHONY: fix
fix:
	@poetry run ruff check --fix .

# Run tests (default Python version)
.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build fastapi-guard pytest -v --cov=.
	@$(MAKE) stop

# Run All Python versions
.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13

# Python 3.10
.PHONY: test-3.10
test-3.10:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build fastapi-guard
	@PYTHON_VERSION=3.10 docker compose run --rm fastapi-guard pytest -v --cov=.
	@$(MAKE) stop

# Python 3.11
.PHONY: test-3.11
test-3.11:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build fastapi-guard
	@PYTHON_VERSION=3.11 docker compose run --rm fastapi-guard pytest -v --cov=.
	@$(MAKE) stop

# Python 3.12
.PHONY: test-3.12
test-3.12:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build fastapi-guard
	@PYTHON_VERSION=3.12 docker compose run --rm fastapi-guard pytest -v --cov=.
	@$(MAKE) stop

# Python 3.13
.PHONY: test-3.13
test-3.13:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build fastapi-guard
	@PYTHON_VERSION=3.13 docker compose run --rm fastapi-guard pytest -v --cov=.
	@$(MAKE) stop

# Local testing
.PHONY: local-test
local-test:
	@poetry run pytest -v --cov=.

# Prune
.PHONY: prune
prune:
	@docker system prune -f

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make install-deps     - Install dependencies"
	@echo "  make update-deps      - Update dependencies"
	@echo "  make start-example    - Start example application with docker compose"
	@echo "  make run-example      - Build and run example container directly"
	@echo "  make stop             - Stop all containers and clean up resources"
	@echo "  make restart          - Restart example application"
	@echo "  make lint             - Run linting checks"
	@echo "  make test             - Run tests with Python $(DEFAULT_PYTHON)"
	@echo "  make test-all         - Run tests with all Python versions ($(PYTHON_VERSIONS))"
	@echo "  make test-<version>   - Run tests with specific Python version (e.g., make test-3.10)"
	@echo "  make local-test       - Run tests locally"
	@echo "  make show-python-versions - Show supported Python versions"
	@echo "  make help             - Show this help message"

# Python versions list
.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
