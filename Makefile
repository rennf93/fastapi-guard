# Supported Python versions
PYTHON_VERSIONS = 3.10 3.11 3.12 3.13
DEFAULT_PYTHON = 3.10

# Install dependencies
.PHONY: install
install:
	@poetry install
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Update dependencies
.PHONY: lock
lock:
	@poetry lock
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Start example-app
.PHONY: start-example
start-example:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose up --build fastapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

.PHONY: run-example
run-example:
	@COMPOSE_BAKE=true docker compose build fastapi-guard-example
	@docker compose up fastapi-guard-example
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Stop
.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Restart
.PHONY: restart
restart: stop start-example

# Lint code
.PHONY: lint
lint:
	@COMPOSE_BAKE=true docker compose run --rm --no-deps fastapi-guard sh -c "ruff format . ; ruff check . ; mypy ."
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Fix code
.PHONY: fix
fix:
	@poetry run ruff check --fix .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Run tests (default Python version)
.PHONY: test
test:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build fastapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Run All Python versions
.PHONY: test-all
test-all: test-3.10 test-3.11 test-3.12 test-3.13

# Python 3.10
.PHONY: test-3.10
test-3.10:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.10 docker compose build fastapi-guard
	@PYTHON_VERSION=3.10 docker compose run --rm fastapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.11
.PHONY: test-3.11
test-3.11:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.11 docker compose build fastapi-guard
	@PYTHON_VERSION=3.11 docker compose run --rm fastapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.12
.PHONY: test-3.12
test-3.12:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.12 docker compose build fastapi-guard
	@PYTHON_VERSION=3.12 docker compose run --rm fastapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Python 3.13
.PHONY: test-3.13
test-3.13:
	@docker compose down -v fastapi-guard
	@COMPOSE_BAKE=true PYTHON_VERSION=3.13 docker compose build fastapi-guard
	@PYTHON_VERSION=3.13 docker compose run --rm fastapi-guard pytest -v --cov=.
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Local testing
.PHONY: local-test
local-test:
	@poetry run pytest -v --cov=.
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Stress Test
.PHONY: stress-test
stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example poetry run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 120 --concurrency 50 --ramp-up 10 --delay 0.02 --test-type standard -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# High-load stress test
.PHONY: high-load-stress-test
high-load-stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example poetry run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 180 --concurrency 100 --ramp-up 15 --delay 0.01 --test-type high_load -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Serve docs
.PHONY: serve-docs
serve-docs:
	@poetry run mkdocs serve
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Prune
.PHONY: prune
prune:
	@docker system prune -f

# Clean Cache Files
.PHONY: clean
clean:
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo$|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

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
