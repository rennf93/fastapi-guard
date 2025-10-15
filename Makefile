# Supported Python versions
PYTHON_VERSIONS = 3.10 3.11 3.12 3.13
DEFAULT_PYTHON = 3.10

# Install dependencies
.PHONY: install
install:
	@uv sync
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Install dev dependencies
.PHONY: install-dev
install-dev:
	@uv sync --extra dev
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Update dependencies
.PHONY: lock
lock:
	@uv lock
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf


# Upgrade dependencies
.PHONY: upgrade
upgrade:
	@uv lock --upgrade
	@uv sync --all-extras
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

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
	@COMPOSE_BAKE=true docker compose run --rm --no-deps fastapi-guard sh -c "echo 'Formatting w/ Ruff...' ; echo '' ; ruff format . ; echo '' ; echo '' ; echo 'Linting w/ Ruff...' ; echo '' ; ruff check . ; echo '' ; echo '' ; echo 'Type checking w/ Mypy...' ; echo '' ; mypy . ; echo '' ; echo '' ; echo 'Finding dead code w/ Vulture...' ; echo '' ; vulture"
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Fix code
.PHONY: fix
fix:
	@echo "Fixing formatting w/ Ruff..."
	@echo ''
	@uv run ruff check --fix .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Find dead code with Vulture
.PHONY: vulture
vulture:
	@echo "Finding dead code with Vulture..."
	@echo ''
#	@uv run vulture
#	@uv run vulture --verbose
	@uv run vulture vulture_whitelist.py
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Security scan with Bandit
.PHONY: bandit
bandit:
	@echo "Running Bandit security scan..."
	@echo ''
	@uv run bandit -r guard -ll
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Check dependencies with Safety
.PHONY: safety
safety:
	@echo "Checking dependencies with Safety..."
	@echo ''
	@uv run safety scan
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Audit dependencies with pip-audit
.PHONY: pip-audit
pip-audit:
	@echo "Auditing dependencies with pip-audit..."
	@echo ''
	@uv run pip-audit
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Analyze code complexity with Radon
.PHONY: radon
radon:
	@echo "Analyzing code complexity with Radon..."
	@echo ''
	@echo "Cyclomatic Complexity:"
	@uv run radon cc guard -nc
	@echo ''
	@echo "Maintainability Index:"
	@uv run radon mi guard -nc
	@echo ''
	@echo "Raw Metrics:"
	@uv run radon raw guard
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Check complexity thresholds with Xenon
.PHONY: xenon
xenon:
	@echo "Checking complexity thresholds with Xenon..."
	@echo ''
	@uv run xenon guard --max-absolute B --max-modules A --max-average A
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Analyze dependencies with Deptry
.PHONY: deptry
deptry:
	@echo "Analyzing dependencies with Deptry..."
	@echo ''
	@uv run deptry .
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Static analysis with Semgrep
.PHONY: semgrep
semgrep:
	@echo "Running Semgrep static analysis..."
	@echo ''
	@uv run semgrep --config=auto guard
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Profile with py-spy
.PHONY: profile
profile:
	@echo "Profiling with py-spy (requires running application)..."
	@echo "Usage: make profile PID=<process_id>"
	@echo "Or: make profile-record to record a new profile"
	@[ -n "$(PID)" ] && uv run py-spy top --pid $(PID) || echo "Please provide PID=<process_id>"
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Record profile with py-spy
.PHONY: profile-record
profile-record:
	@echo "Recording profile with py-spy..."
	@echo "This will profile the example application for 30 seconds"
	@uv run py-spy record -o profile.svg -d 30 -- uv run python examples/main.py &
	@echo "Profile will be saved to profile.svg"
	@find . | grep -E "(__pycache__|\.pyc|\.pyo|\.pytest_cache|\.ruff_cache|\.mypy_cache)" | xargs rm -rf

# Run hypothesis tests
.PHONY: hypothesis
hypothesis:
	@COMPOSE_BAKE=true PYTHON_VERSION=$(DEFAULT_PYTHON) docker compose run --rm --build fastapi-guard pytest -v --hypothesis-show-statistics
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Run all security checks
.PHONY: security
security: bandit safety pip-audit
	@echo "All security checks completed."

# Run all code quality checks
.PHONY: quality
quality: lint vulture radon xenon interrogate
	@echo "All code quality checks completed."

# Run all analysis tools
.PHONY: analysis
analysis: deptry semgrep
	@echo "All analysis tools completed."

# Run all checks (linting, security, quality, and analysis)
.PHONY: check-all
check-all: lint security quality analysis
	@echo "All checks completed."

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

# Stress Test
.PHONY: stress-test
stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example uv run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 120 --concurrency 50 --ramp-up 10 --delay 0.02 --test-type standard -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# High-load stress test
.PHONY: high-load-stress-test
high-load-stress-test:
	@COMPOSE_BAKE=true docker compose up --build -d fastapi-guard-example redis
	@echo "Waiting for services to start up..."
	@sleep 5
	@docker compose run --rm fastapi-guard-example uv run python examples/testing/stress_test.py --url http://fastapi-guard-example:8000 --duration 180 --concurrency 100 --ramp-up 15 --delay 0.01 --test-type high_load -v
	@docker compose down --rmi all --remove-orphans -v
	@docker system prune -f

# Serve docs
.PHONY: serve-docs
serve-docs:
	@uv run mkdocs serve
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Lint documentation
.PHONY: lint-docs
lint-docs:
	@uv run pymarkdownlnt scan -r -e ./.venv -e ./.git -e ./.github -e ./data -e ./guard -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Fix documentation
.PHONY: fix-docs
fix-docs:
	@uv run pymarkdownlnt fix -r -e ./.venv -e ./.git -e ./.github -e ./data -e ./guard -e ./tests -e ./.claude -e ./CLAUDE.md -e ./.cursor -e ./.kiro -e ./ZZZ .
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Prune
.PHONY: prune
prune:
	@docker system prune -f

# Clean Cache Files
.PHONY: clean
clean:
	@find . | grep -E "(__pycache__|\\.pyc|\\.pyo|\\.pytest_cache|\\.ruff_cache|\\.mypy_cache)" | xargs rm -rf

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make install            	   - Install dependencies"
	@echo "  make install-dev        	   - Install dev dependencies"
	@echo "  make lock               	   - Update dependencies"
	@echo "  make start-example      	   - Start example application with docker compose"
	@echo "  make run-example        	   - Build and run example container directly"
	@echo "  make stop               	   - Stop all containers and clean up resources"
	@echo "  make restart            	   - Restart example application"
	@echo "  make lint               	   - Run linting checks"
	@echo "  make fix                	   - Auto-fix linting issues"
	@echo "  make vulture            	   - Find dead code with Vulture"
	@echo "  make bandit             	   - Run Bandit security scan"
	@echo "  make safety             	   - Check dependencies with Safety"
	@echo "  make pip-audit          	   - Audit dependencies with pip-audit"
	@echo "  make radon              	   - Analyze code complexity with Radon"
	@echo "  make xenon              	   - Check complexity thresholds with Xenon"
	@echo "  make interrogate        	   - Check docstring coverage with Interrogate"
	@echo "  make deptry             	   - Analyze dependencies with Deptry"
	@echo "  make semgrep            	   - Run Semgrep static analysis"
	@echo "  make profile            	   - Profile running application with py-spy"
	@echo "  make profile-record     	   - Record profile with py-spy"
	@echo "  make hypothesis         	   - Run property-based tests with Hypothesis"
	@echo "  make security           	   - Run all security checks"
	@echo "  make quality            	   - Run all code quality checks"
	@echo "  make analysis           	   - Run all analysis tools"
	@echo "  make check-all          	   - Run all checks (lint, security, quality, analysis)"
	@echo "  make test               	   - Run tests with Python $(DEFAULT_PYTHON)"
	@echo "  make test-all           	   - Run tests with all Python versions ($(PYTHON_VERSIONS))"
	@echo "  make test-<version>     	   - Run tests with specific Python version (e.g., make test-3.10)"
	@echo "  make local-test         	   - Run tests locally"
	@echo "  make stress-test        	   - Run stress test"
	@echo "  make high-load-stress-test    - Run high-load stress test"
	@echo "  make serve-docs       		   - Serve documentation"
	@echo "  make lint-docs        		   - Run markdownlint on documentation"
	@echo "  make fix-docs         		   - Auto-fix markdownlint issues"
	@echo "  make prune            		   - Prune docker resources"
	@echo "  make clean                    - Clean cache files"
	@echo "  make help             		   - Show this help message"
	@echo "  make show-python-versions     - Show supported Python versions"

# Python versions list
.PHONY: show-python-versions
show-python-versions:
	@echo "Supported Python versions: $(PYTHON_VERSIONS)"
	@echo "Default Python version: $(DEFAULT_PYTHON)"
