.PHONY: start-example
start-example:
	@docker compose up --build fastapi-guard-example

.PHONY: stop
stop:
	@docker compose down --rmi all --remove-orphans -v

.PHONY: restart
restart: stop start

.PHONY: test
test:
	@docker compose run --rm fastapi-guard pytest -v --cov=.

.PHONY: lint
lint:
	@docker compose run --rm --no-deps fastapi-guard sh -c "ruff format . ; ruff check . ; mypy guard"

.PHONY: update-dependencies
update-dependencies:
	@docker compose run --rm --no-deps fastapi-guard poetry lock

.PHONY: install
install:
	@poetry install

.PHONY: local-test
local-test:
	@poetry run pytest -v --cov=.
