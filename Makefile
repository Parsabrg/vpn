.DEFAULT_GOAL := help

.PHONY: help bootstrap check test db-upgrade db-check compose-config compose-up compose-down compose-smoke

help:
	@echo "bootstrap      Install workspace dependencies"
	@echo "check          Run all static checks and tests"
	@echo "db-upgrade     Upgrade PostgreSQL to the checked-in migration head"
	@echo "db-check       Verify model metadata matches the migration head"
	@echo "compose-config Validate the development Compose model"
	@echo "compose-up     Build and start the local stack"
	@echo "compose-down   Stop the local stack"
	@echo "compose-smoke  Start the stack and verify container health"

bootstrap:
	python -m pip install -e "./services/api[dev]" -e "./services/vpn-agent[dev]"
	npm --prefix apps/admin ci
	cd apps/mobile && flutter pub get

check:
	python -m pip_audit
	python -m ruff check services/api services/vpn-agent
	python -m ruff format --check services/api services/vpn-agent
	cd services/api && python -m mypy && python -m pytest
	cd services/vpn-agent && python -m mypy && python -m pytest
	npm --prefix apps/admin run check
	cd apps/mobile && dart format --output=none --set-exit-if-changed . && flutter analyze && flutter test
	$(MAKE) compose-config

test:
	python -m pytest services/api/tests services/vpn-agent/tests
	npm --prefix apps/admin test
	cd apps/mobile && flutter test

db-upgrade:
	cd services/api && python -m alembic upgrade head

db-check:
	cd services/api && python -m alembic check

compose-config:
	docker compose config --quiet

compose-up:
	docker compose up --build --detach --wait

compose-down:
	docker compose down --remove-orphans

compose-smoke:
	docker compose up --build --detach --wait
	docker compose ps
