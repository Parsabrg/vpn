import asyncio
import sys
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

import nebula_api.cli as cli_module
from nebula_api.cli import build_parser, main, read_password, run_seed_admin
from nebula_api.db.engine import SessionFactory
from nebula_api.seed_admin import SeedAdminResult, SeedAdminStatus


def test_seed_parser_has_no_password_argument(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    canary = "canary-secret-that-must-not-be-reflected"

    with pytest.raises(SystemExit):
        parser.parse_args(["seed-admin", "--email", "admin@example.com", "--password", canary])

    assert canary not in capsys.readouterr().err


def test_password_entry_requires_interactive_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    with pytest.raises(RuntimeError, match="interactive terminal"):
        read_password()


def test_password_confirmation_must_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    responses = iter(["first-password", "second-password"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(responses))

    with pytest.raises(ValueError, match="confirmation"):
        read_password()


def test_password_confirmation_returns_hidden_value(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = "matching-canary-value"
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: candidate)

    assert read_password() == candidate


@pytest.mark.parametrize(
    ("status", "expected_output"),
    [
        (SeedAdminStatus.CREATED, "Created initial administrator"),
        (SeedAdminStatus.ALREADY_INITIALIZED, "already initialized"),
    ],
)
def test_run_seed_admin_disposes_engine_and_reports_generic_outcome(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: SeedAdminStatus,
    expected_output: str,
) -> None:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    session_factory = cast(SessionFactory, MagicMock())
    identifier = uuid4() if status is SeedAdminStatus.CREATED else None

    def fake_create_engine(_url: str, **_kwargs: object) -> AsyncEngine:
        return cast(AsyncEngine, engine)

    def fake_session_factory(_engine: AsyncEngine) -> SessionFactory:
        return session_factory

    seed = AsyncMock(return_value=SeedAdminResult(status=status, admin_id=identifier))
    monkeypatch.setattr(cli_module, "create_database_engine", fake_create_engine)
    monkeypatch.setattr(cli_module, "create_session_factory", fake_session_factory)
    monkeypatch.setattr(cli_module, "seed_initial_admin", seed)
    candidate = "canary-value-never-printed"

    result = asyncio.run(
        run_seed_admin(email="owner@example.com", username=None, password=candidate)
    )

    assert result == 0
    engine.dispose.assert_awaited_once_with()
    output = capsys.readouterr().out
    assert expected_output in output
    assert candidate not in output


def test_main_never_accepts_password_option(capsys: pytest.CaptureFixture[str]) -> None:
    canary = "second-canary-secret-that-must-not-be-reflected"

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "admin@example.com", "--password", canary])

    assert canary not in capsys.readouterr().err


def test_main_runs_seed_without_reflecting_password(monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = "main-canary-value"
    received: dict[str, str | None] = {}

    async def fake_run_seed_admin(*, email: str, username: str | None, password: str) -> int:
        received.update(email=email, username=username, password=password)
        return 0

    monkeypatch.setattr(cli_module, "read_password", lambda: candidate)
    monkeypatch.setattr(cli_module, "run_seed_admin", fake_run_seed_admin)

    assert main(["seed-admin", "--email", "owner@example.com"]) == 0
    assert received == {
        "email": "owner@example.com",
        "username": None,
        "password": candidate,
    }


def test_main_redacts_database_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    detail = "database-canary-detail"

    async def failing_seed(*, email: str, username: str | None, password: str) -> int:
        del email, username, password
        raise SQLAlchemyError(detail)

    monkeypatch.setattr(cli_module, "read_password", lambda: "hidden-canary-value")
    monkeypatch.setattr(cli_module, "run_seed_admin", failing_seed)

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "owner@example.com"])

    error = capsys.readouterr().err
    assert "database operation failed" in error
    assert detail not in error


def test_main_redacts_invalid_database_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = "malformed-database-url-with-cli-canary"
    monkeypatch.setenv("NEBULA_DATABASE_URL", canary)
    monkeypatch.setattr(cli_module, "read_password", lambda: "hidden-canary-value")

    with pytest.raises(SystemExit):
        main(["seed-admin", "--email", "owner@example.com"])

    assert canary not in capsys.readouterr().err
