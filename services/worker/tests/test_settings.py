from pathlib import Path

import pytest
from pydantic import ValidationError

from nebula_worker.settings import Settings, get_settings


def test_defaults_are_bounded() -> None:
    settings = Settings()

    assert settings.email_provider == "smtp"
    assert settings.smtp_host == "mailpit"
    assert settings.poll_interval_seconds == 5.0
    assert settings.lease_seconds == 60
    assert settings.batch_size == 10
    assert settings.max_attempts == 8


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite:///nebula.db",
        "postgresql+asyncpg://nebula:password@localhost/nebula",
        "postgresql+psycopg://localhost/nebula",
        "malformed-database-url-with-no-structure",
    ],
)
def test_database_url_requires_explicit_psycopg_role(database_url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(database_url=database_url)


def test_get_settings_returns_a_cached_instance() -> None:
    assert get_settings() is get_settings()


@pytest.mark.parametrize("redis_url", ["not-a-url", "http://localhost:6379/0"])
def test_redis_url_must_be_absolute_redis_url(redis_url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(redis_url=redis_url)


def test_smtp_password_defaults_to_empty_string_without_a_file() -> None:
    settings = Settings()

    assert settings.smtp_password == ""


def test_smtp_password_is_read_and_stripped_from_the_mounted_file(tmp_path: Path) -> None:
    password_file = tmp_path / "smtp_password"
    password_file.write_text("  secret-canary  \n", encoding="utf-8")

    settings = Settings(smtp_password_file=password_file)

    assert settings.smtp_password == "secret-canary"  # noqa: S105 - test fixture


def test_resend_api_key_requires_a_configured_file() -> None:
    settings = Settings()

    with pytest.raises(ValueError, match="not configured"):
        _ = settings.resend_api_key


def test_resend_api_key_is_read_and_stripped_from_the_mounted_file(tmp_path: Path) -> None:
    key_file = tmp_path / "resend_api_key"
    key_file.write_text("re_canary_key\n", encoding="utf-8")

    settings = Settings(resend_api_key_file=key_file)

    assert settings.resend_api_key == "re_canary_key"


def test_unknown_settings_are_ignored_rather_than_rejected() -> None:
    settings = Settings(some_future_field="value")

    assert settings.env == "development"
