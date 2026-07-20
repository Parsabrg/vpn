import pytest
from pydantic import ValidationError

from nebula_api.settings import Settings


@pytest.mark.parametrize(
    "url",
    [
        "/relative",
        "https://user:password@api.example.com",
        "https://api.example.com?token=secret",
    ],
)
def test_public_url_rejects_non_public_values(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(api_public_url=url)


def test_production_requires_https() -> None:
    with pytest.raises(ValidationError, match="production URLs"):
        Settings(
            env="production",
            api_public_url="http://api.example.com",
            allowed_origins="https://admin.example.com",
        )


def test_wildcard_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="exact HTTP"):
        Settings(allowed_origins="*")


@pytest.mark.parametrize("origins", [",", "https://admin.example.com/path"])
def test_invalid_origin_lists_are_rejected(origins: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_origins=origins)


def test_safe_production_urls_are_normalized() -> None:
    settings = Settings(
        env="production",
        api_public_url="https://api.example.com/",
        allowed_origins="https://admin.example.com/, https://support.example.com",
    )

    assert settings.api_public_url == "https://api.example.com"
    assert settings.allowed_origins == ("https://admin.example.com/,https://support.example.com")


def test_unknown_explicit_setting_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Settings(unexpected=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite:///nebula.db",
        "postgresql+asyncpg://nebula:password@localhost/nebula",
        "postgresql+psycopg://localhost/nebula",
        "postgresql+psycopg://nebula:password@localhost/nebula?sslmode=disable",
    ],
)
def test_database_url_requires_explicit_psycopg_role(database_url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(database_url=database_url)


def test_database_credentials_are_redacted_from_settings_representation() -> None:
    settings = Settings(database_url="postgresql+psycopg://nebula:canary-password@localhost/nebula")

    assert "canary-password" not in repr(settings)
    assert "canary-password" not in str(settings)


def test_invalid_database_url_is_redacted_from_validation_errors() -> None:
    canary = "malformed-database-url-with-canary-secret"

    with pytest.raises(ValidationError) as error:
        Settings(database_url=canary)

    assert canary not in str(error.value)


def test_production_rejects_shared_application_and_migration_roles() -> None:
    shared_url = "postgresql+psycopg://nebula:canary-password@db.example.com/nebula"

    with pytest.raises(ValidationError, match="roles must differ"):
        Settings(
            env="production",
            api_public_url="https://api.example.com",
            allowed_origins="https://admin.example.com",
            database_url=shared_url,
            migration_database_url=shared_url,
        )
