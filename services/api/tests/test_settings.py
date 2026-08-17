from pathlib import Path

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
            admin_public_url="https://admin.example.com",
            allowed_origins="https://admin.example.com",
        )


def test_wildcard_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="exact HTTP"):
        Settings(allowed_origins="*")


@pytest.mark.parametrize("origins", [",", "https://admin.example.com/path"])
def test_invalid_origin_lists_are_rejected(origins: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_origins=origins)


def test_safe_production_urls_are_normalized(tmp_path: Path) -> None:
    settings = Settings(
        env="production",
        api_public_url="https://api.example.com/",
        admin_public_url="https://admin.example.com/",
        allowed_origins="https://admin.example.com/, https://support.example.com",
        redis_url="rediss://:production-password@redis.example.com:6379/0",
        jwt_private_key_file=tmp_path / "jwt_private_key",
        jwt_public_key_file=tmp_path / "jwt_public_key",
        token_pepper_file=tmp_path / "token_pepper",
        mfa_encryption_key_file=tmp_path / "mfa_encryption_key",
        agent_client_cert_file=tmp_path / "agent_client_cert",
        agent_client_key_file=tmp_path / "agent_client_key",
        agent_trusted_ca_file=tmp_path / "agent_trusted_ca",
    )

    assert settings.api_public_url == "https://api.example.com"
    assert settings.admin_public_url == "https://admin.example.com"
    assert settings.allowed_origins == ("https://admin.example.com/,https://support.example.com")
    assert settings.admin_cookie_name == "__Host-nebula_admin"
    assert settings.admin_cookie_secure


def test_production_requires_agent_mtls_secret_files(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="production authentication secret files"):
        Settings(
            env="production",
            api_public_url="https://api.example.com",
            admin_public_url="https://admin.example.com",
            allowed_origins="https://admin.example.com",
            redis_url="rediss://:production-password@redis.example.com:6379/0",
            jwt_private_key_file=tmp_path / "jwt_private_key",
            jwt_public_key_file=tmp_path / "jwt_public_key",
            token_pepper_file=tmp_path / "token_pepper",
            mfa_encryption_key_file=tmp_path / "mfa_encryption_key",
        )


def test_agent_request_timeout_seconds_must_be_within_bounds() -> None:
    with pytest.raises(ValidationError):
        Settings(agent_request_timeout_seconds=0.5)
    with pytest.raises(ValidationError):
        Settings(agent_request_timeout_seconds=61)


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
            admin_public_url="https://admin.example.com",
            allowed_origins="https://admin.example.com",
            database_url=shared_url,
            migration_database_url=shared_url,
        )


def test_redis_credentials_are_redacted_from_settings_representation() -> None:
    settings = Settings(redis_url="redis://:canary-redis-password@localhost:6379/0")

    assert "canary-redis-password" not in repr(settings)
    assert "canary-redis-password" not in str(settings)


def test_production_requires_authentication_secret_files() -> None:
    with pytest.raises(ValidationError, match="authentication secret files"):
        Settings(
            env="production",
            api_public_url="https://api.example.com",
            admin_public_url="https://admin.example.com",
            allowed_origins="https://admin.example.com",
            redis_url="rediss://:production-password@redis.example.com:6379/0",
        )


def test_development_cookie_is_local_http_compatible() -> None:
    settings = Settings(env="development")

    assert settings.admin_cookie_name == "nebula_admin"
    assert not settings.admin_cookie_secure


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jwt_key_id", ".invalid"),
        ("jwt_issuer", " issuer"),
        ("jwt_audience", "audience "),
    ],
)
def test_jwt_configuration_fails_during_settings_validation(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})  # type: ignore[arg-type]


def test_admin_idle_session_cannot_outlive_absolute_session() -> None:
    with pytest.raises(ValidationError, match="idle session lifetime"):
        Settings(admin_session_ttl_minutes=121, admin_session_absolute_ttl_hours=2)


def test_account_request_defaults_are_bounded() -> None:
    settings = Settings()

    assert settings.activation_token_ttl_hours == 24
    assert settings.account_request_ttl_days == 7
    assert settings.default_device_limit == 3
    assert settings.account_request_rate_limit == 5
    assert settings.account_request_review_rate_limit == 20
    assert settings.admin_user_mutation_rate_limit == 20


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("activation_token_ttl_hours", 0),
        ("activation_token_ttl_hours", 169),
        ("account_request_ttl_days", 0),
        ("account_request_ttl_days", 91),
        ("default_device_limit", 0),
        ("default_device_limit", 21),
        ("account_request_rate_limit", 0),
        ("account_request_review_rate_limit", 0),
        ("admin_user_mutation_rate_limit", 0),
    ],
)
def test_account_request_settings_reject_out_of_bounds_values(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})  # type: ignore[arg-type]
