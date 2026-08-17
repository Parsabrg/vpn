"""Validated runtime configuration for the public API."""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """API settings loaded exclusively from explicit `NEBULA_*` variables."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    api_public_url: str = "http://localhost:8000"
    admin_public_url: str = "http://localhost:3000"
    allowed_origins: str = "http://localhost:3000"
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://nebula_app:replace-local-only@localhost:5432/nebula"
        ),
        repr=False,
    )
    migration_database_url: SecretStr | None = Field(default=None, repr=False)
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    database_statement_timeout_ms: int = Field(default=5_000, ge=100, le=30_000)
    readiness_timeout_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"), repr=False)

    jwt_issuer: str = Field(default="nebula-api", min_length=1, max_length=128)
    jwt_audience: str = Field(default="nebula-user", min_length=1, max_length=128)
    jwt_key_id: str = Field(default="v1", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
    jwt_private_key_file: Path | None = None
    jwt_public_key_file: Path | None = None
    token_pepper_file: Path | None = None
    token_key_version: int = Field(default=1, ge=1, le=2_147_483_647)
    mfa_encryption_key_file: Path | None = None
    mfa_key_version: int = Field(default=1, ge=1, le=2_147_483_647)

    agent_client_cert_file: Path | None = None
    agent_client_key_file: Path | None = None
    agent_trusted_ca_file: Path | None = None
    agent_request_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)

    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3_600)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=90)
    password_reset_ttl_minutes: int = Field(default=30, ge=5, le=120)
    activation_token_ttl_hours: int = Field(default=24, ge=1, le=168)
    account_request_ttl_days: int = Field(default=7, ge=1, le=90)
    default_device_limit: int = Field(default=3, ge=1, le=20)
    admin_session_ttl_minutes: int = Field(default=30, ge=5, le=480)
    admin_session_absolute_ttl_hours: int = Field(default=8, ge=1, le=24)
    admin_preauth_ttl_minutes: int = Field(default=5, ge=1, le=15)
    admin_step_up_ttl_minutes: int = Field(default=5, ge=1, le=15)
    totp_allowed_skew_steps: int = Field(default=1, ge=0, le=1)

    auth_rate_window_seconds: int = Field(default=900, ge=60, le=3_600)
    user_login_rate_limit: int = Field(default=10, ge=1, le=100)
    admin_login_rate_limit: int = Field(default=5, ge=1, le=50)
    admin_mfa_rate_limit: int = Field(default=5, ge=1, le=50)
    password_reset_rate_limit: int = Field(default=5, ge=1, le=50)
    account_request_rate_limit: int = Field(default=5, ge=1, le=50)
    account_request_review_rate_limit: int = Field(default=20, ge=1, le=100)
    admin_user_mutation_rate_limit: int = Field(default=20, ge=1, le=100)
    admin_lockout_threshold: int = Field(default=5, ge=2, le=20)
    admin_lockout_seconds: int = Field(default=900, ge=60, le=86_400)

    @field_validator("api_public_url", "admin_public_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("must not contain credentials, query parameters, or fragments")
        return value.rstrip("/")

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("must be an absolute Redis URL")
        if parsed.fragment:
            raise ValueError("must not contain a fragment")
        return value

    @field_validator("jwt_issuer", "jwt_audience")
    @classmethod
    def validate_jwt_context(cls, value: str) -> str:
        if value.strip() != value:
            raise ValueError("must not contain leading or trailing whitespace")
        return value

    @field_validator("allowed_origins")
    @classmethod
    def validate_allowed_origins(cls, value: str) -> str:
        origins = [origin.strip() for origin in value.split(",")]
        if not origins or any(not origin for origin in origins):
            raise ValueError("must contain at least one exact origin")
        for origin in origins:
            parsed = urlsplit(origin)
            if origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("must contain only exact HTTP(S) origins")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError("origins must not contain paths, queries, or fragments")
        return ",".join(origins)

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        try:
            url = make_url(value.get_secret_value())
        except ArgumentError as exc:
            raise ValueError("must be a valid SQLAlchemy PostgreSQL URL") from exc
        if url.drivername != "postgresql+psycopg":
            raise ValueError("must use the postgresql+psycopg driver")
        if not url.database or not url.username:
            raise ValueError("must identify a database and least-privilege role")
        if url.query:
            raise ValueError("must not contain query parameters")
        return value

    @model_validator(mode="after")
    def validate_runtime_boundaries(self) -> Self:
        if self.admin_session_ttl_minutes > self.admin_session_absolute_ttl_hours * 60:
            raise ValueError("administrator idle session lifetime cannot exceed absolute lifetime")
        if self.env != "production":
            return self
        urls = [self.api_public_url, self.admin_public_url, *self.allowed_origins.split(",")]
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    "production URLs and origins must use HTTPS and non-loopback hosts"
                )
        if self.migration_database_url is not None and (
            self.migration_database_url.get_secret_value() == self.database_url.get_secret_value()
        ):
            raise ValueError("production application and migration database roles must differ")
        required_secret_files = {
            "jwt_private_key_file": self.jwt_private_key_file,
            "jwt_public_key_file": self.jwt_public_key_file,
            "token_pepper_file": self.token_pepper_file,
            "mfa_encryption_key_file": self.mfa_encryption_key_file,
            "agent_client_cert_file": self.agent_client_cert_file,
            "agent_client_key_file": self.agent_client_key_file,
            "agent_trusted_ca_file": self.agent_trusted_ca_file,
        }
        missing = [name for name, path in required_secret_files.items() if path is None]
        if missing:
            raise ValueError("production authentication secret files are required")
        if any(
            path is not None and not path.is_absolute() for path in required_secret_files.values()
        ):
            raise ValueError("production authentication secret file paths must be absolute")
        parsed_redis = urlsplit(self.redis_url.get_secret_value())
        if not parsed_redis.password:
            raise ValueError("production Redis must use authentication")
        return self

    @property
    def allowed_origin_values(self) -> tuple[str, ...]:
        """Return the exact CORS/origin allowlist without reparsing at call sites."""

        return tuple(self.allowed_origins.split(","))

    @property
    def admin_cookie_name(self) -> str:
        """Use the host-only cookie prefix whenever HTTPS is mandatory."""

        return "__Host-nebula_admin" if self.env in {"staging", "production"} else "nebula_admin"

    @property
    def admin_cookie_secure(self) -> bool:
        """Permit local HTTP development while requiring secure deployed cookies."""

        return self.env in {"staging", "production"}

    @property
    def admin_csrf_cookie_name(self) -> str:
        """Name the readable, host-only CSRF cookie separately from the session."""

        return "__Host-nebula_csrf" if self.admin_cookie_secure else "nebula_csrf"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
