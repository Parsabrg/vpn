"""Validated runtime configuration for the email outbox worker."""

from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
EmailProvider = Literal["smtp", "resend"]


class Settings(BaseSettings):
    """Worker settings loaded exclusively from explicit `NEBULA_*` variables."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    database_url: SecretStr = Field(
        default=SecretStr(
            "postgresql+psycopg://nebula_app:replace-local-only@localhost:5432/nebula"
        ),
        repr=False,
    )
    redis_url: SecretStr = Field(default=SecretStr("redis://localhost:6379/0"), repr=False)

    email_provider: EmailProvider = "smtp"
    email_from: str = Field(
        default="Nebula VPN <no-reply@example.com>", min_length=3, max_length=320
    )
    smtp_host: str = Field(default="mailpit", min_length=1, max_length=255)
    smtp_port: int = Field(default=1025, ge=1, le=65_535)
    smtp_username: str = ""
    smtp_password_file: Path | None = None
    smtp_starttls: bool = False
    resend_api_key_file: Path | None = None

    poll_interval_seconds: float = Field(default=5.0, ge=0.5, le=60.0)
    lease_seconds: int = Field(default=60, ge=5, le=3_600)
    batch_size: int = Field(default=10, ge=1, le=100)
    max_attempts: int = Field(default=8, ge=1, le=50)

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        try:
            url = make_url(value.get_secret_value())
        except ArgumentError as exc:
            raise ValueError("must be a valid SQLAlchemy PostgreSQL URL") from exc
        if url.drivername != "postgresql+psycopg":
            raise ValueError("must use the postgresql+psycopg driver")
        if not url.database or not url.username:
            raise ValueError("must identify a database and least-privilege role")
        return value

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        parsed = urlsplit(value.get_secret_value())
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("must be an absolute Redis URL")
        return value

    @property
    def smtp_password(self) -> str:
        """Read the mounted SMTP password file, or an empty string for local Mailpit."""

        if self.smtp_password_file is None:
            return ""
        return self.smtp_password_file.read_text(encoding="utf-8").strip()

    @property
    def resend_api_key(self) -> str:
        if self.resend_api_key_file is None:
            raise ValueError("Resend API key file is not configured")
        return self.resend_api_key_file.read_text(encoding="utf-8").strip()


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
