"""Validated runtime configuration for the public API."""

from functools import lru_cache
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """API settings loaded exclusively from explicit `NEBULA_*` variables."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    api_public_url: str = "http://localhost:8000"
    allowed_origins: str = "http://localhost:3000"
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)

    @field_validator("api_public_url")
    @classmethod
    def validate_public_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("must not contain credentials, query parameters, or fragments")
        return value.rstrip("/")

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

    @model_validator(mode="after")
    def reject_unsafe_production_defaults(self) -> Self:
        if self.env != "production":
            return self
        urls = [self.api_public_url, *self.allowed_origins.split(",")]
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    "production URLs and origins must use HTTPS and non-loopback hosts"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
