"""Validated host-only configuration for the VPN agent."""

import re
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")


class Settings(BaseSettings):
    """Immutable agent settings; operation payloads cannot override these paths."""

    model_config = SettingsConfigDict(
        env_prefix="NEBULA_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    env: Environment = "development"
    log_level: LogLevel = "INFO"
    wg_interface: str = "wg0"
    wg_server_private_key_file: PurePosixPath = PurePosixPath(
        "/run/nebula-secrets/wireguard_server_private_key"
    )
    xray_enabled: bool = False
    xray_binary: PurePosixPath = PurePosixPath("/usr/local/bin/xray")
    xray_config_dir: PurePosixPath = PurePosixPath("/etc/nebula/xray")
    xray_state_dir: PurePosixPath = PurePosixPath("/var/lib/nebula/xray")
    xray_validate_timeout_seconds: int = Field(default=10, ge=1, le=60)
    xray_apply_timeout_seconds: int = Field(default=20, ge=1, le=120)

    @field_validator("wg_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if not _INTERFACE_PATTERN.fullmatch(value):
            raise ValueError("must be a valid Linux interface name of at most 15 characters")
        return value

    @field_validator(
        "wg_server_private_key_file",
        "xray_binary",
        "xray_config_dir",
        "xray_state_dir",
    )
    @classmethod
    def require_absolute_host_path(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute():
            raise ValueError("host paths must be absolute")
        return value

    @model_validator(mode="after")
    def reject_unimplemented_xray_driver(self) -> Self:
        if self.xray_enabled:
            raise ValueError("Xray is disabled until its reviewed delivery milestone")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable host settings instance."""

    return Settings()
