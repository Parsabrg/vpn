"""Validated host-only configuration for the VPN agent."""

import re
from functools import lru_cache
from ipaddress import ip_network
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import (
    Field,
    IPvAnyAddress,
    IPvAnyInterface,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
_PUBLIC_ENDPOINT_PATTERN = re.compile(
    r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):(?P<port>\d{1,5})$"
)


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
    wg_driver: Literal["fake", "native"] = "fake"
    operation_ledger_file: PurePosixPath = PurePosixPath(
        "/var/lib/nebula/wireguard/operation_ledger.jsonl"
    )
    operation_ledger_max_entries: int = Field(default=10_000, ge=100, le=1_000_000)

    # --- WireGuard networking ---
    wg_binary: PurePosixPath = PurePosixPath("/usr/bin/wg")
    wg_quick_binary: PurePosixPath = PurePosixPath("/usr/bin/wg-quick")
    wg_state_dir: PurePosixPath = PurePosixPath("/var/lib/nebula/wireguard")
    wg_server_address: IPvAnyInterface = "10.77.0.1/24"  # type: ignore[assignment]
    wg_client_pool: IPvAnyNetwork = "10.77.0.0/24"  # type: ignore[assignment]
    wg_listen_port: int = Field(default=51820, ge=1, le=65535)
    wg_public_endpoint: str = "vpn.example.com:51820"
    wg_client_dns: IPvAnyAddress = "1.1.1.1"  # type: ignore[assignment]
    wg_client_allowed_ips: str = "0.0.0.0/0,::/0"
    wg_persistent_keepalive_seconds: int = Field(default=25, ge=1, le=3600)

    # --- Agent-side mTLS server identity ---
    agent_tls_cert_file: PurePosixPath = PurePosixPath("/run/nebula-secrets/agent_tls_cert")
    agent_tls_key_file: PurePosixPath = PurePosixPath("/run/nebula-secrets/agent_tls_key")
    agent_trusted_client_ca_file: PurePosixPath = PurePosixPath(
        "/run/nebula-secrets/agent_trusted_client_ca"
    )

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
        "operation_ledger_file",
        "wg_binary",
        "wg_quick_binary",
        "wg_state_dir",
        "agent_tls_cert_file",
        "agent_tls_key_file",
        "agent_trusted_client_ca_file",
    )
    @classmethod
    def require_absolute_host_path(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute():
            raise ValueError("host paths must be absolute")
        return value

    @field_validator("wg_public_endpoint")
    @classmethod
    def validate_public_endpoint(cls, value: str) -> str:
        match = _PUBLIC_ENDPOINT_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError(
                "must be a bare host:port with no scheme, path, or shell metacharacters"
            )
        port = int(match.group("port"))
        if not (1 <= port <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("wg_client_allowed_ips")
    @classmethod
    def validate_client_allowed_ips(cls, value: str) -> str:
        segments = value.split(",")
        if not segments or any(not segment for segment in segments):
            raise ValueError("must be a comma-separated list of CIDR networks")
        for segment in segments:
            try:
                ip_network(segment.strip(), strict=True)
            except ValueError as error:
                raise ValueError(f"invalid CIDR network {segment!r}: {error}") from error
        return value

    @model_validator(mode="after")
    def reject_unimplemented_xray_driver(self) -> Self:
        if self.xray_enabled:
            raise ValueError("Xray is disabled until its reviewed delivery milestone")
        return self

    @model_validator(mode="after")
    def require_server_address_within_client_pool(self) -> Self:
        if self.wg_server_address.ip not in self.wg_client_pool:
            raise ValueError("wg_server_address must fall inside wg_client_pool")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable host settings instance."""

    return Settings()
