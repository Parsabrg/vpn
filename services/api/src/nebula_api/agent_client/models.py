"""Typed request/response models for the VPN agent's operation API.

Mirrors services/vpn-agent/src/nebula_agent/drivers/base.py's request and
response shapes exactly. Defined here rather than imported -- services/api
must not depend on services/vpn-agent, the same cross-service independence
1.6a maintained in the other direction. Keep these in sync manually;
tests/test_agent_client_models.py checks the shared vocabularies against a
pasted copy of this service's own operations.py tuples (the live DB
CHECK-constraint source of truth for both services).
"""

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

OperationKind = Literal[
    "provision_device",
    "revoke_device",
    "enable_device",
    "disable_device",
    "health",
    "reconcile",
]
TargetKind = Literal[
    "device_credential",
    "wireguard_peer",
    "xray_client",
    "server_capability",
    "vpn_server",
]
HealthState = Literal["healthy", "degraded", "unreachable", "unknown"]

# The agent only ever reports these three; repair_* outcomes belong to this
# service's own reconciliation job, applied after deciding what to do about
# a drift_detected/ambiguous result.
ReconcileOutcome = Literal["in_sync", "drift_detected", "ambiguous"]

_PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")
# Matches wireguard_peers.public_key_canonical's CHECK constraint in
# models/provisioning.py exactly.
_ALL_ZERO_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# Matches agent_operations.error_code's CHECK constraint format in
# models/operations.py.
_ERROR_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

# Matches services/vpn-agent/src/nebula_agent/drivers/xray_base.py's own
# _PROFILE_CODE_PATTERN exactly.
_PROFILE_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _validate_profile_code(value: str) -> str:
    if not _PROFILE_CODE_PATTERN.fullmatch(value):
        raise ValueError("must be a lowercase, hyphenated profile code")
    return value


def _validate_public_key(value: str) -> str:
    if not _PUBLIC_KEY_PATTERN.fullmatch(value):
        raise ValueError("must be a 32-byte base64-encoded WireGuard public key")
    if value == _ALL_ZERO_PUBLIC_KEY:
        raise ValueError("must not be the all-zero public key")
    return value


def _validate_error_code(value: str | None) -> str | None:
    if value is not None and not _ERROR_CODE_PATTERN.fullmatch(value):
        raise ValueError("must match the agent_operations error_code format")
    return value


class _OperationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _ResponseModel(_OperationModel):
    error_code: str | None = None

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        return _validate_error_code(value)


class ProvisionDeviceRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["wireguard_peer"]
    target_id: UUID
    desired_generation: int = Field(ge=0)
    public_key: str
    assigned_address: IPvAnyAddress
    persistent_keepalive_seconds: int | None = Field(default=None, ge=1, le=3600)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _validate_public_key(value)


class ProvisionDeviceResponse(_ResponseModel):
    state: Literal["active", "failed"]
    applied_generation: int = Field(ge=0)
    server_public_key: str
    listen_port: int = Field(ge=1, le=65535)
    public_endpoint: str
    client_dns: str
    client_allowed_ips: str
    persistent_keepalive_seconds: int


class RevokeDeviceRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["wireguard_peer"]
    target_id: UUID
    public_key: str
    desired_generation: int = Field(ge=0)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _validate_public_key(value)


class RevokeDeviceResponse(_ResponseModel):
    state: Literal["revoked", "failed"]
    applied_generation: int = Field(ge=0)
    revoked_at: datetime


class EnableDeviceRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["wireguard_peer"]
    target_id: UUID
    public_key: str
    assigned_address: IPvAnyAddress
    desired_generation: int = Field(ge=0)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _validate_public_key(value)


class EnableDeviceResponse(_ResponseModel):
    state: Literal["enabled", "failed"]
    applied_generation: int = Field(ge=0)


class DisableDeviceRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["wireguard_peer"]
    target_id: UUID
    public_key: str
    desired_generation: int = Field(ge=0)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _validate_public_key(value)


class DisableDeviceResponse(_ResponseModel):
    state: Literal["disabled", "failed"]
    applied_generation: int = Field(ge=0)


class HealthRequest(_OperationModel):
    correlation_id: UUID


class HealthResponse(_ResponseModel):
    state: HealthState
    source: Literal["agent"] = "agent"
    observed_at: datetime
    latency_ms: int | None = Field(default=None, ge=0, le=600_000)
    agent_version: str
    interface_up: bool
    peer_count: int = Field(ge=0)


class ReconcileRequest(_OperationModel):
    correlation_id: UUID
    target_kind: Literal["wireguard_peer"]
    target_id: UUID
    public_key: str
    assigned_address: IPvAnyAddress
    desired_generation: int = Field(ge=0)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        return _validate_public_key(value)


class ReconcileResponse(_ResponseModel):
    outcome: ReconcileOutcome
    observed_generation: int | None = Field(default=None, ge=0)


# Mirrors services/vpn-agent/src/nebula_agent/drivers/xray_base.py exactly.
# Deliberately not an extension of the WireGuard models above -- their fields
# (public_key, assigned_address) can't carry a VLESS UUID. The XHTTP path is
# a single value shared by the whole server inbound, not a per-client field,
# so it never appears on these request/response models.
class ProvisionXrayClientRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["xray_client"]
    target_id: UUID
    desired_generation: int = Field(ge=0)
    client_uuid: UUID
    # Which of the agent's configured Xray inbounds this client belongs to
    # (e.g. "vless-xhttp-tls", "hysteria2") -- must match one of that
    # server's own XrayInboundProfile.protocol_profile_code values.
    protocol_profile_code: str

    @field_validator("protocol_profile_code")
    @classmethod
    def validate_protocol_profile_code(cls, value: str) -> str:
        return _validate_profile_code(value)


class ProvisionXrayClientResponse(_ResponseModel):
    state: Literal["active", "failed"]
    applied_generation: int = Field(ge=0)
    server_address: str
    port: int = Field(ge=1, le=65535)
    sni: str
    transport: Literal["xhttp", "grpc", "websocket", "raw", "hysteria"]
    transport_security: Literal["none", "tls"]
    # At most one of these is set, matching `transport` -- xhttp/websocket
    # carry a path, grpc carries a service name, raw/hysteria carry neither.
    path: str | None = None
    service_name: str | None = None
    # Hysteria2 only -- the inbound's Salamander obfuscation password (see
    # vpn-agent's XrayInboundProfile.hysteria_obfs_password), so the mobile
    # client can render a matching `udpmasks` block. Every other transport
    # leaves this unset.
    obfs_password: str | None = None
    # Shadowsocks-2022 only (vpn-agent's ss2022 inbound): what the client's
    # outbound takes. VLESS and Hysteria2 leave method and password unset.
    protocol: Literal["vless", "shadowsocks", "vmess"] = "vless"
    method: str | None = None
    password: str | None = None
    # VLESS Encryption only: the client's `encryption` string.
    encryption: str | None = None


class ExpectedXrayClient(_OperationModel):
    client_uuid: UUID
    protocol_profile_code: str

    @field_validator("protocol_profile_code")
    @classmethod
    def validate_protocol_profile_code(cls, value: str) -> str:
        return _validate_profile_code(value)


class PruneXrayClientsRequest(_OperationModel):
    """The complete set of clients a server should be serving. Anything the
    agent still holds that is absent from `expected` is removed, so this must
    never be built from a partial read -- see run_xray_orphan_prune."""

    correlation_id: UUID
    expected: tuple[ExpectedXrayClient, ...]


class PruneXrayClientsResponse(_ResponseModel):
    state: Literal["pruned", "failed"]
    removed: int = Field(ge=0)
    kept: int = Field(ge=0)


class ReconcileXrayClientRequest(_OperationModel):
    """Read-only drift probe; no idempotency key because it changes nothing --
    mirrors ReconcileRequest's relationship to the WireGuard operations."""

    correlation_id: UUID
    target_kind: Literal["xray_client"]
    target_id: UUID
    client_uuid: UUID
    protocol_profile_code: str
    desired_generation: int = Field(ge=0)

    @field_validator("protocol_profile_code")
    @classmethod
    def validate_protocol_profile_code(cls, value: str) -> str:
        return _validate_profile_code(value)


class ReconcileXrayClientResponse(_ResponseModel):
    outcome: ReconcileOutcome
    observed_generation: int | None = Field(default=None, ge=0)


class RevokeXrayClientRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["xray_client"]
    target_id: UUID
    client_uuid: UUID
    protocol_profile_code: str
    desired_generation: int = Field(ge=0)

    @field_validator("protocol_profile_code")
    @classmethod
    def validate_protocol_profile_code(cls, value: str) -> str:
        return _validate_profile_code(value)


class RevokeXrayClientResponse(_ResponseModel):
    state: Literal["revoked", "failed"]
    applied_generation: int = Field(ge=0)
    revoked_at: datetime


class XrayHealthRequest(_OperationModel):
    correlation_id: UUID


class XrayHealthResponse(_ResponseModel):
    state: HealthState
    source: Literal["agent"] = "agent"
    observed_at: datetime
    agent_version: str
    listener_up: bool
    client_count: int = Field(ge=0)


class CollectUsageRequest(BaseModel):
    """No fields. The agent reports every counter it can see, and there is
    nothing for the caller to narrow -- see the agent's route for why it does
    not filter to credentials the control plane already knows about."""

    model_config = ConfigDict(extra="forbid")


class UsageSampleItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str
    # A SHA-256 digest, never the credential. The agent hashes before
    # reporting because for VLESS and Hysteria2 the identity is the secret.
    identity: str
    rx_bytes: int
    tx_bytes: int
    sampled_at: datetime


class CollectUsageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    samples: list[UsageSampleItem]
    sources_read: list[str]
    sources_failed: list[str]
