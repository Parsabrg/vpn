"""Typed Xray (VLESS over one of several transports) driver contract:
request/response models and the Protocol swappable implementations
(FakeXrayRunner, NativeXrayDriver) satisfy. Deliberately a separate contract
from drivers/base.py's WireGuardDriver, not an extension of it -- that
Protocol's request/response models are hard-typed to WireGuard-only fields
(public_key, assigned_address) that cannot carry a VLESS UUID.

A client is identified by its VLESS UUID alone (a bearer credential) plus
which inbound (protocol_profile_code) it belongs to; each inbound's own
path/service-name is a single value shared by every client on it (Xray's
stream settings apply per-inbound, not per-client), so those live in
Settings (see xray_config_store.py's XrayInboundProfile), not in these
per-client request bodies -- the response echoes them back for the client's
convenience, not because the agent invented them.
"""

import re
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Mirrors services/api's ProvisioningState/HealthState vocabulary, exactly as
# drivers/base.py already does for WireGuard. Kept in sync manually.
HealthState = Literal["healthy", "degraded", "unreachable", "unknown"]
# Same three outcomes drivers/base.py's WireGuard reconcile reports, and they
# mean the same things here: the agent answers only "is this client present
# and at what generation", never what the API intended by that.
ReconcileOutcome = Literal["in_sync", "drift_detected", "ambiguous"]

_ERROR_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _validate_error_code(value: str | None) -> str | None:
    if value is not None and not _ERROR_CODE_PATTERN.fullmatch(value):
        raise ValueError("must match the agent_operations error_code format")
    return value


class _OperationModel(BaseModel):
    """No operation payload may carry unexpected fields or be mutated after construction."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class _ResponseModel(_OperationModel):
    error_code: str | None = None

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        return _validate_error_code(value)


_PROFILE_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _validate_profile_code(value: str) -> str:
    if not _PROFILE_CODE_PATTERN.fullmatch(value):
        raise ValueError("must be a lowercase, hyphenated profile code")
    return value


class ProvisionXrayClientRequest(_OperationModel):
    idempotency_key: UUID
    correlation_id: UUID
    target_kind: Literal["xray_client"]
    target_id: UUID
    desired_generation: int = Field(ge=0)
    client_uuid: UUID
    # Which configured inbound this client belongs to (e.g.
    # "vless-xhttp-tls", "vless-grpc-tls") -- matches one of the agent's own
    # XrayInboundProfile.protocol_profile_code values (Settings-derived, see
    # xray_config_store.py); an unrecognized code is a validation error the
    # driver raises itself, not a silently-ignored no-op.
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
    # carry a path, grpc carries a service name, raw carries neither.
    path: str | None = None
    service_name: str | None = None
    # Hysteria2 only -- the inbound's Salamander obfuscation password (see
    # xray_config_store.py's XrayInboundProfile.hysteria_obfs_password), so
    # the client can render the matching `udpmasks` block. Every other
    # transport leaves this unset.
    obfs_password: str | None = None
    # Shadowsocks-2022 only: what the client's outbound takes. VLESS and
    # Hysteria2 leave method and password unset.
    protocol: Literal["vless", "shadowsocks", "vmess"] = "vless"
    method: str | None = None
    password: str | None = None
    # VLESS Encryption only: the client's `encryption` string ("none" when
    # unset, as every other VLESS profile).
    encryption: str | None = None


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


class ReconcileXrayClientRequest(_OperationModel):
    """Read-only drift probe -- carries no idempotency key because it changes
    nothing, so (like WireGuard's ReconcileRequest) it bypasses the operation
    ledger entirely."""

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


class ExpectedXrayClient(_OperationModel):
    client_uuid: UUID
    protocol_profile_code: str

    @field_validator("protocol_profile_code")
    @classmethod
    def validate_protocol_profile_code(cls, value: str) -> str:
        return _validate_profile_code(value)


class PruneXrayClientsRequest(_OperationModel):
    """The complete set of clients this server should be serving, so the agent
    can drop anything else it is still holding.

    `expected` must be exhaustive, never a page of a larger set: the agent
    treats everything absent from it as an orphan and removes it. That is the
    whole point -- a credential the control plane has no live record of is
    exactly what should not remain on a VPN server -- but it also means a
    truncated list would revoke working clients, so the API side is required
    to refuse to send one it cannot vouch for in full.

    Removal only. A client the API expects but the agent has lost is drift in
    the other direction, and reconcile-client already repairs that; doing both
    here would make one operation that can add or remove credentials from a
    single list, which is a much sharper edge than it needs to be.
    """

    correlation_id: UUID
    expected: tuple[ExpectedXrayClient, ...]


class PruneXrayClientsResponse(_ResponseModel):
    state: Literal["pruned", "failed"]
    removed: int = Field(ge=0)
    kept: int = Field(ge=0)


class XrayHealthRequest(_OperationModel):
    correlation_id: UUID


class XrayHealthResponse(_ResponseModel):
    state: HealthState
    source: Literal["agent"] = "agent"
    observed_at: datetime
    agent_version: str
    listener_up: bool
    client_count: int = Field(ge=0)


class XrayDriver(Protocol):
    """Swappable-implementation contract, matching drivers/base.py's
    WireGuardDriver Protocol shape for the Xray/VLESS path."""

    async def provision_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse: ...

    async def revoke_client(self, request: RevokeXrayClientRequest) -> RevokeXrayClientResponse: ...

    async def reconcile_client(
        self, request: ReconcileXrayClientRequest
    ) -> ReconcileXrayClientResponse: ...

    async def prune_clients(self, request: PruneXrayClientsRequest) -> PruneXrayClientsResponse: ...

    async def health(self, request: XrayHealthRequest) -> XrayHealthResponse: ...

    async def resync_served_config(self) -> bool:
        """Bring the served config up to date with what this build renders.

        Called once at startup. Provisioning writes config only when the
        client set changes, so without this a release that changes the shape
        of the rendered config never takes effect -- it waits for an unrelated
        user action. Returns whether anything was actually rewritten.
        """
        ...

    def authorize_hysteria(self, auth: str) -> str | None:
        """The label to admit a new Hysteria2 connection as, or None to
        refuse it. See nebula_agent.hysteria_auth."""
        ...
