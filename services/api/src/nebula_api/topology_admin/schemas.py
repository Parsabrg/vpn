"""Strict, bounded HTTP contracts for read-only topology listings."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from nebula_api.agent_client.models import HealthState
from nebula_api.auth.schemas import AuthModel
from nebula_api.models.types import ServerState


class ProtocolListItem(AuthModel):
    id: UUID
    code: str
    display_name: str
    engine: str
    is_user_selectable: bool


class ProtocolListResponse(AuthModel):
    items: list[ProtocolListItem]


class TrafficSummaryItem(AuthModel):
    protocol: str
    # Sums can exceed JavaScript's safe integer range (and PostgreSQL int8).
    rx_bytes: str = Field(pattern=r"^[0-9]+$")
    tx_bytes: str = Field(pattern=r"^[0-9]+$")
    total_bytes: str = Field(pattern=r"^[0-9]+$")
    newest_collected_at: datetime | None


class TrafficSummaryResponse(AuthModel):
    items: list[TrafficSummaryItem]


class ProtocolProfileListItem(AuthModel):
    id: UUID
    protocol_id: UUID
    code: str
    version: int
    display_name: str
    state: str
    transport: str | None
    transport_security: str | None
    requires_udp: bool
    is_full_tunnel: bool


class ProtocolProfileListResponse(AuthModel):
    items: list[ProtocolProfileListItem]


class VpnServerListItem(AuthModel):
    id: UUID
    code: str
    display_name: str
    state: str
    public_host: str
    maximum_devices: int


class SecurityCheckItem(AuthModel):
    key: str
    label: str
    status: Literal["ok", "warning", "failing", "unknown"]
    detail: str
    observed_at: datetime | None


class SecurityStatusResponse(AuthModel):
    checks: list[SecurityCheckItem]


class ReconcileNowRequest(AuthModel):
    """Everything, or one WireGuard peer or Xray client."""

    target_id: UUID | None = None


class ReconciliationSummaryItem(AuthModel):
    checked: int
    in_sync: int
    repaired: int
    repair_failed: int
    ambiguous: int
    errored: int


class ReconcileNowResponse(AuthModel):
    wireguard: ReconciliationSummaryItem
    xray: ReconciliationSummaryItem


class SetVpnServerStateRequest(AuthModel):
    state: ServerState


class SetVpnServerNameRequest(AuthModel):
    """The name the app and the panel show; the code stays as it is."""

    display_name: str = Field(min_length=1, max_length=96)


class VpnServerListResponse(AuthModel):
    items: list[VpnServerListItem]


class VpnServerHealthItem(AuthModel):
    server_id: UUID
    code: str
    state: HealthState
    observed_at: datetime
    latency_ms: int | None
    agent_version: str | None
    interface_up: bool | None
    peer_count: int | None


class VpnServerHealthListResponse(AuthModel):
    items: list[VpnServerHealthItem]


class VpnServerXrayHealthItem(AuthModel):
    server_id: UUID
    code: str
    state: HealthState
    observed_at: datetime
    latency_ms: int | None
    agent_version: str | None
    listener_up: bool | None
    error_code: str | None


class VpnServerXrayHealthListResponse(AuthModel):
    items: list[VpnServerXrayHealthItem]


class VpnServerReconciliationItem(AuthModel):
    server_id: UUID
    code: str
    pending_provisions: int
    pending_revocations: int
    failed_records: int


class VpnServerReconciliationListResponse(AuthModel):
    items: list[VpnServerReconciliationItem]


class ReconciliationHistoryItem(AuthModel):
    id: UUID
    server_id: UUID
    server_code: str
    target_kind: str
    target_id: UUID
    desired_generation: int
    observed_generation: int | None
    outcome: str
    checked_at: datetime
    error_code: str | None


class ReconciliationHistoryResponse(AuthModel):
    items: list[ReconciliationHistoryItem]
    total: int
    limit: int
    offset: int
