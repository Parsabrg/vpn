"""Read-only listing of protocols, protocol profiles, and VPN servers."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, func, select, union_all

from nebula_api.agent_client.client import (
    AgentClientBuilder,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentResponseInvalid,
    AgentUnreachable,
)
from nebula_api.agent_client.models import HealthRequest, HealthState, XrayHealthRequest
from nebula_api.auth.audit import add_audit_event
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import ReconciliationRecord
from nebula_api.models.provisioning import WireGuardPeer, XrayClient
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, ProtocolEngine, ServerState
from nebula_api.models.usage import CredentialUsage
from nebula_api.provisioning.reconciliation import ReconciliationSummary

Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class ProtocolEntry:
    id: UUID
    code: str
    display_name: str
    engine: str
    is_user_selectable: bool


@dataclass(frozen=True, slots=True)
class TrafficSummaryEntry:
    protocol: str
    rx_bytes: int
    tx_bytes: int
    newest_collected_at: datetime | None


@dataclass(frozen=True, slots=True)
class ProtocolProfileEntry:
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


@dataclass(frozen=True, slots=True)
class VpnServerEntry:
    id: UUID
    code: str
    display_name: str
    state: str
    public_host: str
    maximum_devices: int


@dataclass(frozen=True, slots=True)
class VpnServerHealthEntry:
    server_id: UUID
    code: str
    state: HealthState
    observed_at: datetime
    latency_ms: int | None
    agent_version: str | None
    interface_up: bool | None
    peer_count: int | None


@dataclass(frozen=True, slots=True)
class VpnServerReconciliationEntry:
    server_id: UUID
    code: str
    pending_provisions: int
    pending_revocations: int
    failed_records: int


@dataclass(frozen=True, slots=True)
class VpnServerXrayHealthEntry:
    server_id: UUID
    code: str
    state: HealthState
    observed_at: datetime
    latency_ms: int | None
    agent_version: str | None
    listener_up: bool | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class ReconciliationHistoryEntry:
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


@dataclass(frozen=True, slots=True)
class ReconciliationHistoryPage:
    items: list[ReconciliationHistoryEntry]
    total: int


# The scheduled sweep's two passes, run now: everything, or one target.
# Raises ReconciliationBusy while another pass holds the lock.
Reconciler = Callable[[UUID | None], Awaitable[tuple[ReconciliationSummary, ReconciliationSummary]]]


class TopologyAdminService:
    """Own read-only access to topology and runtime lifecycle summaries."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        agent_client_builder: AgentClientBuilder | None = None,
        reconciler: Reconciler | None = None,
        clock: Clock = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._agent_client_builder = agent_client_builder
        self._reconciler = reconciler
        self._clock = clock
        self._monotonic = monotonic

    async def list_protocols(self) -> list[ProtocolEntry]:
        async with self._session_factory() as session:
            rows = (await session.scalars(select(Protocol).order_by(Protocol.code))).all()
        return [
            ProtocolEntry(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                engine=row.engine,
                is_user_selectable=row.is_user_selectable,
            )
            for row in rows
        ]

    async def get_traffic_summary(self) -> list[TrafficSummaryEntry]:
        """Platform-wide accumulated totals; the ledger has no node dimension.

        Aggregate without reading credential identities or decrypting keys.
        Newest collection time belongs to one record, not every counter.
        """
        # ponytail: scans the ledger; roll up totals if this exceeds the DB timeout.
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        CredentialUsage.protocol,
                        func.sum(CredentialUsage.rx_bytes).label("rx_bytes"),
                        func.sum(CredentialUsage.tx_bytes).label("tx_bytes"),
                        func.max(CredentialUsage.last_collected_at).label("newest_collected_at"),
                    )
                    .group_by(CredentialUsage.protocol)
                    .order_by(CredentialUsage.protocol)
                )
            ).all()
        return [
            TrafficSummaryEntry(
                row.protocol,
                int(row.rx_bytes),
                int(row.tx_bytes),
                row.newest_collected_at,
            )
            for row in rows
        ]

    async def list_protocol_profiles(self) -> list[ProtocolProfileEntry]:
        async with self._session_factory() as session:
            rows = (
                await session.scalars(select(ProtocolProfile).order_by(ProtocolProfile.code))
            ).all()
        return [
            ProtocolProfileEntry(
                id=row.id,
                protocol_id=row.protocol_id,
                code=row.code,
                version=row.version,
                display_name=row.display_name,
                state=row.state,
                transport=row.transport,
                transport_security=row.transport_security,
                requires_udp=row.requires_udp,
                is_full_tunnel=row.is_full_tunnel,
            )
            for row in rows
        ]

    async def list_vpn_servers(self) -> list[VpnServerEntry]:
        async with self._session_factory() as session:
            rows = (await session.scalars(select(VPNServer).order_by(VPNServer.code))).all()
        return [
            VpnServerEntry(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                state=row.state,
                public_host=row.public_host,
                maximum_devices=row.maximum_devices,
            )
            for row in rows
        ]

    async def set_vpn_server_state(
        self, *, server_id: UUID, state: ServerState, admin_id: UUID, request_id: UUID
    ) -> VpnServerEntry | None:
        """Put a server into service, into maintenance, or out of it.

        Maintenance takes no new connections and leaves the app's server list,
        while the tunnels it already serves keep running, counted and
        repaired. Disabled is out of service: not offered, not counted, not
        repaired -- for a server being retired or rebuilt.
        """

        async with self._session_factory() as session:
            server = await session.scalar(
                select(VPNServer).where(VPNServer.id == server_id).with_for_update()
            )
            if server is None:
                return None
            server.state = state.value
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="vpn_server",
                target_id=server_id,
                event_code="server_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code=f"server_{state.value}",
            )
            await session.commit()
            return VpnServerEntry(
                id=server.id,
                code=server.code,
                display_name=server.display_name,
                state=server.state,
                public_host=server.public_host,
                maximum_devices=server.maximum_devices,
            )

    async def set_vpn_server_name(
        self, *, server_id: UUID, display_name: str, admin_id: UUID, request_id: UUID
    ) -> VpnServerEntry | None:
        """The name people see. A joined server starts out named by its code."""

        async with self._session_factory() as session:
            server = await session.scalar(
                select(VPNServer).where(VPNServer.id == server_id).with_for_update()
            )
            if server is None:
                return None
            server.display_name = display_name
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="vpn_server",
                target_id=server_id,
                event_code="server_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="server_renamed",
            )
            await session.commit()
            return VpnServerEntry(
                id=server.id,
                code=server.code,
                display_name=server.display_name,
                state=server.state,
                public_host=server.public_host,
                maximum_devices=server.maximum_devices,
            )

    async def reconcile_now(
        self, *, target_id: UUID | None, admin_id: UUID, request_id: UUID
    ) -> tuple[ReconciliationSummary, ReconciliationSummary] | None:
        """Run reconciliation now, as the sweep would, and audit who asked.

        None when this deployment has no agent wiring. A target that is not
        a live WireGuard peer or Xray client comes back with nothing checked,
        and nothing is audited for it.
        """

        if self._reconciler is None:
            return None
        wireguard, xray = await self._reconciler(target_id)
        if target_id is not None and wireguard.checked + xray.checked == 0:
            return wireguard, xray
        if target_id is None:
            target_kind = "agent_operation"
        elif wireguard.checked:
            target_kind = "wireguard_peer"
        else:
            target_kind = "xray_client"
        problems = wireguard.had_problems or xray.had_problems
        async with self._session_factory() as session:
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind=target_kind,
                target_id=target_id or request_id,
                event_code="operation_changed",
                outcome="failed" if problems else "succeeded",
                request_id=request_id,
                reason_code="reconciliation_run" if target_id is None else "reconciliation_target",
            )
            await session.commit()
        return wireguard, xray

    async def get_vpn_server_reconciliation(self) -> list[VpnServerReconciliationEntry]:
        """Count unsettled runtime records once, across all three engines.

        Hysteria2 uses XrayClient records too. Aggregate in SQL rather than
        loading peers or credentials (including their keys) into this listing.
        These are control-plane states, not an observation of the agent.
        """
        runtimes = union_all(
            select(WireGuardPeer.vpn_server_id, WireGuardPeer.state),
            select(XrayClient.vpn_server_id, XrayClient.state),
        ).subquery()
        counts = (
            select(
                runtimes.c.vpn_server_id,
                func.count()
                .filter(runtimes.c.state.in_(("requested", "applying")))
                .label("pending_provisions"),
                func.count().filter(runtimes.c.state == "revoking").label("pending_revocations"),
                func.count().filter(runtimes.c.state == "failed").label("failed_records"),
            )
            .where(runtimes.c.state.in_(("requested", "applying", "revoking", "failed")))
            .group_by(runtimes.c.vpn_server_id)
            .subquery()
        )
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(
                        VPNServer.id,
                        VPNServer.code,
                        func.coalesce(counts.c.pending_provisions, 0),
                        func.coalesce(counts.c.pending_revocations, 0),
                        func.coalesce(counts.c.failed_records, 0),
                    )
                    .outerjoin(counts, counts.c.vpn_server_id == VPNServer.id)
                    .order_by(VPNServer.code)
                )
            ).all()
        return [VpnServerReconciliationEntry(*row) for row in rows]

    async def list_reconciliation_history(
        self,
        *,
        server_id: UUID | None = None,
        target_id: UUID | None = None,
        outcome: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> ReconciliationHistoryPage:
        conditions: list[ColumnElement[bool]] = []
        if server_id is not None:
            conditions.append(ReconciliationRecord.vpn_server_id == server_id)
        if target_id is not None:
            conditions.append(ReconciliationRecord.target_id == target_id)
        if outcome is not None:
            conditions.append(ReconciliationRecord.outcome == outcome)
        # ponytail: global history sorts retained records; add a checked_at/id
        # index if history volume makes this exceed the database timeout.
        statement = (
            select(ReconciliationRecord, VPNServer.code)
            .join(VPNServer, VPNServer.id == ReconciliationRecord.vpn_server_id)
            .where(*conditions)
            .order_by(ReconciliationRecord.checked_at.desc(), ReconciliationRecord.id.desc())
            .limit(max(1, min(limit, 100)))
            .offset(max(0, offset))
        )
        async with self._session_factory() as session:
            rows = (await session.execute(statement)).all()
            total = await session.scalar(
                select(func.count()).select_from(ReconciliationRecord).where(*conditions)
            )
        return ReconciliationHistoryPage(
            items=[
                ReconciliationHistoryEntry(
                    id=row.id,
                    server_id=row.vpn_server_id,
                    server_code=code,
                    target_kind=row.target_kind,
                    target_id=row.target_id,
                    desired_generation=row.desired_generation,
                    observed_generation=row.observed_generation,
                    outcome=row.outcome,
                    checked_at=row.checked_at,
                    error_code=row.error_code,
                )
                for row, code in rows
            ],
            total=total or 0,
        )

    async def get_vpn_server_health(self) -> list[VpnServerHealthEntry]:
        """Live agent health for every configured server, checked in parallel so
        total wall time stays bounded by the request timeout, not server count."""

        agent_client_builder = self._agent_client_builder
        if agent_client_builder is None:
            raise RuntimeError("agent_client_builder is not configured")
        async with self._session_factory() as session:
            rows = (await session.scalars(select(VPNServer).order_by(VPNServer.code))).all()
        return list(
            await asyncio.gather(*(self._check_one(row, agent_client_builder) for row in rows))
        )

    async def get_vpn_server_xray_health(self) -> list[VpnServerXrayHealthEntry]:
        """Probe each server with an enabled Xray capability once.

        Maintenance/disabled servers may still have working listeners.
        The agent probes its loopback XHTTP listener, not every transport
        or the separate Hysteria2 process.
        """
        agent_client_builder = self._agent_client_builder
        if agent_client_builder is None:
            raise RuntimeError("agent_client_builder is not configured")
        enabled_servers = (
            select(ServerProtocolCapability.vpn_server_id)
            .join(
                ProtocolProfile, ProtocolProfile.id == ServerProtocolCapability.protocol_profile_id
            )
            .join(Protocol, Protocol.id == ProtocolProfile.protocol_id)
            .where(
                ServerProtocolCapability.state == CapabilityState.ENABLED.value,
                Protocol.engine == ProtocolEngine.XRAY.value,
            )
        )
        async with self._session_factory() as session:
            servers = (
                await session.scalars(
                    select(VPNServer)
                    .where(VPNServer.id.in_(enabled_servers))
                    .order_by(VPNServer.code)
                )
            ).all()
        return list(
            await asyncio.gather(
                *(self._check_xray(server, agent_client_builder) for server in servers)
            )
        )

    async def _check_xray(
        self, server: VPNServer, agent_client_builder: AgentClientBuilder
    ) -> VpnServerXrayHealthEntry:
        started_at = self._monotonic()
        try:
            async with agent_client_builder(server.agent_host, server.agent_port) as agent:
                response = await agent.xray_health(XrayHealthRequest(correlation_id=uuid4()))
        except (
            AgentUnreachable,
            AgentResponseAmbiguous,
            AgentResponseInvalid,
            AgentRejected,
        ) as error:
            # Do not expose exception messages or rejected response bodies.
            error_code = (
                "agent_unreachable"
                if isinstance(error, AgentUnreachable)
                else "agent_rejected"
                if isinstance(error, AgentRejected)
                else "agent_response_ambiguous"
                if isinstance(error, AgentResponseAmbiguous)
                else "agent_response_invalid"
            )
            return VpnServerXrayHealthEntry(
                server.id,
                server.code,
                "unreachable",
                self._clock(),
                None,
                None,
                None,
                error_code,
            )
        return VpnServerXrayHealthEntry(
            server.id,
            server.code,
            response.state,
            response.observed_at,
            round((self._monotonic() - started_at) * 1000),
            response.agent_version,
            response.listener_up,
            response.error_code,
        )

    async def _check_one(
        self, server: VPNServer, agent_client_builder: AgentClientBuilder
    ) -> VpnServerHealthEntry:
        # The agent's own HealthResponse.latency_ms is never populated (it has
        # no round trip of its own to measure) -- we're the caller making the
        # network hop, so we measure it here instead.
        started_at = self._monotonic()
        try:
            async with agent_client_builder(server.agent_host, server.agent_port) as agent:
                response = await agent.health(HealthRequest(correlation_id=uuid4()))
        except (
            AgentUnreachable,
            AgentResponseAmbiguous,
            AgentResponseInvalid,
            AgentRejected,
        ):
            return VpnServerHealthEntry(
                server_id=server.id,
                code=server.code,
                state="unreachable",
                observed_at=self._clock(),
                latency_ms=None,
                agent_version=None,
                interface_up=None,
                peer_count=None,
            )
        latency_ms = round((self._monotonic() - started_at) * 1000)
        return VpnServerHealthEntry(
            server_id=server.id,
            code=server.code,
            state=response.state,
            observed_at=response.observed_at,
            latency_ms=latency_ms,
            agent_version=response.agent_version,
            interface_up=response.interface_up,
            peer_count=response.peer_count,
        )
