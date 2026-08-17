"""WireGuard peer provisioning: three-phase orchestration matching the
agent's crash-safety contract (agent_client/client.py's exception hierarchy)
around the address allocator and the mTLS agent client.

Phase A (one DB transaction) validates the request, allocates an address,
and writes the credential/peer/operation rows in their in-flight states
before ever calling the agent -- an "applying"/"running" row left behind by
a crash between Phase A and Phase C is exactly what the reconciliation pass
(Phase 1.6b M8) needs to detect and repair. Phase B calls the agent outside
any transaction. Phase C, a fresh transaction, finalizes state depending on
how Phase B ended: a clean result (success, a definite agent rejection, or
an unreachable agent) is always resolved to a terminal state; an ambiguous
result (a lost response) is deliberately left non-terminal, since guessing
wrong here would either strand a working peer as "failed" or silently paper
over one that was never actually applied.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address, ip_network
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.agent_client.client import (
    AgentClientBuilder,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentResponseInvalid,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    RevokeDeviceRequest,
)
from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device
from nebula_api.models.operations import AgentOperation
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import (
    CapabilityState,
    LifecycleState,
    OperationState,
    ProfileState,
    ProvisioningState,
    ServerState,
)
from nebula_api.provisioning.allocator import IPAddress, allocate_next_address
from nebula_api.settings import Settings
from nebula_api.topology_seed import WIREGUARD_PROTOCOL_CODE

Clock = Callable[[], datetime]

_LOGGER = logging.getLogger(__name__)

_LIVE_PEER_STATES = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
    ProvisioningState.REVOKING.value,
)

# Matches wireguard_peers.public_key_canonical's CHECK constraint exactly --
# duplicated from agent_client/models.py (a private name there) so a
# malformed key is rejected before Phase A ever writes a row, rather than
# only failing once Phase B tries to build the agent request.
_PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_ALL_ZERO_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# Matches agent_operations.error_code's CHECK constraint format.
_ERROR_CODE_DISALLOWED = re.compile(r"[^a-z0-9_.-]")
_ERROR_CODE_FALLBACK = "agent_error"


class ProvisioningError(Exception):
    """Base class for all provisioning failures."""


class ProvisioningRejected(ProvisioningError):
    """Stable denial for invalid, not-found, or out-of-scope requests."""

    def __init__(self, detail: str = "Request was not accepted") -> None:
        super().__init__(detail)


class ProvisioningRateLimited(ProvisioningRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request was not accepted")
        self.retry_after_seconds = retry_after_seconds


class DeviceAlreadyHasPeer(ProvisioningRejected):
    def __init__(self) -> None:
        super().__init__("Device already has a WireGuard peer")


class OperationInProgress(ProvisioningRejected):
    def __init__(self) -> None:
        super().__init__("A WireGuard operation is already in progress for this device")


class ProvisioningAmbiguous(ProvisioningError):
    """The agent's response was lost; the operation's outcome is unknown and
    is left for reconciliation. Callers should map this to a retryable
    error, not a definite failure."""

    def __init__(self) -> None:
        super().__init__("The VPN agent did not confirm this request; try again shortly")


@dataclass(frozen=True, slots=True)
class RequestPeerResult:
    peer_id: UUID
    assigned_address: str
    server_public_key: str
    listen_port: int
    public_endpoint: str
    client_dns: str
    client_allowed_ips: str
    persistent_keepalive_seconds: int


@dataclass(frozen=True, slots=True)
class RevokePeerResult:
    peer_id: UUID
    revoked_at: datetime


class ProvisioningService:
    """Own WireGuard peer provisioning/revocation and their audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        settings: Settings,
        agent_client_builder: AgentClientBuilder,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._settings = settings
        self._agent_client_builder = agent_client_builder
        self._clock = clock

    async def request_peer(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        server_code: str,
        public_key: str,
        network_prefix: str,
        request_id: UUID,
    ) -> RequestPeerResult:
        if not _PUBLIC_KEY_PATTERN.fullmatch(public_key) or public_key == _ALL_ZERO_PUBLIC_KEY:
            raise ProvisioningRejected()

        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(session, user_id, network_prefix, request_id)

            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user_id)
                .with_for_update()
            )
            if device is None or device.state is not LifecycleState.ACTIVE:
                raise ProvisioningRejected()

            profile = await self._require_wireguard_profile(session)
            server, capability = await self._require_active_server(session, server_code, profile.id)
            await self._require_permission(session, user_id, profile.id, now)
            await self._require_assignment(session, user_id, server.id, now)

            existing_peer = await session.scalar(
                select(WireGuardPeer).where(
                    WireGuardPeer.device_id == device.id,
                    WireGuardPeer.state.in_(_LIVE_PEER_STATES),
                )
            )
            if existing_peer is not None:
                raise DeviceAlreadyHasPeer()

            # Both the capacity check and the address allocation must happen
            # under this server's allocation lock: without it two concurrent
            # requests could each observe the last free slot and overshoot the
            # configured cap by one.
            await self._lock_server_allocation(session, server.id)
            await self._require_capacity(session, server, capability)
            address = await self._allocate_address(session, server)

            credential = DeviceProtocolCredential(
                device_id=device.id,
                protocol_profile_id=profile.id,
                vpn_server_id=server.id,
                kind="wireguard_public",
                state=ProvisioningState.REQUESTED.value,
                generation=1,
                issued_at=now,
            )
            session.add(credential)
            await session.flush()

            peer = WireGuardPeer(
                credential_id=credential.id,
                device_id=device.id,
                protocol_profile_id=profile.id,
                vpn_server_id=server.id,
                public_key=public_key,
                assigned_address=str(address),
                state=ProvisioningState.APPLYING.value,
            )
            session.add(peer)
            await session.flush()

            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=request_id,
                operation_kind="provision_device",
                target_kind="wireguard_peer",
                target_id=peer.id,
                state=OperationState.RUNNING.value,
                desired_generation=1,
                request_fingerprint=_fingerprint(
                    "provision_device", str(peer.id), public_key, str(address)
                ),
                requested_at=now,
                started_at=now,
            )
            session.add(operation)
            await session.flush()
            await session.commit()

            agent_host, agent_port = server.agent_host, server.agent_port
            peer_id, credential_id, operation_id = peer.id, credential.id, operation.id
            idempotency_key = operation.idempotency_key

        try:
            async with self._agent_client_builder(agent_host, agent_port) as agent:
                response = await agent.provision_device(
                    ProvisionDeviceRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=request_id,
                        target_kind="wireguard_peer",
                        target_id=peer_id,
                        desired_generation=1,
                        public_key=public_key,
                        assigned_address=address,
                    )
                )
        except (AgentResponseAmbiguous, AgentResponseInvalid):
            _LOGGER.warning(
                "agent response ambiguous during peer provisioning",
                extra={"operation_id": str(operation_id)},
            )
            raise ProvisioningAmbiguous() from None
        except (AgentUnreachable, AgentRejected) as error:
            await self._finalize_failure(
                peer_id=peer_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=_agent_error_code(error),
            )
            raise ProvisioningRejected() from None

        if response.state == "failed":
            await self._finalize_failure(
                peer_id=peer_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=response.error_code or "agent_rejected",
            )
            raise ProvisioningRejected()

        return await self._finalize_provision_success(
            peer_id=peer_id,
            credential_id=credential_id,
            operation_id=operation_id,
            user_id=user_id,
            request_id=request_id,
            assigned_address=str(address),
            response=response,
        )

    async def revoke_peer(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        server_code: str,
        network_prefix: str,
        request_id: UUID,
    ) -> RevokePeerResult:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(session, user_id, network_prefix, request_id)

            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user_id)
                .with_for_update()
            )
            if device is None:
                raise ProvisioningRejected()

            server = await session.scalar(select(VPNServer).where(VPNServer.code == server_code))
            if server is None:
                raise ProvisioningRejected()

            peer = await session.scalar(
                select(WireGuardPeer)
                .where(
                    WireGuardPeer.device_id == device.id,
                    WireGuardPeer.vpn_server_id == server.id,
                    WireGuardPeer.state.in_(_LIVE_PEER_STATES),
                )
                .with_for_update()
            )
            if peer is None:
                raise ProvisioningRejected()
            if peer.state != ProvisioningState.ACTIVE.value:
                raise OperationInProgress()

            credential = await session.scalar(
                select(DeviceProtocolCredential)
                .where(DeviceProtocolCredential.id == peer.credential_id)
                .with_for_update()
            )
            if credential is None:
                raise ProvisioningRejected()

            peer.state = ProvisioningState.REVOKING.value
            credential.state = ProvisioningState.REVOKING.value

            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=request_id,
                operation_kind="revoke_device",
                target_kind="wireguard_peer",
                target_id=peer.id,
                state=OperationState.RUNNING.value,
                desired_generation=peer.applied_generation,
                request_fingerprint=_fingerprint("revoke_device", str(peer.id), peer.public_key),
                requested_at=now,
                started_at=now,
            )
            session.add(operation)
            await session.flush()
            await session.commit()

            agent_host, agent_port = server.agent_host, server.agent_port
            peer_id, credential_id, operation_id = peer.id, credential.id, operation.id
            idempotency_key = operation.idempotency_key
            public_key, desired_generation = peer.public_key, peer.applied_generation

        try:
            async with self._agent_client_builder(agent_host, agent_port) as agent:
                response = await agent.revoke_device(
                    RevokeDeviceRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=request_id,
                        target_kind="wireguard_peer",
                        target_id=peer_id,
                        public_key=public_key,
                        desired_generation=desired_generation,
                    )
                )
        except (AgentResponseAmbiguous, AgentResponseInvalid):
            _LOGGER.warning(
                "agent response ambiguous during peer revocation",
                extra={"operation_id": str(operation_id)},
            )
            raise ProvisioningAmbiguous() from None
        except (AgentUnreachable, AgentRejected) as error:
            await self._finalize_failure(
                peer_id=peer_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=_agent_error_code(error),
            )
            raise ProvisioningRejected() from None

        if response.state == "failed":
            await self._finalize_failure(
                peer_id=peer_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=response.error_code or "agent_rejected",
            )
            raise ProvisioningRejected()

        return await self._finalize_revoke_success(
            peer_id=peer_id,
            credential_id=credential_id,
            operation_id=operation_id,
            user_id=user_id,
            request_id=request_id,
        )

    async def _require_wireguard_profile(self, session: AsyncSession) -> ProtocolProfile:
        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is None:
            raise ProvisioningRejected()
        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.state == ProfileState.IMPLEMENTED.value,
            )
        )
        if profile is None:
            raise ProvisioningRejected()
        return profile

    async def _require_active_server(
        self, session: AsyncSession, server_code: str, profile_id: UUID
    ) -> tuple[VPNServer, ServerProtocolCapability]:
        server = await session.scalar(select(VPNServer).where(VPNServer.code == server_code))
        if server is None or server.state != ServerState.ACTIVE.value:
            raise ProvisioningRejected()
        capability = await session.scalar(
            select(ServerProtocolCapability).where(
                ServerProtocolCapability.vpn_server_id == server.id,
                ServerProtocolCapability.protocol_profile_id == profile_id,
            )
        )
        if capability is None or capability.state != CapabilityState.ENABLED.value:
            raise ProvisioningRejected()
        return server, capability

    async def _require_capacity(
        self,
        session: AsyncSession,
        server: VPNServer,
        capability: ServerProtocolCapability,
    ) -> None:
        """Enforce the server's device cap and the capability's optional
        per-protocol cap, whichever is lower.

        Only live peers count: a revoked peer frees a device slot even though
        its address stays burned by `uq_wireguard_peers_server_address`, so
        capacity and address exhaustion are genuinely separate limits.
        Callers must already hold this server's allocation lock.
        """

        live_peers = (
            await session.scalar(
                select(func.count())
                .select_from(WireGuardPeer)
                .where(
                    WireGuardPeer.vpn_server_id == server.id,
                    WireGuardPeer.state.in_(_LIVE_PEER_STATES),
                )
            )
            or 0
        )
        effective_limit = server.maximum_devices
        if capability.capacity_limit is not None:
            effective_limit = min(effective_limit, capability.capacity_limit)
        if live_peers >= effective_limit:
            raise ProvisioningRejected()

    async def _require_permission(
        self, session: AsyncSession, user_id: UUID, profile_id: UUID, now: datetime
    ) -> None:
        permission = await session.scalar(
            select(UserProtocolPermission).where(
                UserProtocolPermission.user_id == user_id,
                UserProtocolPermission.protocol_profile_id == profile_id,
            )
        )
        if permission is None or permission.state != CapabilityState.ENABLED.value:
            raise ProvisioningRejected()
        if permission.expires_at is not None and permission.expires_at <= now:
            raise ProvisioningRejected()

    async def _require_assignment(
        self, session: AsyncSession, user_id: UUID, server_id: UUID, now: datetime
    ) -> None:
        assignment = await session.scalar(
            select(UserServerAssignment).where(
                UserServerAssignment.user_id == user_id,
                UserServerAssignment.vpn_server_id == server_id,
            )
        )
        if assignment is None or assignment.state != LifecycleState.ACTIVE.value:
            raise ProvisioningRejected()
        if assignment.expires_at is not None and assignment.expires_at <= now:
            raise ProvisioningRejected()

    async def _lock_server_allocation(self, session: AsyncSession, server_id: UUID) -> None:
        """Serialize capacity checking and address allocation per server. The
        address does not belong to any row until it is inserted, so there is
        nothing to row-lock -- this advisory lock is what makes the
        check-then-insert sequence safe. The 2-int overload namespaces it away
        from seed_admin.py's lock."""

        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('nebula.wireguard_address_alloc'), hashtext(:server_id))"
            ),
            {"server_id": str(server_id)},
        )

    async def _allocate_address(self, session: AsyncSession, server: VPNServer) -> IPAddress:
        """Callers must already hold this server's allocation lock."""

        if server.wireguard_client_pool is None:
            raise ProvisioningRejected()
        existing = (
            await session.scalars(
                select(WireGuardPeer.assigned_address).where(
                    WireGuardPeer.vpn_server_id == server.id
                )
            )
        ).all()
        address = allocate_next_address(
            pool=ip_network(server.wireguard_client_pool),
            gateway_address=(
                ip_address(server.wireguard_gateway_address)
                if server.wireguard_gateway_address is not None
                else None
            ),
            excluded_addresses=(ip_address(value) for value in existing),
        )
        if address is None:
            raise ProvisioningRejected()
        return address

    async def _require_rate_limit(
        self, session: AsyncSession, user_id: UUID, network_prefix: str, request_id: UUID
    ) -> None:
        if await self._redis.rate_limit(
            (
                RateBucket("device-provision", str(user_id)),
                RateBucket("device-provision-network", network_prefix),
            ),
            limit=self._settings.device_provision_rate_limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            return
        add_audit_event(
            session,
            actor_kind="user",
            actor_id=user_id,
            target_kind="user",
            target_id=user_id,
            event_code="auth_rate_limited",
            outcome="denied",
            request_id=request_id,
            reason_code="rate_limited",
        )
        await session.commit()
        raise ProvisioningRateLimited(self._settings.auth_rate_window_seconds)

    async def _finalize_provision_success(
        self,
        *,
        peer_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
        assigned_address: str,
        response: ProvisionDeviceResponse,
    ) -> RequestPeerResult:
        now = self._now()
        async with self._session_factory() as session:
            peer, credential, operation = await self._lock_triple(
                session, peer_id, credential_id, operation_id
            )
            peer.state = ProvisioningState.ACTIVE.value
            peer.applied_generation = response.applied_generation
            peer.applied_at = now
            credential.state = ProvisioningState.ACTIVE.value
            operation.state = OperationState.SUCCEEDED.value
            operation.finished_at = now
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=peer.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="succeeded",
                peer_credential_reason="activated",
            )
            await session.commit()
        return RequestPeerResult(
            peer_id=peer_id,
            assigned_address=assigned_address,
            server_public_key=response.server_public_key,
            listen_port=response.listen_port,
            public_endpoint=response.public_endpoint,
            client_dns=response.client_dns,
            client_allowed_ips=response.client_allowed_ips,
            persistent_keepalive_seconds=response.persistent_keepalive_seconds,
        )

    async def _finalize_revoke_success(
        self,
        *,
        peer_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
    ) -> RevokePeerResult:
        now = self._now()
        async with self._session_factory() as session:
            peer, credential, operation = await self._lock_triple(
                session, peer_id, credential_id, operation_id
            )
            peer.state = ProvisioningState.REVOKED.value
            peer.revoked_at = now
            credential.state = ProvisioningState.REVOKED.value
            credential.revoked_at = now
            operation.state = OperationState.SUCCEEDED.value
            operation.finished_at = now
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=peer.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="succeeded",
                peer_credential_reason="revoked",
            )
            await session.commit()
        return RevokePeerResult(peer_id=peer_id, revoked_at=now)

    async def _finalize_failure(
        self,
        *,
        peer_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
        error_code: str,
    ) -> None:
        now = self._now()
        async with self._session_factory() as session:
            peer, credential, operation = await self._lock_triple(
                session, peer_id, credential_id, operation_id
            )
            peer.state = ProvisioningState.FAILED.value
            credential.state = ProvisioningState.FAILED.value
            operation.state = OperationState.FAILED.value
            operation.finished_at = now
            operation.error_code = error_code
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=peer.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="failed",
                peer_credential_reason="failed",
            )
            await session.commit()

    async def _lock_triple(
        self, session: AsyncSession, peer_id: UUID, credential_id: UUID, operation_id: UUID
    ) -> tuple[WireGuardPeer, DeviceProtocolCredential, AgentOperation]:
        peer = await session.scalar(
            select(WireGuardPeer).where(WireGuardPeer.id == peer_id).with_for_update()
        )
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == credential_id)
            .with_for_update()
        )
        operation = await session.scalar(
            select(AgentOperation).where(AgentOperation.id == operation_id).with_for_update()
        )
        if peer is None or credential is None or operation is None:
            raise ProvisioningError("provisioning rows disappeared mid-finalization")
        return peer, credential, operation

    def _audit_transition(
        self,
        session: AsyncSession,
        *,
        credential_id: UUID,
        peer_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
        outcome: str,
        peer_credential_reason: str,
    ) -> None:
        for target_kind, target_id, event_code, reason_code in (
            ("device_credential", credential_id, "credential_changed", peer_credential_reason),
            ("wireguard_peer", peer_id, "peer_changed", peer_credential_reason),
            ("agent_operation", operation_id, "operation_changed", outcome),
        ):
            add_audit_event(
                session,
                actor_kind="user",
                actor_id=user_id,
                target_kind=target_kind,
                target_id=target_id,
                event_code=event_code,
                outcome=outcome,
                request_id=request_id,
                reason_code=reason_code,
            )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provisioning clock must be timezone aware")
        return value.astimezone(UTC)


def _fingerprint(*parts: str) -> str:
    return sha256("\x00".join(parts).encode()).hexdigest()


def _agent_error_code(error: AgentUnreachable | AgentRejected) -> str:
    if isinstance(error, AgentUnreachable):
        return "agent_unreachable"
    slug = _ERROR_CODE_DISALLOWED.sub("_", error.detail.strip().lower())
    slug = slug.strip("_.-")[:64]
    return slug or _ERROR_CODE_FALLBACK
