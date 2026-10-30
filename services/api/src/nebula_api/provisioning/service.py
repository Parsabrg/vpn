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
import secrets
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
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    RevokeDeviceRequest,
    RevokeXrayClientRequest,
)
from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.dns_profiles import effective_profile
from nebula_api.models.identity import Device, User
from nebula_api.models.operations import AgentOperation
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer, XrayClient
from nebula_api.models.topology import (
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
from nebula_api.provisioning.xray_credentials import (
    EncryptedXrayCredential,
    XrayCredentialEncryptionError,
    decrypt_xray_credential,
    encrypt_xray_credential,
    key_fingerprint,
)
from nebula_api.settings import Settings

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

# AdGuard DNS's default filtering resolver -- blocks ads, trackers, and known
# malware/phishing domains at resolution time, same mechanism (and same
# provider) as the working ad-blocking VPN config this was modeled on. Purely
# advisory to the client (WireGuard's own server never enforces or even sees
# a peer's DNS setting), and applied only when the caller picked one of the
# "-adblock" sibling profiles rather than the plain one.
# IPv4 only: this interface carries no IPv6 -- the server address is a v4
# /24 -- so a v6 resolver here is a resolver the tunnel cannot reach, and
# every lookup pays for the attempt before falling back. Same reasoning as
# the Xray client's own resolver list (apps/mobile/lib/core/xray/xray_config.dart).
_AD_BLOCK_DNS_SERVER = "94.140.14.14"


class ProvisioningError(Exception):
    """Base class for all provisioning failures."""


class ServerUnderMaintenance(ProvisioningError):
    """The server exists and is the account's, but takes no new connections."""


class ProvisioningRejected(ProvisioningError):
    """Stable denial for invalid, not-found, or out-of-scope requests."""

    def __init__(self, detail: str = "Request was not accepted") -> None:
        super().__init__(detail)


class TrafficQuotaExhausted(ProvisioningRejected):
    """The account has spent its traffic allowance.

    Told plainly, unlike the other refusals here. Those are deliberately
    opaque because the thing refused is not the caller's to know about -- a
    server they cannot reach, a profile that is not theirs. This one is
    entirely their own state, and a person who cannot connect deserves to be
    told it is because their data ran out rather than left to guess.
    """

    def __init__(self) -> None:
        super().__init__("Data limit reached")


class ProvisioningRateLimited(ProvisioningRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request was not accepted")
        self.retry_after_seconds = retry_after_seconds


class OperationInProgress(ProvisioningRejected):
    def __init__(self) -> None:
        super().__init__("A WireGuard operation is already in progress for this device")


class XrayOperationInProgress(ProvisioningRejected):
    def __init__(self) -> None:
        super().__init__("An Xray operation is already in progress for this device")


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


@dataclass(frozen=True, slots=True)
class RequestXrayClientResult:
    client_id: UUID
    uuid: UUID
    server_address: str
    port: int
    sni: str
    transport: str
    transport_security: str
    # At most one is set, matching `transport` -- xhttp/websocket carry a
    # path, grpc carries a service name, raw/hysteria carry neither.
    path: str | None
    service_name: str | None
    # Hysteria2 only -- the inbound's Salamander obfuscation password, so the
    # mobile client can render a matching `udpmasks` block. Every other
    # transport leaves this unset.
    obfs_password: str | None
    # True when the caller picked this transport's "-adblock" sibling
    # profile -- the mobile app uses this to decide whether to add a `dns`
    # module to the client-side Xray config it renders locally.
    ad_block: bool
    # Shadowsocks-2022 only: the outbound's protocol, method and password.
    protocol: str = "vless"
    method: str | None = None
    password: str | None = None
    # VLESS Encryption only: the client's `encryption` string.
    encryption: str | None = None


@dataclass(frozen=True, slots=True)
class RevokeXrayClientResult:
    client_id: UUID
    revoked_at: datetime


class ProvisioningService:
    """Own WireGuard peer provisioning/revocation and their audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        settings: Settings,
        agent_client_builder: AgentClientBuilder,
        key_material: AuthKeyMaterial,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._settings = settings
        self._agent_client_builder = agent_client_builder
        self._keys = key_material
        self._clock = clock

    async def request_peer(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        server_code: str,
        protocol_profile_code: str,
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
            await self._require_traffic_allowance(session, user_id)

            profile = await self._require_wireguard_profile(session, protocol_profile_code)
            server, capability = await self._require_active_server(session, server_code, profile.id)
            await self._require_permission(session, user_id, profile.id, now)
            await self._require_assignment(session, user_id, server.id, now)

            existing_peer = await session.scalar(
                select(WireGuardPeer)
                .where(
                    WireGuardPeer.device_id == device.id,
                    WireGuardPeer.state.in_(_LIVE_PEER_STATES),
                )
                .with_for_update()
            )
            if existing_peer is not None and existing_peer.state != ProvisioningState.ACTIVE.value:
                raise OperationInProgress()

            if existing_peer is not None:
                # Reconnecting an already-active peer -- reuse its identity
                # instead of rejecting outright, mirroring the Xray path's
                # same fix. A device toggling the VPN off and back on is
                # normal usage, not something the app can reliably detect in
                # advance (its local state doesn't survive a
                # restart/reinstall, but the server's does). The caller's
                # freshly-supplied public_key is always authoritative here --
                # it is derived from whatever private key the app currently
                # holds, so adopting it (a no-op if unchanged, a real re-key
                # if the app generated a new keypair since) is correct either
                # way; unlike Xray's UUID this is not secret material, so no
                # decryption is needed to reuse it.
                credential = await session.scalar(
                    select(DeviceProtocolCredential)
                    .where(DeviceProtocolCredential.id == existing_peer.credential_id)
                    .with_for_update()
                )
                if credential is None:
                    raise ProvisioningRejected()
                peer = existing_peer
                peer.public_key = public_key
                # The reconnect may have picked a different WireGuard
                # profile than last time (e.g. switching to/from the
                # ad-block sibling) -- there is only ever one live peer per
                # device (uq_wireguard_peers_live_device is device-scoped,
                # not profile-scoped, unlike Xray), so the existing row is
                # reassigned to whichever profile was just requested rather
                # than silently keeping its old one. credential and peer
                # must move together: WireGuardPeer's own FK to
                # DeviceProtocolCredential is a composite key that includes
                # protocol_profile_id.
                peer.protocol_profile_id = profile.id
                credential.protocol_profile_id = profile.id
                address = ip_address(peer.assigned_address)
                desired_generation = peer.applied_generation + 1
                peer.state = ProvisioningState.APPLYING.value
                credential.state = ProvisioningState.APPLYING.value
            else:
                # Both the capacity check and the address allocation must
                # happen under this server's allocation lock: without it two
                # concurrent requests could each observe the last free slot
                # and overshoot the configured cap by one.
                await self._lock_server_allocation(session, server.id)
                await self._require_capacity(session, server, capability)
                address = await self._allocate_address(session, server)
                desired_generation = 1

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
                desired_generation=desired_generation,
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
            ad_block = profile.ad_block

        try:
            async with self._agent_client_builder(agent_host, agent_port) as agent:
                response = await agent.provision_device(
                    ProvisionDeviceRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=request_id,
                        target_kind="wireguard_peer",
                        target_id=peer_id,
                        desired_generation=desired_generation,
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
            ad_block=ad_block,
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
                removal_pending=True,
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
                removal_pending=True,
            )
            raise ProvisioningRejected()

        return await self._finalize_revoke_success(
            peer_id=peer_id,
            credential_id=credential_id,
            operation_id=operation_id,
            user_id=user_id,
            request_id=request_id,
        )

    async def request_xray_client(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        server_code: str,
        protocol_profile_code: str,
        request_id: UUID,
        network_prefix: str,
    ) -> RequestXrayClientResult:
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
            await self._require_traffic_allowance(session, user_id)

            profile = await self._require_xray_profile(session, protocol_profile_code)
            server, capability = await self._require_active_server(session, server_code, profile.id)
            await self._require_permission(session, user_id, profile.id, now)
            await self._require_assignment(session, user_id, server.id, now)

            # Scoped by protocol_profile_id, not just device_id -- a device
            # can hold a live XrayClient per profile simultaneously (e.g. one
            # over XHTTP and one over Hysteria2 at once), matching
            # uq_xray_clients_live_device_profile's own partial-unique index.
            existing_client = await session.scalar(
                select(XrayClient)
                .where(
                    XrayClient.device_id == device.id,
                    XrayClient.protocol_profile_id == profile.id,
                    XrayClient.state.in_(_LIVE_PEER_STATES),
                )
                .with_for_update()
            )
            if (
                existing_client is not None
                and existing_client.state != ProvisioningState.ACTIVE.value
            ):
                raise XrayOperationInProgress()

            if existing_client is not None:
                # Reconnecting an already-active client -- reuse its identity
                # instead of rejecting outright. The app's local state does not
                # survive a restart/reinstall, but server-side state does; a
                # user turning the VPN off and back on should not need to know
                # whether the server thinks a client already exists. Capacity
                # was already spent on this client when it was first
                # provisioned, so no new allocation lock/capacity check runs
                # here -- only the fresh-client branch below spends a slot.
                credential = await session.scalar(
                    select(DeviceProtocolCredential)
                    .where(DeviceProtocolCredential.id == existing_client.credential_id)
                    .with_for_update()
                )
                if credential is None:
                    raise ProvisioningRejected()
                try:
                    client_uuid = decrypt_xray_credential(
                        EncryptedXrayCredential(
                            key_version=int(credential.key_version or 0),
                            nonce=credential.nonce or b"",
                            ciphertext=credential.ciphertext or b"",
                        ),
                        device_id=device.id,
                        credential_id=credential.id,
                        key_ring=self._keys.xray_encryption_keys,
                    )
                except (XrayCredentialEncryptionError, ValueError):
                    raise ProvisioningRejected() from None

                client = existing_client
                desired_generation = client.applied_generation + 1
                client.state = ProvisioningState.APPLYING.value
                credential.state = ProvisioningState.APPLYING.value
            else:
                # Mirrors _lock_server_allocation/_require_capacity's WireGuard
                # pairing: this server's xray-client count and capacity check
                # must happen under one lock, or two concurrent requests could
                # each observe the last free slot and overshoot the cap by one.
                await self._lock_xray_allocation(session, server.id)
                await self._require_xray_capacity(session, server, capability)

                client_uuid = uuid4()
                desired_generation = 1

                credential = DeviceProtocolCredential(
                    device_id=device.id,
                    protocol_profile_id=profile.id,
                    vpn_server_id=server.id,
                    kind="xray_bearer",
                    state=ProvisioningState.REQUESTED.value,
                    generation=1,
                    issued_at=now,
                )
                session.add(credential)
                await session.flush()

                envelope = encrypt_xray_credential(
                    client_uuid,
                    device_id=device.id,
                    credential_id=credential.id,
                    key_version=self._settings.xray_key_version,
                    key_ring=self._keys.xray_encryption_keys,
                )
                credential.ciphertext = envelope.ciphertext
                credential.nonce = envelope.nonce
                credential.key_version = str(envelope.key_version)
                # Which key, not just which version. A key replaced without a
                # version bump is otherwise invisible until its credentials
                # stop decrypting, with nothing to say when or why.
                credential.key_fingerprint = key_fingerprint(
                    self._keys.xray_encryption_keys[self._settings.xray_key_version]
                )

                client = XrayClient(
                    credential_id=credential.id,
                    device_id=device.id,
                    protocol_profile_id=profile.id,
                    vpn_server_id=server.id,
                    opaque_label=_generate_opaque_label(),
                    state=ProvisioningState.APPLYING.value,
                )
                session.add(client)
                await session.flush()

            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=request_id,
                operation_kind="provision_device",
                target_kind="xray_client",
                target_id=client.id,
                state=OperationState.RUNNING.value,
                desired_generation=desired_generation,
                request_fingerprint=_fingerprint(
                    "provision_device", str(client.id), client.opaque_label
                ),
                requested_at=now,
                started_at=now,
            )
            session.add(operation)
            await session.flush()
            await session.commit()

            agent_host, agent_port = server.agent_host, server.agent_port
            client_id, credential_id, operation_id = client.id, credential.id, operation.id
            idempotency_key = operation.idempotency_key
            # The DB profile the caller picked may be an ad_block sibling
            # (e.g. "vless-xhttp-tls-adblock") that the agent has never
            # heard of -- it only ever knows the real underlying inbound's
            # code. agent_profile_code redirects to that real code; every
            # non-sibling profile has it unset, so it just falls back to
            # its own code unchanged.
            agent_profile_code = profile.agent_profile_code or profile.code
            ad_block = profile.ad_block

        try:
            async with self._agent_client_builder(agent_host, agent_port) as agent:
                response = await agent.provision_xray_client(
                    ProvisionXrayClientRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=request_id,
                        target_kind="xray_client",
                        target_id=client_id,
                        desired_generation=desired_generation,
                        client_uuid=client_uuid,
                        protocol_profile_code=agent_profile_code,
                    )
                )
        except (AgentResponseAmbiguous, AgentResponseInvalid):
            _LOGGER.warning(
                "agent response ambiguous during xray client provisioning",
                extra={"operation_id": str(operation_id)},
            )
            raise ProvisioningAmbiguous() from None
        except (AgentUnreachable, AgentRejected) as error:
            await self._finalize_xray_failure(
                client_id=client_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=_agent_error_code(error),
            )
            raise ProvisioningRejected() from None

        if response.state == "failed":
            await self._finalize_xray_failure(
                client_id=client_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=response.error_code or "agent_rejected",
            )
            raise ProvisioningRejected()

        return await self._finalize_xray_provision_success(
            client_id=client_id,
            credential_id=credential_id,
            operation_id=operation_id,
            user_id=user_id,
            request_id=request_id,
            client_uuid=client_uuid,
            response=response,
            ad_block=ad_block,
        )

    async def revoke_xray_client(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        server_code: str,
        protocol_profile_code: str,
        network_prefix: str,
        request_id: UUID,
    ) -> RevokeXrayClientResult:
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

            profile = await self._require_xray_profile(session, protocol_profile_code)

            client = await session.scalar(
                select(XrayClient)
                .where(
                    XrayClient.device_id == device.id,
                    XrayClient.vpn_server_id == server.id,
                    XrayClient.protocol_profile_id == profile.id,
                    XrayClient.state.in_(_LIVE_PEER_STATES),
                )
                .with_for_update()
            )
            if client is None:
                raise ProvisioningRejected()
            if client.state != ProvisioningState.ACTIVE.value:
                raise XrayOperationInProgress()

            credential = await session.scalar(
                select(DeviceProtocolCredential)
                .where(DeviceProtocolCredential.id == client.credential_id)
                .with_for_update()
            )
            if credential is None:
                raise ProvisioningRejected()

            try:
                client_uuid = decrypt_xray_credential(
                    EncryptedXrayCredential(
                        key_version=int(credential.key_version or 0),
                        nonce=credential.nonce or b"",
                        ciphertext=credential.ciphertext or b"",
                    ),
                    device_id=device.id,
                    credential_id=credential.id,
                    key_ring=self._keys.xray_encryption_keys,
                )
            except (XrayCredentialEncryptionError, ValueError):
                raise ProvisioningRejected() from None

            client.state = ProvisioningState.REVOKING.value
            credential.state = ProvisioningState.REVOKING.value

            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=request_id,
                operation_kind="revoke_device",
                target_kind="xray_client",
                target_id=client.id,
                state=OperationState.RUNNING.value,
                desired_generation=client.applied_generation,
                request_fingerprint=_fingerprint(
                    "revoke_device", str(client.id), client.opaque_label
                ),
                requested_at=now,
                started_at=now,
            )
            session.add(operation)
            await session.flush()
            await session.commit()

            agent_host, agent_port = server.agent_host, server.agent_port
            client_id, credential_id, operation_id = client.id, credential.id, operation.id
            idempotency_key = operation.idempotency_key
            desired_generation = client.applied_generation
            agent_profile_code = profile.agent_profile_code or profile.code

        try:
            async with self._agent_client_builder(agent_host, agent_port) as agent:
                response = await agent.revoke_xray_client(
                    RevokeXrayClientRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=request_id,
                        target_kind="xray_client",
                        target_id=client_id,
                        client_uuid=client_uuid,
                        protocol_profile_code=agent_profile_code,
                        desired_generation=desired_generation,
                    )
                )
        except (AgentResponseAmbiguous, AgentResponseInvalid):
            _LOGGER.warning(
                "agent response ambiguous during xray client revocation",
                extra={"operation_id": str(operation_id)},
            )
            raise ProvisioningAmbiguous() from None
        except (AgentUnreachable, AgentRejected) as error:
            await self._finalize_xray_failure(
                client_id=client_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=_agent_error_code(error),
                removal_pending=True,
            )
            raise ProvisioningRejected() from None

        if response.state == "failed":
            await self._finalize_xray_failure(
                client_id=client_id,
                credential_id=credential_id,
                operation_id=operation_id,
                user_id=user_id,
                request_id=request_id,
                error_code=response.error_code or "agent_rejected",
                removal_pending=True,
            )
            raise ProvisioningRejected()

        return await self._finalize_xray_revoke_success(
            client_id=client_id,
            credential_id=credential_id,
            operation_id=operation_id,
            user_id=user_id,
            request_id=request_id,
        )

    async def _require_traffic_allowance(self, session: AsyncSession, user_id: UUID) -> None:
        """Refuse an account whose allowance the sweep found spent.

        Reads the mark the enforcement sweep leaves rather than recomputing
        usage here. Recomputing would decrypt every credential this account
        holds on a path that runs whenever somebody presses Connect, to
        produce an answer that could only be as fresh as the last poll
        anyway -- the sweep is where the measurement belongs, and this is
        where its verdict is applied.
        """

        exhausted = await session.scalar(select(User.quota_exhausted_at).where(User.id == user_id))
        if exhausted is not None:
            raise TrafficQuotaExhausted()

    async def _require_wireguard_profile(
        self, session: AsyncSession, protocol_profile_code: str
    ) -> ProtocolProfile:
        """Thin, WireGuard-specific wrapper over _require_profile -- kept as
        its own method (rather than every WireGuard call site calling
        _require_profile directly) so a future WireGuard-only invariant
        (e.g. reasserting Protocol.engine) has one place to live."""

        return await self._require_profile(session, protocol_profile_code)

    async def _require_xray_profile(
        self, session: AsyncSession, protocol_profile_code: str
    ) -> ProtocolProfile:
        """Thin, Xray-specific wrapper over _require_profile -- see
        _require_wireguard_profile's docstring."""

        return await self._require_profile(session, protocol_profile_code)

    async def _require_profile(
        self, session: AsyncSession, protocol_profile_code: str
    ) -> ProtocolProfile:
        """Looks up any implemented ProtocolProfile by its own profile code
        -- e.g. "wireguard-native", "wireguard-adblock", "vless-xhttp-tls",
        "hysteria2" -- rather than by protocol code, since one Protocol
        (e.g. "vless", "wireguard") can own several profiles: one per
        transport, plus each transport's ad_block sibling."""

        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.code == protocol_profile_code,
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
        if server is not None and server.state == ServerState.MAINTENANCE.value:
            raise ServerUnderMaintenance("This server is under maintenance. Try again later.")
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

        Only live peers count: a revoked or failed peer frees both its
        device slot and its address (see `_allocate_address`), matching
        `_LIVE_PEER_STATES` everywhere it's used on this table. Callers must
        already hold this server's allocation lock.
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

    async def _require_xray_capacity(
        self,
        session: AsyncSession,
        server: VPNServer,
        capability: ServerProtocolCapability,
    ) -> None:
        """Mirrors _require_capacity for the Xray/VLESS profile's own
        XrayClient rows -- a separate count from WireGuardPeer's, since each
        protocol has its own ServerProtocolCapability row and cap. Callers
        must already hold this server's xray allocation lock."""

        live_clients = (
            await session.scalar(
                select(func.count())
                .select_from(XrayClient)
                .where(
                    XrayClient.vpn_server_id == server.id,
                    XrayClient.state.in_(_LIVE_PEER_STATES),
                )
            )
            or 0
        )
        effective_limit = server.maximum_devices
        if capability.capacity_limit is not None:
            effective_limit = min(effective_limit, capability.capacity_limit)
        if live_clients >= effective_limit:
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

    async def _lock_xray_allocation(self, session: AsyncSession, server_id: UUID) -> None:
        """Serializes xray-client capacity checking per server, mirroring
        _lock_server_allocation under a distinct advisory-lock namespace --
        there is no address to allocate here, only a count to check."""

        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('nebula.xray_client_alloc'), hashtext(:server_id))"
            ),
            {"server_id": str(server_id)},
        )

    async def _allocate_address(self, session: AsyncSession, server: VPNServer) -> IPAddress:
        """Callers must already hold this server's allocation lock. Only
        live peers hold their address -- a revoked or failed peer's address
        is free for reuse (uq_wireguard_peers_server_address_live enforces
        this at the DB level too)."""

        if server.wireguard_client_pool is None:
            raise ProvisioningRejected()
        existing = (
            await session.scalars(
                select(WireGuardPeer.assigned_address).where(
                    WireGuardPeer.vpn_server_id == server.id,
                    WireGuardPeer.state.in_(_LIVE_PEER_STATES),
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
        ad_block: bool,
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
            # Purely client-side advice (the WireGuard server itself never
            # enforces or even sees this) -- overriding it here, after the
            # agent's own response, is enough to make the ad-block profile
            # do something real, no agent changes needed at all.
            client_dns=_AD_BLOCK_DNS_SERVER if ad_block else response.client_dns,
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
        removal_pending: bool = False,
    ) -> None:
        now = self._now()
        async with self._session_factory() as session:
            peer, credential, operation = await self._lock_triple(
                session, peer_id, credential_id, operation_id
            )
            # A failed attempt does not cancel removal intent.
            pending_state = (
                ProvisioningState.REVOKING.value
                if removal_pending
                else ProvisioningState.FAILED.value
            )
            peer.state = pending_state
            credential.state = pending_state
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
                peer_credential_reason=pending_state,
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

    async def _lock_xray_triple(
        self, session: AsyncSession, client_id: UUID, credential_id: UUID, operation_id: UUID
    ) -> tuple[XrayClient, DeviceProtocolCredential, AgentOperation]:
        client = await session.scalar(
            select(XrayClient).where(XrayClient.id == client_id).with_for_update()
        )
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == credential_id)
            .with_for_update()
        )
        operation = await session.scalar(
            select(AgentOperation).where(AgentOperation.id == operation_id).with_for_update()
        )
        if client is None or credential is None or operation is None:
            raise ProvisioningError("provisioning rows disappeared mid-finalization")
        return client, credential, operation

    async def _finalize_xray_provision_success(
        self,
        *,
        client_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
        client_uuid: UUID,
        response: ProvisionXrayClientResponse,
        ad_block: bool,
    ) -> RequestXrayClientResult:
        now = self._now()
        async with self._session_factory() as session:
            client, credential, operation = await self._lock_xray_triple(
                session, client_id, credential_id, operation_id
            )
            client.state = ProvisioningState.ACTIVE.value
            client.applied_generation = response.applied_generation
            client.applied_at = now
            credential.state = ProvisioningState.ACTIVE.value
            operation.state = OperationState.SUCCEEDED.value
            operation.finished_at = now
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=client.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="succeeded",
                peer_credential_reason="activated",
                peer_target_kind="xray_client",
            )
            await session.commit()
        return RequestXrayClientResult(
            client_id=client_id,
            uuid=client_uuid,
            server_address=response.server_address,
            port=response.port,
            sni=response.sni,
            transport=response.transport,
            transport_security=response.transport_security,
            path=response.path,
            service_name=response.service_name,
            obfs_password=response.obfs_password,
            protocol=response.protocol,
            method=response.method,
            password=response.password,
            encryption=response.encryption,
            ad_block=ad_block,
        )

    async def dns_profile_for(self, *, user_id: UUID, device_id: UUID) -> str:
        """The DNS profile this device's tunnels get: its own, else its
        account's. "default" when either row is gone -- the caller has just
        been issued a credential for it, so that only happens in a race."""

        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(User.dns_profile, Device.dns_profile)
                    .join(Device, Device.user_id == User.id)
                    .where(User.id == user_id, Device.id == device_id)
                )
            ).first()
        if row is None:
            return "default"
        return effective_profile(row[0], row[1])

    async def _finalize_xray_revoke_success(
        self,
        *,
        client_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
    ) -> RevokeXrayClientResult:
        now = self._now()
        async with self._session_factory() as session:
            client, credential, operation = await self._lock_xray_triple(
                session, client_id, credential_id, operation_id
            )
            client.state = ProvisioningState.REVOKED.value
            client.revoked_at = now
            credential.state = ProvisioningState.REVOKED.value
            credential.revoked_at = now
            operation.state = OperationState.SUCCEEDED.value
            operation.finished_at = now
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=client.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="succeeded",
                peer_credential_reason="revoked",
                peer_target_kind="xray_client",
            )
            await session.commit()
        return RevokeXrayClientResult(client_id=client_id, revoked_at=now)

    async def _finalize_xray_failure(
        self,
        *,
        client_id: UUID,
        credential_id: UUID,
        operation_id: UUID,
        user_id: UUID,
        request_id: UUID,
        error_code: str,
        removal_pending: bool = False,
    ) -> None:
        now = self._now()
        async with self._session_factory() as session:
            client, credential, operation = await self._lock_xray_triple(
                session, client_id, credential_id, operation_id
            )
            # A failed attempt does not cancel removal intent.
            pending_state = (
                ProvisioningState.REVOKING.value
                if removal_pending
                else ProvisioningState.FAILED.value
            )
            client.state = pending_state
            credential.state = pending_state
            operation.state = OperationState.FAILED.value
            operation.finished_at = now
            operation.error_code = error_code
            self._audit_transition(
                session,
                credential_id=credential.id,
                peer_id=client.id,
                operation_id=operation.id,
                user_id=user_id,
                request_id=request_id,
                outcome="failed",
                peer_credential_reason=pending_state,
                peer_target_kind="xray_client",
            )
            await session.commit()

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
        peer_target_kind: str = "wireguard_peer",
    ) -> None:
        for target_kind, target_id, event_code, reason_code in (
            ("device_credential", credential_id, "credential_changed", peer_credential_reason),
            (peer_target_kind, peer_id, "peer_changed", peer_credential_reason),
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


def _generate_opaque_label() -> str:
    """32 URL-safe characters -- comfortably inside xray_clients.opaque_label's
    ^[A-Za-z0-9_-]{16,64}$ constraint, with no ambiguity in the encoded
    alphabet the way secrets.token_hex's lowercase-only output would risk."""

    return secrets.token_urlsafe(24)


def _agent_error_code(error: AgentUnreachable | AgentRejected) -> str:
    if isinstance(error, AgentUnreachable):
        return "agent_unreachable"
    slug = _ERROR_CODE_DISALLOWED.sub("_", error.detail.strip().lower())
    slug = slug.strip("_.-")[:64]
    return slug or _ERROR_CODE_FALLBACK
