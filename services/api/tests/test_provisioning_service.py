import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Select
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.agent_client.client import (
    AgentClient,
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
    RevokeDeviceResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
)
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device
from nebula_api.models.operations import AgentOperation
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer, XrayClient
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
    ProfileState,
    ProvisioningState,
    ServerState,
)
from nebula_api.provisioning.service import (
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningRejected,
    ProvisioningService,
    ServerUnderMaintenance,
    XrayOperationInProgress,
)
from nebula_api.provisioning.xray_credentials import encrypt_xray_credential
from nebula_api.settings import Settings

USER_ID = uuid4()
DEVICE_ID = uuid4()
SERVER_ID = uuid4()
PROTOCOL_ID = uuid4()
PROFILE_ID = uuid4()
CLIENT_PUBLIC_KEY = "C" * 43 + "="
NETWORK_PREFIX = "203.0.113.0/24"


class FakeRedisAuthState:
    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[tuple[RateBucket, ...]] = []

    async def rate_limit(
        self, buckets: tuple[RateBucket, ...], *, limit: int, window_seconds: int
    ) -> bool:
        self.calls.append(buckets)
        return self.allow


class FakeAgentClient:
    """Records every call and either returns a canned response or raises."""

    def __init__(
        self,
        *,
        provision: ProvisionDeviceResponse | Exception | None = None,
        revoke: RevokeDeviceResponse | Exception | None = None,
        provision_xray: ProvisionXrayClientResponse | Exception | None = None,
        revoke_xray: RevokeXrayClientResponse | Exception | None = None,
    ) -> None:
        self.provision_result = provision
        self.revoke_result = revoke
        self.provision_xray_result = provision_xray
        self.revoke_xray_result = revoke_xray
        self.provision_calls: list[ProvisionDeviceRequest] = []
        self.revoke_calls: list[RevokeDeviceRequest] = []
        self.provision_xray_calls: list[ProvisionXrayClientRequest] = []
        self.revoke_xray_calls: list[RevokeXrayClientRequest] = []

    async def __aenter__(self) -> "FakeAgentClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        self.provision_calls.append(request)
        if isinstance(self.provision_result, Exception):
            raise self.provision_result
        assert self.provision_result is not None
        return self.provision_result

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        self.revoke_calls.append(request)
        if isinstance(self.revoke_result, Exception):
            raise self.revoke_result
        assert self.revoke_result is not None
        return self.revoke_result

    async def provision_xray_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        self.provision_xray_calls.append(request)
        if isinstance(self.provision_xray_result, Exception):
            raise self.provision_xray_result
        assert self.provision_xray_result is not None
        return self.provision_xray_result

    async def revoke_xray_client(
        self, request: RevokeXrayClientRequest
    ) -> RevokeXrayClientResponse:
        self.revoke_xray_calls.append(request)
        if isinstance(self.revoke_xray_result, Exception):
            raise self.revoke_xray_result
        assert self.revoke_xray_result is not None
        return self.revoke_xray_result


def _agent_builder(client: FakeAgentClient) -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, client)

    return _builder


def _never_called_agent_builder() -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        raise AssertionError("the agent should not have been called")

    return _builder


def _entity_of(statement: Select[Any]) -> type | None:
    return cast("type | None", statement.column_descriptions[0]["entity"])


def _added(session: MagicMock, model: type) -> Any:
    for call in reversed(session.add.call_args_list):
        row = call.args[0]
        if isinstance(row, model):
            return row
    raise AssertionError(f"no {model.__name__} was added")


def make_session(
    fixtures: dict[type, object | None],
    *,
    existing_addresses: list[str] | None = None,
    live_peer_count: int = 0,
) -> MagicMock:
    """A fake AsyncSession dispatching scalar() by queried entity type: a
    freshly `add()`-ed row of that type wins (most recent first), otherwise
    the static `fixtures` value for that type is returned. This lets one
    session stand in for every phase's separate transaction, since a row
    this flow just created is always preferred over a pre-existing fixture,
    and a row it only mutated in place (never re-added) still round-trips
    correctly through the fixtures fallback."""

    session = MagicMock(spec=AsyncSession)
    session.add = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()

    assigned: set[int] = set()

    async def _flush() -> None:
        for index, call in enumerate(session.add.call_args_list):
            if index in assigned:
                continue
            row = call.args[0]
            if getattr(row, "id", None) is None:
                row.id = uuid4()
            assigned.add(index)

    session.flush = AsyncMock(side_effect=_flush)

    async def _scalar(statement: Select[Any]) -> object | None:
        entity = _entity_of(statement)
        if entity is None:
            # An aggregate (select(func.count())) has no entity -- the only
            # one this service issues is the live-peer capacity count.
            return live_peer_count
        for call in reversed(session.add.call_args_list):
            row = call.args[0]
            if isinstance(row, entity):
                return row
        return fixtures.get(entity)

    session.scalar = AsyncMock(side_effect=_scalar)
    session.scalars = AsyncMock(
        return_value=MagicMock(all=MagicMock(return_value=existing_addresses or []))
    )
    return session


def make_session_factory(session: AsyncSession) -> SessionFactory:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        yield session

    def _factory() -> AbstractAsyncContextManager[AsyncSession]:
        return _scope()

    return cast(SessionFactory, _factory)


def _device(*, state: LifecycleState = LifecycleState.ACTIVE, user_id: UUID = USER_ID) -> MagicMock:
    device = MagicMock(spec=Device)
    device.id = DEVICE_ID
    device.user_id = user_id
    device.state = state
    return device


def _protocol() -> MagicMock:
    protocol = MagicMock(spec=Protocol)
    protocol.id = PROTOCOL_ID
    return protocol


def _profile(
    *,
    state: str = ProfileState.IMPLEMENTED.value,
    code: str = "vless-xhttp-tls",
    ad_block: bool = False,
    agent_profile_code: str | None = None,
) -> MagicMock:
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = PROFILE_ID
    profile.code = code
    profile.state = state
    # A bare MagicMock(spec=...) attribute is truthy by default -- these
    # must be real bool/str|None values, or every ad_block/agent_profile_code
    # branch in provisioning/service.py would silently take the "ad_block"
    # path regardless of what a test actually intends.
    profile.ad_block = ad_block
    profile.agent_profile_code = agent_profile_code
    return profile


def _server(
    *,
    state: str = ServerState.ACTIVE.value,
    pool: str | None = "203.0.113.0/24",
    gateway: str | None = "203.0.113.1",
    maximum_devices: int = 1000,
) -> MagicMock:
    server = MagicMock(spec=VPNServer)
    server.id = SERVER_ID
    server.code = "vps-1"
    server.state = state
    server.agent_host = "vps1.internal"
    server.agent_port = 9443
    server.wireguard_client_pool = pool
    server.wireguard_gateway_address = gateway
    server.maximum_devices = maximum_devices
    return server


def _capability(
    *, state: str = CapabilityState.ENABLED.value, capacity_limit: int | None = None
) -> MagicMock:
    capability = MagicMock(spec=ServerProtocolCapability)
    capability.state = state
    capability.capacity_limit = capacity_limit
    return capability


def _permission(
    *, state: str = CapabilityState.ENABLED.value, expires_at: datetime | None = None
) -> MagicMock:
    permission = MagicMock(spec=UserProtocolPermission)
    permission.state = state
    permission.expires_at = expires_at
    return permission


def _assignment(
    *, state: str = LifecycleState.ACTIVE.value, expires_at: datetime | None = None
) -> MagicMock:
    assignment = MagicMock(spec=UserServerAssignment)
    assignment.state = state
    assignment.expires_at = expires_at
    return assignment


def _live_peer(*, state: str = ProvisioningState.ACTIVE.value) -> MagicMock:
    peer = MagicMock(spec=WireGuardPeer)
    peer.id = uuid4()
    peer.credential_id = uuid4()
    peer.public_key = "D" * 43 + "="
    peer.assigned_address = "203.0.113.5"
    peer.state = state
    peer.applied_generation = 1
    return peer


def _credential_for(peer: MagicMock, *, state: str = ProvisioningState.ACTIVE.value) -> MagicMock:
    credential = MagicMock(spec=DeviceProtocolCredential)
    credential.id = peer.credential_id
    credential.state = state
    return credential


def _happy_fixtures(
    overrides: dict[type, object | None] | None = None,
) -> dict[type, object | None]:
    fixtures: dict[type, object | None] = {
        Device: _device(),
        Protocol: _protocol(),
        ProtocolProfile: _profile(),
        VPNServer: _server(),
        ServerProtocolCapability: _capability(),
        UserProtocolPermission: _permission(),
        UserServerAssignment: _assignment(),
        WireGuardPeer: None,
    }
    fixtures.update(overrides or {})
    return fixtures


def _provision_response(
    *,
    state: str = "active",
    applied_generation: int = 1,
    error_code: str | None = None,
) -> ProvisionDeviceResponse:
    return ProvisionDeviceResponse(
        state=cast(Any, state),
        applied_generation=applied_generation,
        error_code=error_code,
        server_public_key="B" * 43 + "=",
        listen_port=51820,
        public_endpoint="vps1.example.com:51820",
        client_dns="10.77.0.1",
        client_allowed_ips="0.0.0.0/0,::/0",
        persistent_keepalive_seconds=25,
    )


def _revoke_response(
    *,
    state: str = "revoked",
    applied_generation: int = 1,
    error_code: str | None = None,
) -> RevokeDeviceResponse:
    return RevokeDeviceResponse(
        state=cast(Any, state),
        applied_generation=applied_generation,
        error_code=error_code,
        revoked_at=datetime.now(UTC),
    )


def _xray_provision_response(
    *,
    state: str = "active",
    applied_generation: int = 1,
    error_code: str | None = None,
    transport: str = "xhttp",
    transport_security: str = "none",
    path: str | None = "/xhttp",
    service_name: str | None = None,
) -> ProvisionXrayClientResponse:
    return ProvisionXrayClientResponse(
        state=cast(Any, state),
        applied_generation=applied_generation,
        error_code=error_code,
        server_address="vps1.example.com",
        port=8445,
        sni="vps1.example.com",
        transport=cast(Any, transport),
        transport_security=cast(Any, transport_security),
        path=path,
        service_name=service_name,
    )


def _xray_revoke_response(
    *,
    state: str = "revoked",
    applied_generation: int = 1,
    error_code: str | None = None,
) -> RevokeXrayClientResponse:
    return RevokeXrayClientResponse(
        state=cast(Any, state),
        applied_generation=applied_generation,
        error_code=error_code,
        revoked_at=datetime.now(UTC),
    )


def _xray_live_client(*, state: str = ProvisioningState.ACTIVE.value) -> MagicMock:
    client = MagicMock(spec=XrayClient)
    client.id = uuid4()
    client.credential_id = uuid4()
    client.opaque_label = "a" * 32
    client.state = state
    client.applied_generation = 1
    return client


def _xray_credential_for(
    client: MagicMock,
    client_uuid: UUID,
    key_material: AuthKeyMaterial,
    *,
    state: str = ProvisioningState.ACTIVE.value,
) -> MagicMock:
    envelope = encrypt_xray_credential(
        client_uuid,
        device_id=DEVICE_ID,
        credential_id=client.credential_id,
        key_version=1,
        key_ring=key_material.xray_encryption_keys,
    )
    credential = MagicMock(spec=DeviceProtocolCredential)
    credential.id = client.credential_id
    credential.state = state
    credential.ciphertext = envelope.ciphertext
    credential.nonce = envelope.nonce
    credential.key_version = str(envelope.key_version)
    return credential


def _key_material() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(
        private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32}, {1: b"x" * 32}
    )


def make_service(
    session: AsyncSession,
    *,
    agent_builder: AgentClientBuilder | None = None,
    allow_rate_limit: bool = True,
    key_material: AuthKeyMaterial | None = None,
) -> ProvisioningService:
    return ProvisioningService(
        make_session_factory(session),
        cast(RedisAuthState, FakeRedisAuthState(allow=allow_rate_limit)),
        Settings(),
        agent_builder or _never_called_agent_builder(),
        key_material or _key_material(),
    )


async def _request_peer(service: ProvisioningService) -> Any:
    return await service.request_peer(
        user_id=USER_ID,
        device_id=DEVICE_ID,
        server_code="vps-1",
        protocol_profile_code="wireguard-native",
        public_key=CLIENT_PUBLIC_KEY,
        network_prefix=NETWORK_PREFIX,
        request_id=uuid4(),
    )


async def _revoke_peer(service: ProvisioningService) -> Any:
    return await service.revoke_peer(
        user_id=USER_ID,
        device_id=DEVICE_ID,
        server_code="vps-1",
        network_prefix=NETWORK_PREFIX,
        request_id=uuid4(),
    )


# --- request_peer: happy path -----------------------------------------------


def test_request_peer_provisions_and_activates_the_peer() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.assigned_address == "203.0.113.2"
    assert result.server_public_key == "B" * 43 + "="
    assert result.listen_port == 51820
    peer = _added(session, WireGuardPeer)
    credential = _added(session, DeviceProtocolCredential)
    operation = _added(session, AgentOperation)
    assert peer.state == ProvisioningState.ACTIVE.value
    assert peer.applied_generation == 1
    assert credential.state == ProvisioningState.ACTIVE.value
    assert operation.state == "succeeded"
    assert len(agent.provision_calls) == 1
    assert agent.provision_calls[0].public_key == CLIENT_PUBLIC_KEY


def test_request_peer_skips_the_gateway_and_taken_addresses() -> None:
    session = make_session(_happy_fixtures(), existing_addresses=["203.0.113.2"])
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.assigned_address == "203.0.113.3"


def test_request_peer_only_excludes_addresses_held_by_live_peers() -> None:
    """`make_session`'s fake reports whatever `existing_addresses` says is
    taken regardless of the query, so it can't prove the query's WHERE
    clause is right on its own -- inspect the compiled statement passed to
    `session.scalars` directly to prove a `revoked`/`failed` peer's address
    is excluded from the fetch entirely, not merely filtered out
    client-side, matching `uq_wireguard_peers_server_address_live`'s
    live-only scoping at the DB level."""

    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    asyncio.run(_request_peer(service))

    statement = session.scalars.call_args.args[0]
    compiled = str(statement.compile(compile_kwargs={"literal_binds": True}))
    assert "wireguard_peers.state IN" in compiled
    for state in ("requested", "applying", "active", "revoking"):
        assert f"'{state}'" in compiled
    assert "'revoked'" not in compiled
    assert "'failed'" not in compiled


# --- request_peer: rejections that never reach the agent --------------------


def test_request_peer_rejects_an_invalid_public_key() -> None:
    session = make_session(_happy_fixtures())
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(
            service.request_peer(
                user_id=USER_ID,
                device_id=DEVICE_ID,
                server_code="vps-1",
                protocol_profile_code="wireguard-native",
                public_key="not-a-valid-key",
                network_prefix=NETWORK_PREFIX,
                request_id=uuid4(),
            )
        )


def test_request_peer_rejects_when_rate_limited() -> None:
    session = make_session(_happy_fixtures())
    service = ProvisioningService(
        make_session_factory(session),
        cast(RedisAuthState, FakeRedisAuthState(allow=False)),
        Settings(),
        _never_called_agent_builder(),
        _key_material(),
    )

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


@pytest.mark.parametrize(
    "fixtures",
    [
        {Device: None},
        {Device: _device(state=LifecycleState.REVOKED)},
        {ProtocolProfile: None},
        {VPNServer: None},
        {VPNServer: _server(state=ServerState.DISABLED.value)},
        {ServerProtocolCapability: None},
        {ServerProtocolCapability: _capability(state=CapabilityState.DISABLED.value)},
        {UserProtocolPermission: None},
        {UserProtocolPermission: _permission(state=CapabilityState.DISABLED.value)},
        {UserProtocolPermission: _permission(expires_at=datetime.now(UTC) - timedelta(minutes=1))},
        {UserServerAssignment: None},
        {UserServerAssignment: _assignment(state=LifecycleState.REVOKED.value)},
        {UserServerAssignment: _assignment(expires_at=datetime.now(UTC) - timedelta(minutes=1))},
        {VPNServer: _server(pool=None)},
    ],
)
def test_request_peer_rejects_invalid_preconditions(fixtures: dict[type, object | None]) -> None:
    session = make_session(_happy_fixtures(fixtures))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


def test_request_peer_reconnects_an_existing_active_peer() -> None:
    # Toggling the VPN off and back on should not require the app to track
    # whether the server already has a live peer for this device -- the
    # server reuses the existing peer's identity instead of rejecting.
    peer = _live_peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential_for(peer)
    session = make_session(
        _happy_fixtures({WireGuardPeer: peer, DeviceProtocolCredential: credential})
    )
    agent = FakeAgentClient(provision=_provision_response(applied_generation=2))
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.peer_id == peer.id
    assert peer.state == ProvisioningState.ACTIVE.value
    assert len(agent.provision_calls) == 1
    assert agent.provision_calls[0].public_key == CLIENT_PUBLIC_KEY
    assert agent.provision_calls[0].desired_generation == 2


def test_request_peer_adopts_a_new_public_key_when_reconnecting() -> None:
    # The client always sends its current public key -- if the app generated
    # a new keypair since the peer was first provisioned (e.g. storage was
    # cleared), the server should adopt it rather than keep serving the peer
    # under a key the client can no longer actually decrypt with.
    peer = _live_peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential_for(peer)
    session = make_session(
        _happy_fixtures({WireGuardPeer: peer, DeviceProtocolCredential: credential})
    )
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    asyncio.run(_request_peer(service))

    assert peer.public_key == CLIENT_PUBLIC_KEY


def test_request_peer_reassigns_the_existing_peer_to_a_newly_picked_profile() -> None:
    """Reconnecting can pick a different WireGuard sibling than last time
    (e.g. switching to wireguard-adblock) -- there is only ever one live
    peer per device regardless of profile, so the existing row must move to
    whichever profile was just requested rather than silently keeping its
    old one."""

    peer = _live_peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential_for(peer)
    adblock_profile = _profile(ad_block=True)
    session = make_session(
        _happy_fixtures(
            {
                WireGuardPeer: peer,
                DeviceProtocolCredential: credential,
                ProtocolProfile: adblock_profile,
            }
        )
    )
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    asyncio.run(_request_peer(service))

    assert peer.protocol_profile_id == adblock_profile.id
    assert credential.protocol_profile_id == adblock_profile.id


def test_request_peer_returns_ad_block_dns_for_the_ad_block_profile() -> None:
    session = make_session(_happy_fixtures({ProtocolProfile: _profile(ad_block=True)}))
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.client_dns == "94.140.14.14"


def test_request_peer_returns_the_agents_own_dns_for_the_plain_profile() -> None:
    session = make_session(_happy_fixtures({ProtocolProfile: _profile(ad_block=False)}))
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.client_dns == "10.77.0.1"


@pytest.mark.parametrize(
    "state", [ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value]
)
def test_request_peer_rejects_when_an_operation_is_already_in_progress(state: str) -> None:
    peer = _live_peer(state=state)
    credential = _credential_for(peer, state=state)
    session = make_session(
        _happy_fixtures({WireGuardPeer: peer, DeviceProtocolCredential: credential})
    )
    service = make_service(session)

    with pytest.raises(OperationInProgress):
        asyncio.run(_request_peer(service))


def test_request_peer_rejects_when_the_server_device_cap_is_reached() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(maximum_devices=5)}), live_peer_count=5
    )
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


def test_request_peer_rejects_when_the_capability_capacity_limit_is_reached() -> None:
    """The capability's optional per-protocol cap binds even when the
    server-wide device cap still has room."""

    session = make_session(
        _happy_fixtures(
            {
                VPNServer: _server(maximum_devices=1000),
                ServerProtocolCapability: _capability(capacity_limit=2),
            }
        ),
        live_peer_count=2,
    )
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


def test_request_peer_allows_the_last_slot_under_the_cap() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(maximum_devices=5)}), live_peer_count=4
    )
    agent = FakeAgentClient(provision=_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_peer(service))

    assert result.peer_id is not None
    assert len(agent.provision_calls) == 1


def test_request_peer_rejects_when_the_address_pool_is_exhausted() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(pool="203.0.113.0/30", gateway=None)}),
        existing_addresses=["203.0.113.1", "203.0.113.2"],
    )
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


# --- request_peer: agent-call outcomes ---------------------------------------


def test_request_peer_finalizes_as_failed_when_the_agent_rejects_the_request() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=AgentRejected(422, "Peer Conflict!"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))

    peer = _added(session, WireGuardPeer)
    operation = _added(session, AgentOperation)
    assert peer.state == ProvisioningState.FAILED.value
    assert operation.state == "failed"
    assert operation.error_code == "peer_conflict"


def test_request_peer_finalizes_as_failed_when_the_agent_is_unreachable() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=AgentUnreachable("connection refused"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))

    operation = _added(session, AgentOperation)
    assert operation.error_code == "agent_unreachable"


def test_request_peer_finalizes_as_failed_when_the_agent_reports_a_failed_state() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=_provision_response(state="failed", error_code="no_capacity"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))

    peer = _added(session, WireGuardPeer)
    credential = _added(session, DeviceProtocolCredential)
    operation = _added(session, AgentOperation)
    assert peer.state == ProvisioningState.FAILED.value
    assert credential.state == ProvisioningState.FAILED.value
    assert operation.error_code == "no_capacity"


def test_request_peer_raises_ambiguous_and_leaves_rows_in_flight() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=AgentResponseAmbiguous("read timeout"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_request_peer(service))

    peer = _added(session, WireGuardPeer)
    operation = _added(session, AgentOperation)
    assert peer.state == ProvisioningState.APPLYING.value
    assert operation.state == "running"


def test_request_peer_raises_ambiguous_when_the_response_body_is_invalid() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision=AgentResponseInvalid("bad body"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_request_peer(service))


# --- revoke_peer --------------------------------------------------------------


def _revoke_fixtures(
    peer: MagicMock, overrides: dict[type, object | None] | None = None
) -> dict[type, object | None]:
    fixtures: dict[type, object | None] = {
        Device: _device(),
        VPNServer: _server(),
        WireGuardPeer: peer,
        DeviceProtocolCredential: _credential_for(peer),
    }
    fixtures.update(overrides or {})
    return fixtures


def test_revoke_peer_revokes_an_active_peer() -> None:
    peer = _live_peer(state=ProvisioningState.ACTIVE.value)
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=_revoke_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_revoke_peer(service))

    assert result.peer_id == peer.id
    assert peer.state == ProvisioningState.REVOKED.value
    assert peer.revoked_at is not None
    credential = _added(session, AgentOperation)  # AgentOperation is the only new row
    assert credential.state == "succeeded"
    assert len(agent.revoke_calls) == 1
    assert agent.revoke_calls[0].public_key == peer.public_key


def test_revoke_peer_rejects_when_device_is_missing() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer, {Device: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))


def test_revoke_peer_rejects_when_server_is_missing() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer, {VPNServer: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))


def test_revoke_peer_rejects_when_there_is_no_live_peer() -> None:
    session = make_session(_revoke_fixtures(_live_peer(), {WireGuardPeer: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))


@pytest.mark.parametrize(
    "state", [ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value]
)
def test_revoke_peer_rejects_operation_in_progress(state: str) -> None:
    peer = _live_peer(state=state)
    session = make_session(_revoke_fixtures(peer))
    service = make_service(session)

    with pytest.raises(OperationInProgress):
        asyncio.run(_revoke_peer(service))


def test_revoke_peer_keeps_removal_pending_when_the_agent_rejects_the_request() -> None:
    peer = _live_peer()
    credential = _credential_for(peer)
    session = make_session(_revoke_fixtures(peer, {DeviceProtocolCredential: credential}))
    agent = FakeAgentClient(revoke=AgentRejected(409, "already gone"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == credential.state == ProvisioningState.REVOKING.value

    assert _added(session, AgentOperation).state == "failed"


def test_revoke_peer_keeps_removal_pending_when_the_agent_is_unreachable() -> None:
    peer = _live_peer()
    credential = _credential_for(peer)
    session = make_session(_revoke_fixtures(peer, {DeviceProtocolCredential: credential}))
    agent = FakeAgentClient(revoke=AgentUnreachable("timed out"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == credential.state == ProvisioningState.REVOKING.value

    assert _added(session, AgentOperation).state == "failed"


def test_revoke_peer_keeps_removal_pending_when_the_agent_reports_a_failed_state() -> None:
    peer = _live_peer()
    credential = _credential_for(peer)
    session = make_session(_revoke_fixtures(peer, {DeviceProtocolCredential: credential}))
    agent = FakeAgentClient(revoke=_revoke_response(state="failed", error_code="busy"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == credential.state == ProvisioningState.REVOKING.value

    assert _added(session, AgentOperation).state == "failed"


def test_revoke_peer_raises_ambiguous_and_leaves_the_peer_revoking() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=AgentResponseAmbiguous("dropped connection"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_revoke_peer(service))

    assert peer.state == ProvisioningState.REVOKING.value


# --- request_xray_client -------------------------------------------------


async def _request_xray_client(service: ProvisioningService) -> Any:
    return await service.request_xray_client(
        user_id=USER_ID,
        device_id=DEVICE_ID,
        server_code="vps-1",
        protocol_profile_code="vless-xhttp-tls",
        request_id=uuid4(),
        network_prefix=NETWORK_PREFIX,
    )


async def _revoke_xray_client(
    service: ProvisioningService, profile_code: str = "vless-xhttp-tls"
) -> Any:
    return await service.revoke_xray_client(
        user_id=USER_ID,
        device_id=DEVICE_ID,
        server_code="vps-1",
        protocol_profile_code=profile_code,
        network_prefix=NETWORK_PREFIX,
        request_id=uuid4(),
    )


def test_request_xray_client_provisions_and_activates_the_client() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision_xray=_xray_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_xray_client(service))

    assert result.server_address == "vps1.example.com"
    assert result.port == 8445
    assert result.transport_security == "none"
    assert result.transport == "xhttp"
    assert result.path == "/xhttp"
    client = _added(session, XrayClient)
    credential = _added(session, DeviceProtocolCredential)
    operation = _added(session, AgentOperation)
    assert client.state == ProvisioningState.ACTIVE.value
    assert client.applied_generation == 1
    assert credential.state == ProvisioningState.ACTIVE.value
    assert credential.kind == "xray_bearer"
    assert credential.ciphertext is not None
    assert operation.state == "succeeded"
    assert operation.target_kind == "xray_client"
    assert len(agent.provision_xray_calls) == 1
    assert agent.provision_xray_calls[0].client_uuid == result.uuid


def test_request_xray_client_rejects_when_rate_limited() -> None:
    session = make_session(_happy_fixtures())
    service = ProvisioningService(
        make_session_factory(session),
        cast(RedisAuthState, FakeRedisAuthState(allow=False)),
        Settings(),
        _never_called_agent_builder(),
        _key_material(),
    )

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))


@pytest.mark.parametrize(
    "fixtures",
    [
        {Device: None},
        {Device: _device(state=LifecycleState.REVOKED)},
        {ProtocolProfile: None},
        {VPNServer: None},
        {VPNServer: _server(state=ServerState.DISABLED.value)},
        {ServerProtocolCapability: None},
        {ServerProtocolCapability: _capability(state=CapabilityState.DISABLED.value)},
        {UserProtocolPermission: None},
        {UserProtocolPermission: _permission(state=CapabilityState.DISABLED.value)},
        {UserServerAssignment: None},
        {UserServerAssignment: _assignment(state=LifecycleState.REVOKED.value)},
    ],
)
def test_request_xray_client_rejects_invalid_preconditions(
    fixtures: dict[type, object | None],
) -> None:
    session = make_session(_happy_fixtures(fixtures))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))


def test_request_xray_client_reconnects_an_existing_active_client() -> None:
    # Toggling the VPN off and back on should not require the app to track
    # whether the server already has a live client for this device -- the
    # server reuses the existing client's identity instead of rejecting.
    keys = _key_material()
    client_uuid = uuid4()
    client = _xray_live_client(state=ProvisioningState.ACTIVE.value)
    credential = _xray_credential_for(client, client_uuid, keys)
    session = make_session(
        _happy_fixtures({XrayClient: client, DeviceProtocolCredential: credential})
    )
    agent = FakeAgentClient(provision_xray=_xray_provision_response(applied_generation=2))
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    result = asyncio.run(_request_xray_client(service))

    assert result.client_id == client.id
    assert result.uuid == client_uuid
    assert client.state == ProvisioningState.ACTIVE.value
    assert len(agent.provision_xray_calls) == 1
    assert agent.provision_xray_calls[0].client_uuid == client_uuid
    assert agent.provision_xray_calls[0].desired_generation == 2


@pytest.mark.parametrize(
    "state", [ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value]
)
def test_request_xray_client_rejects_when_an_operation_is_already_in_progress(
    state: str,
) -> None:
    keys = _key_material()
    client = _xray_live_client(state=state)
    credential = _xray_credential_for(client, uuid4(), keys)
    session = make_session(
        _happy_fixtures({XrayClient: client, DeviceProtocolCredential: credential})
    )
    service = make_service(session, key_material=keys)

    with pytest.raises(XrayOperationInProgress):
        asyncio.run(_request_xray_client(service))


def test_request_xray_client_rejects_when_the_server_device_cap_is_reached() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(maximum_devices=5)}), live_peer_count=5
    )
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))


def test_request_xray_client_allows_the_last_slot_under_the_cap() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(maximum_devices=5)}), live_peer_count=4
    )
    agent = FakeAgentClient(provision_xray=_xray_provision_response())
    service = make_service(session, agent_builder=_agent_builder(agent))

    result = asyncio.run(_request_xray_client(service))

    assert result.client_id is not None
    assert len(agent.provision_xray_calls) == 1


def test_request_xray_client_finalizes_as_failed_when_the_agent_rejects_the_request() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision_xray=AgentRejected(422, "Client Conflict!"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))

    client = _added(session, XrayClient)
    operation = _added(session, AgentOperation)
    assert client.state == ProvisioningState.FAILED.value
    assert operation.state == "failed"
    assert operation.error_code == "client_conflict"


def test_request_xray_client_finalizes_as_failed_when_the_agent_is_unreachable() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision_xray=AgentUnreachable("connection refused"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))

    operation = _added(session, AgentOperation)
    assert operation.error_code == "agent_unreachable"


def test_request_xray_client_finalizes_as_failed_when_the_agent_reports_a_failed_state() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(
        provision_xray=_xray_provision_response(state="failed", error_code="no_capacity")
    )
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_xray_client(service))

    client = _added(session, XrayClient)
    credential = _added(session, DeviceProtocolCredential)
    operation = _added(session, AgentOperation)
    assert client.state == ProvisioningState.FAILED.value
    assert credential.state == ProvisioningState.FAILED.value
    assert operation.error_code == "no_capacity"


def test_request_xray_client_raises_ambiguous_and_leaves_rows_in_flight() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision_xray=AgentResponseAmbiguous("read timeout"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_request_xray_client(service))

    client = _added(session, XrayClient)
    operation = _added(session, AgentOperation)
    assert client.state == ProvisioningState.APPLYING.value
    assert operation.state == "running"


def test_request_xray_client_raises_ambiguous_when_the_response_body_is_invalid() -> None:
    session = make_session(_happy_fixtures())
    agent = FakeAgentClient(provision_xray=AgentResponseInvalid("bad body"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_request_xray_client(service))


# --- revoke_xray_client ----------------------------------------------------


def _xray_revoke_fixtures(
    client: MagicMock,
    credential: MagicMock,
    overrides: dict[type, object | None] | None = None,
) -> dict[type, object | None]:
    fixtures: dict[type, object | None] = {
        Device: _device(),
        VPNServer: _server(),
        ProtocolProfile: _profile(),
        XrayClient: client,
        DeviceProtocolCredential: credential,
    }
    fixtures.update(overrides or {})
    return fixtures


def test_revoke_xray_client_revokes_an_active_client() -> None:
    keys = _key_material()
    client_uuid = uuid4()
    client = _xray_live_client(state=ProvisioningState.ACTIVE.value)
    credential = _xray_credential_for(client, client_uuid, keys)
    session = make_session(_xray_revoke_fixtures(client, credential))
    agent = FakeAgentClient(revoke_xray=_xray_revoke_response())
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    result = asyncio.run(_revoke_xray_client(service))

    assert result.client_id == client.id
    assert client.state == ProvisioningState.REVOKED.value
    assert client.revoked_at is not None
    operation = _added(session, AgentOperation)
    assert operation.state == "succeeded"
    assert len(agent.revoke_xray_calls) == 1
    assert agent.revoke_xray_calls[0].client_uuid == client_uuid


def test_revoke_xray_client_rejects_when_device_is_missing() -> None:
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), _key_material())
    session = make_session(_xray_revoke_fixtures(client, credential, {Device: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service))


def test_revoke_xray_client_rejects_when_server_is_missing() -> None:
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), _key_material())
    session = make_session(_xray_revoke_fixtures(client, credential, {VPNServer: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service))


def test_revoke_xray_client_rejects_when_there_is_no_live_client() -> None:
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), _key_material())
    session = make_session(_xray_revoke_fixtures(client, credential, {XrayClient: None}))
    service = make_service(session)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service))


@pytest.mark.parametrize(
    "state", [ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value]
)
def test_revoke_xray_client_rejects_operation_in_progress(state: str) -> None:
    client = _xray_live_client(state=state)
    credential = _xray_credential_for(client, uuid4(), _key_material())
    session = make_session(_xray_revoke_fixtures(client, credential))
    service = make_service(session)

    with pytest.raises(XrayOperationInProgress):
        asyncio.run(_revoke_xray_client(service))


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
def test_revoke_xray_client_keeps_removal_pending_when_the_agent_rejects_the_request(
    profile_code: str,
) -> None:
    keys = _key_material()
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), keys)
    session = make_session(
        _xray_revoke_fixtures(client, credential, {ProtocolProfile: _profile(code=profile_code)})
    )
    agent = FakeAgentClient(revoke_xray=AgentRejected(409, "already gone"))
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service, profile_code))

    assert client.state == credential.state == ProvisioningState.REVOKING.value
    assert agent.revoke_xray_calls[0].protocol_profile_code == profile_code

    assert _added(session, AgentOperation).state == "failed"


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
def test_revoke_xray_client_keeps_removal_pending_when_the_agent_is_unreachable(
    profile_code: str,
) -> None:
    keys = _key_material()
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), keys)
    session = make_session(
        _xray_revoke_fixtures(client, credential, {ProtocolProfile: _profile(code=profile_code)})
    )
    agent = FakeAgentClient(revoke_xray=AgentUnreachable("timed out"))
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service, profile_code))

    assert client.state == credential.state == ProvisioningState.REVOKING.value
    assert agent.revoke_xray_calls[0].protocol_profile_code == profile_code

    assert _added(session, AgentOperation).state == "failed"


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
def test_revoke_xray_client_keeps_removal_pending_when_the_agent_reports_a_failed_state(
    profile_code: str,
) -> None:
    keys = _key_material()
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), keys)
    session = make_session(
        _xray_revoke_fixtures(client, credential, {ProtocolProfile: _profile(code=profile_code)})
    )
    agent = FakeAgentClient(revoke_xray=_xray_revoke_response(state="failed", error_code="busy"))
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_xray_client(service, profile_code))

    assert client.state == credential.state == ProvisioningState.REVOKING.value
    assert agent.revoke_xray_calls[0].protocol_profile_code == profile_code

    assert _added(session, AgentOperation).state == "failed"


def test_revoke_xray_client_raises_ambiguous_and_leaves_the_client_revoking() -> None:
    keys = _key_material()
    client = _xray_live_client()
    credential = _xray_credential_for(client, uuid4(), keys)
    session = make_session(_xray_revoke_fixtures(client, credential))
    agent = FakeAgentClient(revoke_xray=AgentResponseAmbiguous("dropped connection"))
    service = make_service(session, agent_builder=_agent_builder(agent), key_material=keys)

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_revoke_xray_client(service))

    assert client.state == ProvisioningState.REVOKING.value


def test_request_peer_on_a_server_under_maintenance_says_so() -> None:
    session = make_session(
        _happy_fixtures({VPNServer: _server(state=ServerState.MAINTENANCE.value)})
    )
    service = make_service(session)

    with pytest.raises(ServerUnderMaintenance):
        asyncio.run(_request_peer(service))
