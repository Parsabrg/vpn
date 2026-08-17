import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
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
    RevokeDeviceRequest,
    RevokeDeviceResponse,
)
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
    ProfileState,
    ProvisioningState,
    ServerState,
)
from nebula_api.provisioning.service import (
    DeviceAlreadyHasPeer,
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningRejected,
    ProvisioningService,
)
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
    ) -> None:
        self.provision_result = provision
        self.revoke_result = revoke
        self.provision_calls: list[ProvisionDeviceRequest] = []
        self.revoke_calls: list[RevokeDeviceRequest] = []

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


def _agent_builder(client: FakeAgentClient) -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, client)

    return _builder


def _never_called_agent_builder() -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        raise AssertionError("the agent should not have been called")

    return _builder


def _entity_of(statement: Select[Any]) -> type:
    return cast(type, statement.column_descriptions[0]["entity"])


def _added(session: MagicMock, model: type) -> Any:
    for call in reversed(session.add.call_args_list):
        row = call.args[0]
        if isinstance(row, model):
            return row
    raise AssertionError(f"no {model.__name__} was added")


def make_session(
    fixtures: dict[type, object | None], *, existing_addresses: list[str] | None = None
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


def _profile(*, state: str = ProfileState.IMPLEMENTED.value) -> MagicMock:
    profile = MagicMock(spec=ProtocolProfile)
    profile.id = PROFILE_ID
    profile.state = state
    return profile


def _server(
    *,
    state: str = ServerState.ACTIVE.value,
    pool: str | None = "203.0.113.0/24",
    gateway: str | None = "203.0.113.1",
) -> MagicMock:
    server = MagicMock(spec=VPNServer)
    server.id = SERVER_ID
    server.code = "vps-1"
    server.state = state
    server.agent_host = "vps1.internal"
    server.agent_port = 9443
    server.wireguard_client_pool = pool
    server.wireguard_gateway_address = gateway
    return server


def _capability(*, state: str = CapabilityState.ENABLED.value) -> MagicMock:
    capability = MagicMock(spec=ServerProtocolCapability)
    capability.state = state
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


def make_service(
    session: AsyncSession,
    *,
    agent_builder: AgentClientBuilder | None = None,
    allow_rate_limit: bool = True,
) -> ProvisioningService:
    return ProvisioningService(
        make_session_factory(session),
        cast(RedisAuthState, FakeRedisAuthState(allow=allow_rate_limit)),
        Settings(),
        agent_builder or _never_called_agent_builder(),
    )


async def _request_peer(service: ProvisioningService) -> Any:
    return await service.request_peer(
        user_id=USER_ID,
        device_id=DEVICE_ID,
        server_code="vps-1",
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
    )

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_request_peer(service))


@pytest.mark.parametrize(
    "fixtures",
    [
        {Device: None},
        {Device: _device(state=LifecycleState.REVOKED)},
        {Protocol: None},
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


def test_request_peer_rejects_when_the_device_already_has_a_live_peer() -> None:
    session = make_session(_happy_fixtures({WireGuardPeer: _live_peer()}))
    service = make_service(session)

    with pytest.raises(DeviceAlreadyHasPeer):
        asyncio.run(_request_peer(service))


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


def test_revoke_peer_finalizes_as_failed_when_the_agent_rejects_the_request() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=AgentRejected(409, "already gone"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == ProvisioningState.FAILED.value


def test_revoke_peer_finalizes_as_failed_when_the_agent_is_unreachable() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=AgentUnreachable("timed out"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == ProvisioningState.FAILED.value


def test_revoke_peer_finalizes_as_failed_when_the_agent_reports_a_failed_state() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=_revoke_response(state="failed", error_code="busy"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningRejected):
        asyncio.run(_revoke_peer(service))

    assert peer.state == ProvisioningState.FAILED.value


def test_revoke_peer_raises_ambiguous_and_leaves_the_peer_revoking() -> None:
    peer = _live_peer()
    session = make_session(_revoke_fixtures(peer))
    agent = FakeAgentClient(revoke=AgentResponseAmbiguous("dropped connection"))
    service = make_service(session, agent_builder=_agent_builder(agent))

    with pytest.raises(ProvisioningAmbiguous):
        asyncio.run(_revoke_peer(service))

    assert peer.state == ProvisioningState.REVOKING.value
