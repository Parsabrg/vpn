import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest

from nebula_api.agent_client.client import (
    AgentClient,
    AgentClientBuilder,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentResponseInvalid,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    HealthRequest,
    HealthResponse,
    XrayHealthRequest,
    XrayHealthResponse,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import Protocol, ProtocolProfile, VPNServer
from nebula_api.topology_admin.service import TopologyAdminService

FIXED_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class FakeHealthAgentClient:
    def __init__(self, *, response: HealthResponse | XrayHealthResponse | Exception) -> None:
        self._response = response

    async def __aenter__(self) -> "FakeHealthAgentClient":
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        return None

    async def health(self, request: HealthRequest) -> HealthResponse:
        del request
        if isinstance(self._response, Exception):
            raise self._response
        assert isinstance(self._response, HealthResponse)
        return self._response

    async def xray_health(self, request: XrayHealthRequest) -> XrayHealthResponse:
        assert request.correlation_id is not None
        if isinstance(self._response, Exception):
            raise self._response
        assert isinstance(self._response, XrayHealthResponse)
        return self._response


def _agent_builder(response: HealthResponse | XrayHealthResponse | Exception) -> AgentClientBuilder:
    def _builder(agent_host: str, agent_port: int) -> AgentClient:
        del agent_host, agent_port
        return cast(AgentClient, FakeHealthAgentClient(response=response))

    return _builder


class ScalarRows:
    def __init__(self, values: Iterable[object]) -> None:
        self._values = list(values)

    def all(self) -> list[object]:
        return self._values


class ScriptedSession:
    def __init__(self, *, scalars_values: Iterable[Iterable[object]] = ()) -> None:
        self.scalars_values = [list(values) for values in scalars_values]

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalars(self, _statement: object) -> ScalarRows:
        return ScalarRows(self.scalars_values.pop(0))


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        return self.sessions.pop(0)


def test_list_protocols_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocols())

    assert result == []


def test_list_protocols_maps_rows() -> None:
    row = Protocol(
        id=uuid4(),
        code="wireguard",
        display_name="WireGuard",
        engine="native_wireguard",
        is_user_selectable=True,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocols())

    assert result[0].code == "wireguard"
    assert result[0].is_user_selectable is True


def test_list_protocol_profiles_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocol_profiles())

    assert result == []


def test_list_protocol_profiles_maps_rows() -> None:
    row = ProtocolProfile(
        id=uuid4(),
        protocol_id=uuid4(),
        code="wireguard-default",
        version=1,
        display_name="WireGuard default",
        state="draft",
        transport=None,
        transport_security=None,
        requires_udp=True,
        is_full_tunnel=True,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_protocol_profiles())

    assert result[0].code == "wireguard-default"
    assert result[0].requires_udp is True


def test_list_vpn_servers_returns_empty_when_none_exist() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_vpn_servers())

    assert result == []


def test_list_vpn_servers_maps_rows() -> None:
    row = VPNServer(
        id=uuid4(),
        code="ams-1",
        display_name="Amsterdam 1",
        state="disabled",
        agent_host="10.0.0.5",
        agent_port=9443,
        public_host="ams-1.example.test",
        maximum_devices=1000,
    )
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    result = asyncio.run(service.list_vpn_servers())

    assert result[0].code == "ams-1"
    assert result[0].public_host == "ams-1.example.test"


def _server(*, code: str = "ams-1") -> VPNServer:
    return VPNServer(
        id=uuid4(),
        code=code,
        display_name="Amsterdam 1",
        state="active",
        agent_host="10.0.0.5",
        agent_port=9443,
        public_host="ams-1.example.test",
        maximum_devices=1000,
    )


def test_get_vpn_server_health_maps_a_healthy_response() -> None:
    row = _server()
    session = ScriptedSession(scalars_values=[[row]])
    response = HealthResponse(
        state="healthy",
        observed_at=FIXED_NOW,
        agent_version="1.0.0",
        interface_up=True,
        peer_count=3,
    )
    ticks = iter([100.0, 100.012])
    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(session)),
        agent_client_builder=_agent_builder(response),
        monotonic=lambda: next(ticks),
    )

    result = asyncio.run(service.get_vpn_server_health())

    assert len(result) == 1
    assert result[0].server_id == row.id
    assert result[0].code == "ams-1"
    assert result[0].state == "healthy"
    assert result[0].observed_at == FIXED_NOW
    assert result[0].latency_ms == 12
    assert result[0].agent_version == "1.0.0"
    assert result[0].interface_up is True
    assert result[0].peer_count == 3


def test_get_vpn_server_health_degrades_an_unreachable_agent() -> None:
    row = _server()
    session = ScriptedSession(scalars_values=[[row]])
    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(session)),
        agent_client_builder=_agent_builder(AgentUnreachable("connection refused")),
        clock=lambda: FIXED_NOW,
    )

    result = asyncio.run(service.get_vpn_server_health())

    assert len(result) == 1
    assert result[0].server_id == row.id
    assert result[0].code == "ams-1"
    assert result[0].state == "unreachable"
    assert result[0].observed_at == FIXED_NOW
    assert result[0].latency_ms is None
    assert result[0].agent_version is None
    assert result[0].interface_up is None
    assert result[0].peer_count is None


def test_get_vpn_server_health_checks_every_server() -> None:
    rows = [_server(code="ams-1"), _server(code="fra-1")]
    session = ScriptedSession(scalars_values=[rows])
    response = HealthResponse(
        state="healthy",
        observed_at=FIXED_NOW,
        agent_version="1.0.0",
        interface_up=True,
        peer_count=0,
    )
    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(session)),
        agent_client_builder=_agent_builder(response),
    )

    result = asyncio.run(service.get_vpn_server_health())

    assert {entry.code for entry in result} == {"ams-1", "fra-1"}


def test_get_vpn_server_health_without_a_configured_builder_raises() -> None:
    session = ScriptedSession(scalars_values=[[]])
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(session)))

    with pytest.raises(RuntimeError, match="agent_client_builder is not configured"):
        asyncio.run(service.get_vpn_server_health())


@pytest.mark.parametrize("listener_up", [True, False])
def test_xray_health_preserves_listener_evidence_and_measures_latency(listener_up: bool) -> None:
    row = _server()
    response = XrayHealthResponse(
        state="healthy" if listener_up else "unreachable",
        observed_at=FIXED_NOW,
        agent_version="1.0.0",
        listener_up=listener_up,
        client_count=0,
        error_code=None if listener_up else "listener_unreachable",
    )
    ticks = iter([100.0, 100.025])
    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(scalars_values=[[row]]))),
        agent_client_builder=_agent_builder(response),
        monotonic=lambda: next(ticks),
    )
    result = asyncio.run(service.get_vpn_server_xray_health())
    assert len(result) == 1
    entry = result[0]
    assert entry.server_id == row.id
    assert entry.state == response.state
    assert entry.listener_up is listener_up
    assert entry.observed_at == FIXED_NOW
    assert entry.latency_ms == 25
    assert entry.agent_version == "1.0.0"
    assert entry.error_code == response.error_code


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (AgentUnreachable("credential-canary"), "agent_unreachable"),
        (AgentRejected(503, "credential-canary"), "agent_rejected"),
        (AgentResponseAmbiguous("credential-canary"), "agent_response_ambiguous"),
        (AgentResponseInvalid("credential-canary"), "agent_response_invalid"),
    ],
)
def test_xray_probe_failure_is_isolated_and_does_not_invent_listener_state(
    failure: Exception,
    code: str,
) -> None:
    rows = [_server(code="ams-1"), _server(code="fra-1")]
    rows[1].agent_host = "10.0.0.6"
    response = XrayHealthResponse(
        state="healthy",
        observed_at=FIXED_NOW,
        agent_version="1.0.0",
        listener_up=True,
        client_count=0,
    )

    def builder(host: str, port: int) -> AgentClient:
        assert port == 9443
        return cast(
            AgentClient, FakeHealthAgentClient(response=failure if host == "10.0.0.5" else response)
        )

    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(scalars_values=[rows]))),
        agent_client_builder=builder,
        clock=lambda: FIXED_NOW,
    )
    result = asyncio.run(service.get_vpn_server_xray_health())
    failed, healthy = result
    assert failed.state == "unreachable"
    assert failed.observed_at == FIXED_NOW
    assert failed.listener_up is None
    assert failed.latency_ms is None
    assert failed.agent_version is None
    assert failed.error_code == code
    assert "credential-canary" not in repr(failed)
    assert healthy.state == "healthy" and healthy.listener_up is True


def test_xray_health_empty_inventory_and_missing_builder() -> None:
    service = TopologyAdminService(
        cast(SessionFactory, ScriptedFactory(ScriptedSession(scalars_values=[[]]))),
        agent_client_builder=_agent_builder(AgentUnreachable("must not be called")),
    )
    assert asyncio.run(service.get_vpn_server_xray_health()) == []
    service = TopologyAdminService(cast(SessionFactory, ScriptedFactory(ScriptedSession())))
    with pytest.raises(RuntimeError, match="agent_client_builder is not configured"):
        asyncio.run(service.get_vpn_server_xray_health())
