import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sqlalchemy import Select
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.agent_client.client import (
    AgentClient,
    AgentClientBuilder,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileRequest,
    ReconcileResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AgentOperation, ReconciliationRecord
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer
from nebula_api.models.topology import VPNServer
from nebula_api.models.types import OperationState, ProvisioningState, ServerState
from nebula_api.provisioning.reconciliation import ReconciliationSummary, run_reconciliation
from nebula_api.settings import Settings

SERVER_ID = uuid4()
PEER_ID = uuid4()
CREDENTIAL_ID = uuid4()
PUBLIC_KEY = "F" * 43 + "="


def test_summary_had_problems_reflects_repairs_and_ambiguity() -> None:
    assert not ReconciliationSummary().had_problems
    assert ReconciliationSummary(repair_failed=1).had_problems
    assert ReconciliationSummary(ambiguous=1).had_problems
    assert not ReconciliationSummary(repaired=3, in_sync=5).had_problems


class FakeAgentClient:
    def __init__(
        self,
        *,
        reconcile: ReconcileResponse | Exception,
        provision: ProvisionDeviceResponse | Exception | None = None,
        revoke: RevokeDeviceResponse | Exception | None = None,
    ) -> None:
        self.reconcile_result = reconcile
        self.provision_result = provision
        self.revoke_result = revoke
        self.reconcile_calls: list[ReconcileRequest] = []
        self.provision_calls: list[ProvisionDeviceRequest] = []
        self.revoke_calls: list[RevokeDeviceRequest] = []

    async def __aenter__(self) -> "FakeAgentClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def reconcile(self, request: ReconcileRequest) -> ReconcileResponse:
        self.reconcile_calls.append(request)
        if isinstance(self.reconcile_result, Exception):
            raise self.reconcile_result
        return self.reconcile_result

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


def _entity_of(statement: Select[Any]) -> type:
    return cast(type, statement.column_descriptions[0]["entity"])


def make_session(lists: dict[type, list[object]], fixtures: dict[type, object | None]) -> MagicMock:
    """Dispatches scalars() by entity type against `lists`, and scalar() by
    entity type against a freshly add()-ed row of that type (most recent
    first) falling back to `fixtures` -- same technique as
    test_provisioning_service.py, extended to cover the batch scalars()
    query this module also issues."""

    session = MagicMock(spec=AsyncSession)
    session.add = MagicMock()
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

    async def _scalars(statement: Select[Any]) -> MagicMock:
        entity = _entity_of(statement)
        result = MagicMock()
        result.all = MagicMock(return_value=lists.get(entity, []))
        return result

    session.scalar = AsyncMock(side_effect=_scalar)
    session.scalars = AsyncMock(side_effect=_scalars)
    return session


def make_session_factory(session: AsyncSession) -> SessionFactory:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        yield session

    def _factory() -> AbstractAsyncContextManager[AsyncSession]:
        return _scope()

    return cast(SessionFactory, _factory)


def _server(*, state: str = ServerState.ACTIVE.value) -> MagicMock:
    server = MagicMock(spec=VPNServer)
    server.id = SERVER_ID
    server.agent_host = "vps1.internal"
    server.agent_port = 9443
    server.state = state
    return server


def _peer(*, state: str, applied_generation: int = 1) -> MagicMock:
    peer = MagicMock(spec=WireGuardPeer)
    peer.id = PEER_ID
    peer.credential_id = CREDENTIAL_ID
    peer.vpn_server_id = SERVER_ID
    peer.public_key = PUBLIC_KEY
    peer.assigned_address = "203.0.113.2"
    peer.state = state
    peer.applied_generation = applied_generation
    return peer


def _credential(*, state: str) -> MagicMock:
    credential = MagicMock(spec=DeviceProtocolCredential)
    credential.id = CREDENTIAL_ID
    credential.state = state
    return credential


def _running_operation() -> MagicMock:
    operation = MagicMock(spec=AgentOperation)
    operation.id = uuid4()
    operation.idempotency_key = uuid4()
    operation.state = OperationState.RUNNING.value
    operation.attempt_count = 0
    return operation


def _reconcile_response(*, outcome: str, observed_generation: int | None = 1) -> ReconcileResponse:
    return ReconcileResponse(outcome=cast(Any, outcome), observed_generation=observed_generation)


def _provision_response(*, state: str = "active") -> ProvisionDeviceResponse:
    return ProvisionDeviceResponse(
        state=cast(Any, state),
        applied_generation=1,
        server_public_key="B" * 43 + "=",
        listen_port=51820,
        public_endpoint="vps1.example.com:51820",
        client_dns="10.77.0.1",
        client_allowed_ips="0.0.0.0/0,::/0",
        persistent_keepalive_seconds=25,
    )


def _run(session: MagicMock, agent: FakeAgentClient) -> ReconciliationSummary:
    return asyncio.run(
        run_reconciliation(make_session_factory(session), _agent_builder(agent), Settings())
    )


def _reconciliation_records(session: MagicMock) -> list[ReconciliationRecord]:
    return [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], ReconciliationRecord)
    ]


def test_active_peer_in_sync_makes_no_state_changes() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    session = make_session({WireGuardPeer: [peer], VPNServer: [_server()]}, {WireGuardPeer: peer})
    agent = FakeAgentClient(reconcile=_reconcile_response(outcome="in_sync"))

    summary = _run(session, agent)

    assert summary.checked == 1
    assert summary.in_sync == 1
    assert peer.state == ProvisioningState.ACTIVE.value
    records = _reconciliation_records(session)
    assert [record.outcome for record in records] == ["in_sync"]


def test_applying_peer_in_sync_promotes_to_active() -> None:
    peer = _peer(state=ProvisioningState.APPLYING.value)
    credential = _credential(state=ProvisioningState.REQUESTED.value)
    operation = _running_operation()
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: operation},
    )
    agent = FakeAgentClient(reconcile=_reconcile_response(outcome="in_sync"))

    summary = _run(session, agent)

    assert summary.in_sync == 1
    assert peer.state == ProvisioningState.ACTIVE.value
    assert credential.state == ProvisioningState.ACTIVE.value
    assert operation.state == OperationState.SUCCEEDED.value


def test_revoking_peer_drift_detected_promotes_to_revoked() -> None:
    peer = _peer(state=ProvisioningState.REVOKING.value)
    credential = _credential(state=ProvisioningState.REVOKING.value)
    operation = _running_operation()
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: operation},
    )
    agent = FakeAgentClient(reconcile=_reconcile_response(outcome="drift_detected"))

    summary = _run(session, agent)

    assert summary.in_sync == 1
    assert peer.state == ProvisioningState.REVOKED.value
    assert credential.state == ProvisioningState.REVOKED.value
    assert operation.state == OperationState.SUCCEEDED.value


def test_active_peer_drift_detected_repairs_by_reprovisioning() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential(state=ProvisioningState.ACTIVE.value)
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {
            WireGuardPeer: peer,
            DeviceProtocolCredential: credential,
            AgentOperation: None,  # no existing running operation -- a fresh repair
        },
    )
    agent = FakeAgentClient(
        reconcile=_reconcile_response(outcome="drift_detected"),
        provision=_provision_response(state="active"),
    )

    summary = _run(session, agent)

    assert summary.repaired == 1
    assert summary.repair_failed == 0
    assert peer.state == ProvisioningState.ACTIVE.value
    assert credential.state == ProvisioningState.ACTIVE.value
    assert len(agent.provision_calls) == 1
    records = _reconciliation_records(session)
    assert [record.outcome for record in records] == ["repair_requested", "repair_succeeded"]


def test_applying_peer_drift_detected_reuses_the_running_operation() -> None:
    peer = _peer(state=ProvisioningState.APPLYING.value)
    credential = _credential(state=ProvisioningState.REQUESTED.value)
    operation = _running_operation()
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: operation},
    )
    agent = FakeAgentClient(
        reconcile=_reconcile_response(outcome="drift_detected"),
        provision=_provision_response(state="active"),
    )

    summary = _run(session, agent)

    assert summary.repaired == 1
    assert operation.attempt_count == 1
    assert operation.state == OperationState.SUCCEEDED.value
    assert peer.state == ProvisioningState.ACTIVE.value


def test_revoking_peer_in_sync_repairs_via_revoke() -> None:
    peer = _peer(state=ProvisioningState.REVOKING.value)
    credential = _credential(state=ProvisioningState.REVOKING.value)
    operation = _running_operation()
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: operation},
    )
    agent = FakeAgentClient(
        reconcile=_reconcile_response(outcome="in_sync"),
        revoke=RevokeDeviceResponse(
            state=cast(Any, "revoked"), applied_generation=1, revoked_at=datetime.now(UTC)
        ),
    )

    summary = _run(session, agent)

    assert summary.repaired == 1
    assert len(agent.revoke_calls) == 1
    assert peer.state == ProvisioningState.REVOKED.value
    assert credential.state == ProvisioningState.REVOKED.value


def test_agent_reports_ambiguous_records_and_does_not_repair() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    session = make_session({WireGuardPeer: [peer], VPNServer: [_server()]}, {WireGuardPeer: peer})
    agent = FakeAgentClient(reconcile=_reconcile_response(outcome="ambiguous"))

    summary = _run(session, agent)

    assert summary.ambiguous == 1
    assert summary.had_problems
    assert peer.state == ProvisioningState.ACTIVE.value
    assert not agent.provision_calls and not agent.revoke_calls


def test_agent_client_exception_during_reconcile_counts_as_ambiguous() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    session = make_session({WireGuardPeer: [peer], VPNServer: [_server()]}, {WireGuardPeer: peer})
    agent = FakeAgentClient(reconcile=AgentUnreachable("connection refused"))

    summary = _run(session, agent)

    assert summary.ambiguous == 1
    records = _reconciliation_records(session)
    assert [record.outcome for record in records] == ["ambiguous"]


def test_repair_failure_marks_the_peer_failed() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential(state=ProvisioningState.ACTIVE.value)
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: None},
    )
    agent = FakeAgentClient(
        reconcile=_reconcile_response(outcome="drift_detected"),
        provision=AgentRejected(422, "capacity exceeded"),
    )

    summary = _run(session, agent)

    assert summary.repair_failed == 1
    assert summary.had_problems
    assert peer.state == ProvisioningState.FAILED.value
    assert credential.state == ProvisioningState.FAILED.value


def test_repair_response_ambiguous_leaves_the_operation_running() -> None:
    peer = _peer(state=ProvisioningState.ACTIVE.value)
    credential = _credential(state=ProvisioningState.ACTIVE.value)
    operation = _running_operation()
    session = make_session(
        {WireGuardPeer: [peer], VPNServer: [_server()]},
        {WireGuardPeer: peer, DeviceProtocolCredential: credential, AgentOperation: operation},
    )
    agent = FakeAgentClient(
        reconcile=_reconcile_response(outcome="drift_detected"),
        provision=AgentResponseAmbiguous("read timeout"),
    )

    summary = _run(session, agent)

    assert summary.repair_failed == 1
    assert peer.state == ProvisioningState.ACTIVE.value
    assert operation.state == OperationState.RUNNING.value


def test_reconciliation_skips_servers_that_are_not_active() -> None:
    session = make_session({WireGuardPeer: [], VPNServer: []}, {})
    agent = FakeAgentClient(reconcile=_reconcile_response(outcome="in_sync"))

    summary = _run(session, agent)

    assert summary.checked == 0
    assert not agent.reconcile_calls
