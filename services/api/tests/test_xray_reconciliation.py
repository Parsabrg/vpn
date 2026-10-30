"""Xray-client reconciliation, mirroring test_reconciliation.py's harness.

Self-contained like every other test module here rather than importing that
one's fakes: mypy runs over `tests` as a package root, so a cross-test import
makes the imported module resolvable under two names and aborts the whole
check. The duplicated pieces are a few lines each; the parts that genuinely
differ for Xray -- the joined batch query (execute(), not scalars()) and the
encrypted credential the pass must decrypt before it can address a client at
all -- are what this file is really about.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
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
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    PruneXrayClientsRequest,
    PruneXrayClientsResponse,
    ReconcileXrayClientRequest,
    ReconcileXrayClientResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
)
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AgentOperation, ReconciliationRecord
from nebula_api.models.provisioning import DeviceProtocolCredential, XrayClient
from nebula_api.models.types import ProvisioningState, ServerState
from nebula_api.provisioning.reconciliation import run_xray_orphan_prune, run_xray_reconciliation
from nebula_api.provisioning.xray_credentials import encrypt_xray_credential
from nebula_api.settings import Settings


def make_session_factory(session: AsyncSession) -> SessionFactory:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        yield session

    def _factory() -> AbstractAsyncContextManager[AsyncSession]:
        return _scope()

    return cast(SessionFactory, _factory)


SERVER_ID = uuid4()
CLIENT_ID = uuid4()
CREDENTIAL_ID = uuid4()
DEVICE_ID = uuid4()
CLIENT_UUID = uuid4()
KEY_VERSION = 1


def _keys() -> AuthKeyMaterial:
    return cast(
        AuthKeyMaterial,
        MagicMock(spec=AuthKeyMaterial, xray_encryption_keys={KEY_VERSION: b"k" * 32}),
    )


def _credential(*, decryptable: bool = True) -> MagicMock:
    envelope = encrypt_xray_credential(
        CLIENT_UUID,
        device_id=DEVICE_ID,
        credential_id=CREDENTIAL_ID,
        key_version=KEY_VERSION,
        key_ring={KEY_VERSION: b"k" * 32},
    )
    credential = MagicMock(spec=DeviceProtocolCredential)
    credential.id = CREDENTIAL_ID
    credential.device_id = DEVICE_ID
    credential.key_version = KEY_VERSION
    credential.nonce = envelope.nonce
    # Flipping a ciphertext byte is how a key that no longer decrypts this
    # envelope would actually present itself: AES-GCM fails the tag check.
    credential.ciphertext = (
        envelope.ciphertext
        if decryptable
        else bytes([envelope.ciphertext[0] ^ 0xFF]) + envelope.ciphertext[1:]
    )
    credential.state = ProvisioningState.ACTIVE.value
    return credential


def _client(*, state: str, applied_generation: int = 1) -> MagicMock:
    client = MagicMock(spec=XrayClient)
    client.id = CLIENT_ID
    client.credential_id = CREDENTIAL_ID
    client.vpn_server_id = SERVER_ID
    client.protocol_profile_id = uuid4()
    client.opaque_label = "abcdefghijklmnop"
    client.state = state
    client.applied_generation = applied_generation
    return client


def _server() -> MagicMock:
    server = MagicMock()
    server.id = SERVER_ID
    server.agent_host = "vps1.internal"
    server.agent_port = 9443
    server.state = ServerState.ACTIVE.value
    return server


class FakeXrayAgent:
    def __init__(
        self,
        *,
        reconcile: ReconcileXrayClientResponse | Exception,
        provision: ProvisionXrayClientResponse | Exception | None = None,
        revoke: RevokeXrayClientResponse | Exception | None = None,
    ) -> None:
        self.reconcile_result = reconcile
        self.provision_result = provision
        self.revoke_result = revoke
        self.reconcile_calls: list[ReconcileXrayClientRequest] = []
        self.provision_calls: list[ProvisionXrayClientRequest] = []
        self.revoke_calls: list[RevokeXrayClientRequest] = []

    async def __aenter__(self) -> "FakeXrayAgent":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def reconcile_xray_client(
        self, request: ReconcileXrayClientRequest
    ) -> ReconcileXrayClientResponse:
        self.reconcile_calls.append(request)
        if isinstance(self.reconcile_result, Exception):
            raise self.reconcile_result
        return self.reconcile_result

    async def provision_xray_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        self.provision_calls.append(request)
        if isinstance(self.provision_result, Exception):
            raise self.provision_result
        assert self.provision_result is not None
        return self.provision_result

    async def revoke_xray_client(
        self, request: RevokeXrayClientRequest
    ) -> RevokeXrayClientResponse:
        self.revoke_calls.append(request)
        if isinstance(self.revoke_result, Exception):
            raise self.revoke_result
        assert self.revoke_result is not None
        return self.revoke_result


def _builder(agent: FakeXrayAgent) -> AgentClientBuilder:
    def _build(agent_host: str, agent_port: int) -> AgentClient:
        return cast(AgentClient, agent)

    return _build


def _session(
    *,
    client: MagicMock,
    credential: MagicMock,
    profile_code: str = "vless-xhttp-tls",
    agent_profile_code: str | None = None,
) -> MagicMock:
    """The Xray pass reads its batch through execute() (a three-column join),
    so this fake answers that separately from the scalar()/scalars() lookups
    the rest of the pass performs."""

    session = MagicMock(spec=AsyncSession)
    session.add = MagicMock()
    session.commit = AsyncMock()

    async def _flush() -> None:
        for call in session.add.call_args_list:
            row = call.args[0]
            if getattr(row, "id", None) is None:
                row.id = uuid4()

    session.flush = AsyncMock(side_effect=_flush)

    async def _execute(statement: Any) -> MagicMock:
        result = MagicMock()
        result.all = MagicMock(return_value=[(client, profile_code, agent_profile_code)])
        return result

    async def _scalars(statement: Any) -> MagicMock:
        result = MagicMock()
        # Healthy fixtures have no orphaned owners; only the server query
        # should receive a VPNServer row.
        result.all = MagicMock(
            return_value=[] if " devices " in " ".join(str(statement).split()) else [_server()]
        )
        return result

    async def _scalar(statement: Any) -> object | None:
        entity = cast(type, statement.column_descriptions[0]["entity"])
        # Anything the pass add()-ed this run (an AgentOperation) wins, so the
        # repair path can find the operation it just created.
        for call in reversed(session.add.call_args_list):
            row = call.args[0]
            if isinstance(row, entity):
                if isinstance(row, AgentOperation) and row.state != "running":
                    continue
                return row
        if entity is DeviceProtocolCredential:
            return credential
        if entity is XrayClient:
            return client
        return None

    session.execute = AsyncMock(side_effect=_execute)
    session.scalars = AsyncMock(side_effect=_scalars)
    session.scalar = AsyncMock(side_effect=_scalar)
    return session


def _run(session: MagicMock, agent: FakeXrayAgent) -> Any:
    return asyncio.run(
        run_xray_reconciliation(
            make_session_factory(cast(AsyncSession, session)),
            _builder(agent),
            Settings(env="test"),
            _keys(),
        )
    )


def test_in_sync_when_the_agent_has_an_active_client() -> None:
    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1)
    )

    summary = _run(_session(client=client, credential=_credential()), agent)

    assert summary.checked == 1
    assert summary.in_sync == 1
    assert agent.reconcile_calls[0].client_uuid == CLIENT_UUID


def test_ad_block_sibling_is_reconciled_under_the_agents_own_profile_code() -> None:
    """The agent serves the underlying inbound and has never heard of the
    "-adblock" sibling, so asking it under the sibling's own code would come
    back as an unknown profile and strand the row."""

    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1)
    )

    _run(
        _session(
            client=client,
            credential=_credential(),
            profile_code="vless-xhttp-tls-adblock",
            agent_profile_code="vless-xhttp-tls",
        ),
        agent,
    )

    assert agent.reconcile_calls[0].protocol_profile_code == "vless-xhttp-tls"


def test_a_revoking_row_the_agent_still_serves_is_repaired_by_revoking() -> None:
    client = _client(state=ProvisioningState.REVOKING.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1),
        revoke=RevokeXrayClientResponse(
            state="revoked", applied_generation=1, revoked_at=datetime.now(UTC)
        ),
    )

    summary = _run(_session(client=client, credential=_credential()), agent)

    assert summary.repaired == 1
    assert agent.revoke_calls[0].client_uuid == CLIENT_UUID
    assert client.state == ProvisioningState.REVOKED.value


def test_an_active_row_the_agent_lost_is_repaired_by_reprovisioning() -> None:
    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="drift_detected", observed_generation=None),
        provision=ProvisionXrayClientResponse(
            state="active",
            applied_generation=2,
            server_address="vps1.example.com",
            port=8445,
            sni="vps1.example.com",
            transport="xhttp",
            transport_security="none",
        ),
    )

    summary = _run(_session(client=client, credential=_credential()), agent)

    assert summary.repaired == 1
    assert agent.provision_calls[0].client_uuid == CLIENT_UUID
    assert client.state == ProvisioningState.ACTIVE.value


def test_a_stuck_applying_row_is_recovered_without_calling_the_agent_again() -> None:
    client = _client(state=ProvisioningState.APPLYING.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=4)
    )

    summary = _run(_session(client=client, credential=_credential()), agent)

    assert summary.in_sync == 1
    assert client.state == ProvisioningState.ACTIVE.value
    assert client.applied_generation == 4
    assert agent.provision_calls == []


def test_an_undecryptable_credential_is_ambiguous_and_never_reaches_the_agent() -> None:
    """A key that no longer decrypts the envelope says nothing about whether
    the client is healthy on the agent, so this must not be repaired -- and
    repairing would be impossible anyway without the plaintext UUID."""

    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1)
    )

    session = _session(client=client, credential=_credential(decryptable=False))
    summary = _run(session, agent)

    assert summary.ambiguous == 1
    assert agent.reconcile_calls == []
    record = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], ReconciliationRecord)
    )
    assert record.error_code == "credential_unreadable"


# --- orphan prune -----------------------------------------------------------


class FakePruneAgent(FakeXrayAgent):
    def __init__(self, response: PruneXrayClientsResponse | Exception) -> None:
        super().__init__(
            reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1)
        )
        self.prune_result = response
        self.prune_calls: list[PruneXrayClientsRequest] = []

    async def prune_xray_clients(
        self, request: PruneXrayClientsRequest
    ) -> PruneXrayClientsResponse:
        self.prune_calls.append(request)
        if isinstance(self.prune_result, Exception):
            raise self.prune_result
        return self.prune_result


def _prune_session(*, client: MagicMock, credential: MagicMock) -> MagicMock:
    session = _session(client=client, credential=credential)

    async def _scalars(statement: Any) -> MagicMock:
        result = MagicMock()
        result.all = MagicMock(return_value=[_server()])
        return result

    session.scalars = AsyncMock(side_effect=_scalars)
    return session


def _run_prune(session: MagicMock, agent: FakePruneAgent) -> Any:
    return asyncio.run(
        run_xray_orphan_prune(
            make_session_factory(cast(AsyncSession, session)), _builder(agent), _keys()
        )
    )


def test_prune_sends_every_live_client_as_the_expected_set() -> None:
    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakePruneAgent(PruneXrayClientsResponse(state="pruned", removed=2, kept=1))

    summary = _run_prune(_prune_session(client=client, credential=_credential()), agent)

    assert summary.removed == 2
    assert summary.kept == 1
    assert [e.client_uuid for e in agent.prune_calls[0].expected] == [CLIENT_UUID]


def test_prune_refuses_to_run_when_a_credential_cannot_be_decrypted() -> None:
    """The undecryptable client is almost certainly live on the agent, so
    omitting it from the expected set would ask the agent to revoke a working
    tunnel. Skipping the whole server is the only safe answer."""

    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakePruneAgent(PruneXrayClientsResponse(state="pruned", removed=1, kept=0))

    summary = _run_prune(
        _prune_session(client=client, credential=_credential(decryptable=False)), agent
    )

    assert summary.skipped == 1
    assert summary.removed == 0
    assert agent.prune_calls == []


def test_prune_records_an_error_when_the_agent_apply_fails() -> None:
    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakePruneAgent(
        PruneXrayClientsResponse(state="failed", removed=0, kept=3, error_code="apply_failed")
    )

    summary = _run_prune(_prune_session(client=client, credential=_credential()), agent)

    assert summary.errored == 1
    assert summary.removed == 0


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
@pytest.mark.parametrize(
    "failure",
    [
        AgentRejected(422, "apply failed"),
        AgentUnreachable("connection refused"),
        RevokeXrayClientResponse(
            state="failed",
            applied_generation=1,
            revoked_at=datetime.now(UTC),
            error_code="apply_failed",
        ),
    ],
)
def test_failed_removal_is_retried_until_revoked(
    profile_code: str,
    failure: Exception | RevokeXrayClientResponse,
) -> None:
    client = _client(state=ProvisioningState.REVOKING.value)
    credential = _credential()
    credential.state = ProvisioningState.REVOKING.value
    client.revoked_at = credential.revoked_at = None
    session = _session(client=client, credential=credential, profile_code=profile_code)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1),
        revoke=failure,
    )

    assert _run(session, agent).repair_failed == 1
    assert client.state == credential.state == ProvisioningState.REVOKING.value
    first_operation = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], AgentOperation)
    )
    assert first_operation.state == "failed"
    assert first_operation.finished_at is not None
    assert _run(session, agent).repair_failed == 1
    assert client.state == credential.state == ProvisioningState.REVOKING.value
    assert client.revoked_at is credential.revoked_at is None
    agent.revoke_result = RevokeXrayClientResponse(
        state="revoked", applied_generation=1, revoked_at=datetime.now(UTC)
    )

    assert _run(session, agent).repaired == 1
    assert client.state == credential.state == ProvisioningState.REVOKED.value
    assert client.revoked_at is not None
    assert credential.revoked_at is not None
    assert len(agent.revoke_calls) == 3
    assert len({call.idempotency_key for call in agent.revoke_calls}) == 3
    assert agent.revoke_calls[2].protocol_profile_code == profile_code
    assert agent.revoke_calls[2].client_uuid == CLIENT_UUID
    assert not agent.provision_calls


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
@pytest.mark.parametrize(
    ("response", "error_code"),
    [
        (AgentUnreachable("credential-canary"), "agent_unreachable"),
        (AgentRejected(422, "credential-canary"), "agent_rejected"),
        (AgentResponseAmbiguous("credential-canary"), "agent_response_ambiguous"),
        (AgentResponseInvalid("credential-canary"), "agent_response_invalid"),
        (
            ReconcileXrayClientResponse(outcome="ambiguous", error_code="generation_unknown"),
            "generation_unknown",
        ),
    ],
)
def test_observation_records_only_safe_error_evidence(
    profile_code: str,
    response: ReconcileXrayClientResponse | Exception,
    error_code: str,
) -> None:
    client = _client(state="active")
    session = _session(client=client, credential=_credential(), profile_code=profile_code)
    agent = FakeXrayAgent(reconcile=response)

    assert _run(session, agent).ambiguous == 1
    record = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], ReconciliationRecord)
    )
    assert record.outcome == "ambiguous"
    assert record.error_code == error_code
    assert record.agent_operation_id is None
    assert "credential-canary" not in repr(vars(record))
    assert not agent.provision_calls and not agent.revoke_calls


@pytest.mark.parametrize("profile_code", ["vless-xhttp-tls", "hysteria2"])
@pytest.mark.parametrize("wants_present", [True, False])
@pytest.mark.parametrize(
    ("failure", "error_code", "ambiguous"),
    [
        (AgentUnreachable("credential-canary"), "agent_unreachable", False),
        (AgentRejected(422, "credential-canary"), "agent_rejected", False),
        (AgentResponseAmbiguous("credential-canary"), "agent_response_ambiguous", True),
        (AgentResponseInvalid("credential-canary"), "agent_response_invalid", True),
        (None, "apply_failed", False),
    ],
)
def test_repair_evidence_preserves_failure_vs_uncertainty_and_operation(
    profile_code: str,
    wants_present: bool,
    failure: Exception | None,
    error_code: str,
    ambiguous: bool,
) -> None:
    state = "applying" if wants_present else "revoking"
    client = _client(state=state)
    credential = _credential()
    credential.state = state
    session = _session(client=client, credential=credential, profile_code=profile_code)
    provision = ProvisionXrayClientResponse(
        state="failed",
        applied_generation=1,
        server_address="vpn.example.test",
        port=8445,
        sni="vpn.example.test",
        transport="xhttp",
        transport_security="none",
        error_code="apply_failed",
    )
    revoke = RevokeXrayClientResponse(
        state="failed",
        applied_generation=1,
        revoked_at=datetime.now(UTC),
        error_code="apply_failed",
    )
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(
            outcome="drift_detected" if wants_present else "in_sync"
        ),
        provision=failure or provision,
        revoke=failure or revoke,
    )

    summary = _run(session, agent)
    assert summary.ambiguous == int(ambiguous)
    assert summary.repair_failed == int(not ambiguous)
    records = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], ReconciliationRecord)
    ]
    record = records[-1]
    operation = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], AgentOperation)
    )
    assert record.outcome == ("ambiguous" if ambiguous else "repair_failed")
    assert record.error_code == error_code
    assert record.agent_operation_id == operation.id
    assert operation.id is not None
    assert "credential-canary" not in repr(vars(record))
    assert operation.state == ("running" if ambiguous else "failed")
    assert (
        client.state == credential.state == (state if ambiguous or not wants_present else "failed")
    )
    if ambiguous:
        assert operation.finished_at is None
        agent.provision_result = provision.model_copy(
            update={"state": "active", "error_code": None}
        )
        agent.revoke_result = revoke.model_copy(update={"state": "revoked", "error_code": None})
        assert _run(session, agent).repaired == 1
        requests = agent.provision_calls if wants_present else agent.revoke_calls
        assert requests[0].idempotency_key == requests[1].idempotency_key
        success = [
            call.args[0]
            for call in session.add.call_args_list
            if isinstance(call.args[0], ReconciliationRecord)
        ][-1]
        assert success.outcome == "repair_succeeded"
        assert success.error_code is operation.error_code is None
        assert success.agent_operation_id == operation.id
    else:
        assert operation.error_code == error_code


def test_a_target_narrows_the_pass_to_that_client() -> None:
    client = _client(state=ProvisioningState.ACTIVE.value)
    agent = FakeXrayAgent(
        reconcile=ReconcileXrayClientResponse(outcome="in_sync", observed_generation=1)
    )
    session = _session(client=client, credential=_credential())

    asyncio.run(
        run_xray_reconciliation(
            make_session_factory(cast(AsyncSession, session)),
            _builder(agent),
            Settings(env="test"),
            _keys(),
            target_id=client.id,
        )
    )

    statements = [str(call.args[0]) for call in session.execute.call_args_list]
    batch = next(s for s in statements if "ORDER BY xray_clients.updated_at" in s)
    assert "xray_clients.id = " in batch
