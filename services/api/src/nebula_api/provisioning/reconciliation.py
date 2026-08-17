"""One-shot reconciliation pass comparing each in-flight or steady-state
WireGuard peer's desired configuration against the agent's observed state,
repairing safe drift and recording ambiguous drift for operator triage
(docs/architecture.md).

The agent's reconcile operation can only answer "does a peer with this
public key exist and match this generation/address" -- it has no notion of
our own intent (provision vs revoke). This module translates that raw
in_sync/drift_detected answer into agreement or disagreement with what each
row is trying to achieve: an active/applying peer *wants* to be present, a
revoking peer wants to be absent.

Agreement recovers DB state without calling the agent again -- this is the
crash-recovery path for a stuck "applying" peer (promotes to "active") and,
symmetrically, a stuck "revoking" peer whose revoke actually landed
(promotes to "revoked"). Disagreement re-issues the appropriate operation
(provision_device or revoke_device): the peer's still-"running"
AgentOperation and idempotency key are reused when one exists (this is a
retry of the same logical operation), or a fresh one is minted when the
peer had already reached a terminal state and only later drifted (a new
repair action, not a retry). "ambiguous" -- from the agent itself, or from
the agent client's own crash-safety classification -- is recorded and
logged for an operator, never auto-repaired: guessing wrong here could
either strand a peer or apply an operation whose safety can't be reasoned
about.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import select
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
    ReconcileRequest,
    RevokeDeviceRequest,
)
from nebula_api.auth.audit import add_audit_event
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AgentOperation, ReconciliationRecord
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer
from nebula_api.models.topology import VPNServer
from nebula_api.models.types import OperationState, ProvisioningState, ServerState
from nebula_api.settings import Settings

Clock = Callable[[], datetime]

_LOGGER = logging.getLogger(__name__)

_CANDIDATE_STATES = (
    ProvisioningState.ACTIVE.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.REVOKING.value,
)
_RUNNING_STUCK_STATES = (ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value)

# Matches agent_operations.attempt_count_range's CHECK constraint. A repair
# whose response keeps coming back ambiguous deliberately leaves its operation
# "running" for the next pass to retry, so this counter climbs once per run and
# would eventually breach the constraint if it were not clamped.
_MAX_ATTEMPT_COUNT = 100


@dataclass(slots=True)
class ReconciliationSummary:
    checked: int = 0
    in_sync: int = 0
    repaired: int = 0
    repair_failed: int = 0
    ambiguous: int = 0
    errored: int = 0

    @property
    def had_problems(self) -> bool:
        return self.repair_failed > 0 or self.ambiguous > 0 or self.errored > 0


async def run_reconciliation(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    settings: Settings,
    *,
    clock: Clock = lambda: datetime.now(UTC),
) -> ReconciliationSummary:
    """Reconcile up to `settings.reconciliation_batch_size` peers, oldest
    first, across every active VPN server."""

    summary = ReconciliationSummary()
    async with session_factory() as session:
        peers = (
            await session.scalars(
                select(WireGuardPeer)
                .join(VPNServer, WireGuardPeer.vpn_server_id == VPNServer.id)
                .where(
                    VPNServer.state == ServerState.ACTIVE.value,
                    WireGuardPeer.state.in_(_CANDIDATE_STATES),
                )
                .order_by(WireGuardPeer.updated_at)
                .limit(settings.reconciliation_batch_size)
            )
        ).all()
        server_ids = {peer.vpn_server_id for peer in peers}
        servers = {
            server.id: server
            for server in (
                await session.scalars(select(VPNServer).where(VPNServer.id.in_(server_ids)))
            ).all()
        }

    for peer in peers:
        summary.checked += 1
        try:
            await _reconcile_one(
                session_factory,
                agent_client_builder,
                servers[peer.vpn_server_id],
                peer,
                summary,
                clock,
            )
        except Exception:
            # One peer must never strand the rest of the batch: without this
            # boundary an unexpected failure here (a constraint violation, a
            # lost connection mid-transaction) would abort the whole pass and
            # every peer after this one would silently go unreconciled.
            summary.errored += 1
            _LOGGER.exception("reconciliation failed unexpectedly for peer %s", peer.id)
    return summary


async def _reconcile_one(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    server: VPNServer,
    peer: WireGuardPeer,
    summary: ReconciliationSummary,
    clock: Clock,
) -> None:
    wants_present = peer.state != ProvisioningState.REVOKING.value
    desired_generation = peer.applied_generation if peer.applied_generation > 0 else 1
    correlation_id = uuid4()

    try:
        async with agent_client_builder(server.agent_host, server.agent_port) as agent:
            response = await agent.reconcile(
                ReconcileRequest(
                    correlation_id=correlation_id,
                    target_kind="wireguard_peer",
                    target_id=peer.id,
                    public_key=peer.public_key,
                    assigned_address=peer.assigned_address,
                    desired_generation=desired_generation,
                )
            )
    except (AgentUnreachable, AgentResponseAmbiguous, AgentResponseInvalid, AgentRejected) as error:
        summary.ambiguous += 1
        _LOGGER.warning("reconciliation could not reach peer %s: %s", peer.id, error)
        await _record(session_factory, server.id, peer.id, desired_generation, None, "ambiguous")
        return

    if response.outcome == "ambiguous":
        summary.ambiguous += 1
        _LOGGER.warning("agent reported ambiguous drift for peer %s", peer.id)
        await _record(
            session_factory,
            server.id,
            peer.id,
            desired_generation,
            response.observed_generation,
            "ambiguous",
        )
        return

    agent_reports_present = response.outcome == "in_sync"
    if agent_reports_present == wants_present:
        summary.in_sync += 1
        await _record(
            session_factory,
            server.id,
            peer.id,
            desired_generation,
            response.observed_generation,
            "in_sync",
        )
        await _recover_if_stuck(session_factory, peer, response.observed_generation, clock)
        return

    await _record(
        session_factory,
        server.id,
        peer.id,
        desired_generation,
        response.observed_generation,
        "repair_requested",
    )
    succeeded = await _repair(
        session_factory,
        agent_client_builder,
        server,
        peer,
        wants_present,
        desired_generation,
        correlation_id,
        clock,
    )
    if succeeded:
        summary.repaired += 1
    else:
        summary.repair_failed += 1
    await _record(
        session_factory,
        server.id,
        peer.id,
        desired_generation,
        None,
        "repair_succeeded" if succeeded else "repair_failed",
    )


async def _record(
    session_factory: SessionFactory,
    server_id: UUID,
    peer_id: UUID,
    desired_generation: int,
    observed_generation: int | None,
    outcome: str,
) -> None:
    async with session_factory() as session:
        session.add(
            ReconciliationRecord(
                vpn_server_id=server_id,
                agent_operation_id=None,
                target_kind="wireguard_peer",
                target_id=peer_id,
                desired_generation=desired_generation,
                observed_generation=observed_generation,
                outcome=outcome,
            )
        )
        await session.commit()


async def _recover_if_stuck(
    session_factory: SessionFactory,
    peer: WireGuardPeer,
    observed_generation: int | None,
    clock: Clock,
) -> None:
    if peer.state not in _RUNNING_STUCK_STATES:
        return
    now = _now(clock)
    async with session_factory() as session:
        fresh_peer = await session.scalar(
            select(WireGuardPeer).where(WireGuardPeer.id == peer.id).with_for_update()
        )
        if fresh_peer is None or fresh_peer.state not in _RUNNING_STUCK_STATES:
            return
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == fresh_peer.credential_id)
            .with_for_update()
        )
        operation = await _running_operation(session, fresh_peer.id)
        if fresh_peer.state == ProvisioningState.APPLYING.value:
            fresh_peer.state = ProvisioningState.ACTIVE.value
            fresh_peer.applied_generation = (
                observed_generation or fresh_peer.applied_generation or 1
            )
            fresh_peer.applied_at = now
            if credential is not None:
                credential.state = ProvisioningState.ACTIVE.value
        else:
            fresh_peer.state = ProvisioningState.REVOKED.value
            fresh_peer.revoked_at = now
            if credential is not None:
                credential.state = ProvisioningState.REVOKED.value
                credential.revoked_at = now
        if operation is not None:
            operation.state = OperationState.SUCCEEDED.value
            operation.finished_at = now
        add_audit_event(
            session,
            actor_kind="system",
            actor_id=None,
            target_kind="wireguard_peer",
            target_id=fresh_peer.id,
            event_code="peer_changed",
            outcome="succeeded",
            request_id=uuid4(),
            reason_code="reconciled",
        )
        await session.commit()


async def _repair(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    server: VPNServer,
    peer: WireGuardPeer,
    wants_present: bool,
    desired_generation: int,
    correlation_id: UUID,
    clock: Clock,
) -> bool:
    now = _now(clock)
    async with session_factory() as session:
        operation = await _running_operation(session, peer.id)
        if operation is None:
            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=correlation_id,
                operation_kind="provision_device" if wants_present else "revoke_device",
                target_kind="wireguard_peer",
                target_id=peer.id,
                state=OperationState.RUNNING.value,
                desired_generation=desired_generation,
                request_fingerprint=_fingerprint(
                    "reconcile_repair", str(peer.id), peer.public_key, str(desired_generation)
                ),
                attempt_count=1,
                requested_at=now,
                started_at=now,
            )
            session.add(operation)
        else:
            operation.attempt_count = min(operation.attempt_count + 1, _MAX_ATTEMPT_COUNT)
            operation.started_at = now
        await session.flush()
        idempotency_key = operation.idempotency_key
        await session.commit()

    try:
        async with agent_client_builder(server.agent_host, server.agent_port) as agent:
            if wants_present:
                provision_response = await agent.provision_device(
                    ProvisionDeviceRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                        target_kind="wireguard_peer",
                        target_id=peer.id,
                        desired_generation=desired_generation,
                        public_key=peer.public_key,
                        assigned_address=peer.assigned_address,
                    )
                )
                succeeded = provision_response.state == "active"
                applied_generation = provision_response.applied_generation
            else:
                revoke_response = await agent.revoke_device(
                    RevokeDeviceRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                        target_kind="wireguard_peer",
                        target_id=peer.id,
                        public_key=peer.public_key,
                        desired_generation=desired_generation,
                    )
                )
                succeeded = revoke_response.state == "revoked"
                applied_generation = revoke_response.applied_generation
    except (AgentUnreachable, AgentRejected):
        await _finalize_repair(
            session_factory,
            peer.id,
            succeeded=False,
            applied_generation=None,
            wants_present=wants_present,
            now=now,
        )
        return False
    except (AgentResponseAmbiguous, AgentResponseInvalid):
        _LOGGER.warning("repair response ambiguous for peer %s; left running", peer.id)
        return False

    await _finalize_repair(
        session_factory,
        peer.id,
        succeeded=succeeded,
        applied_generation=applied_generation,
        wants_present=wants_present,
        now=now,
    )
    return succeeded


async def _finalize_repair(
    session_factory: SessionFactory,
    peer_id: UUID,
    *,
    succeeded: bool,
    applied_generation: int | None,
    wants_present: bool,
    now: datetime,
) -> None:
    async with session_factory() as session:
        peer = await session.scalar(
            select(WireGuardPeer).where(WireGuardPeer.id == peer_id).with_for_update()
        )
        if peer is None:
            return
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == peer.credential_id)
            .with_for_update()
        )
        operation = await _running_operation(session, peer.id)
        if succeeded:
            if wants_present:
                peer.state = ProvisioningState.ACTIVE.value
                peer.applied_generation = applied_generation or peer.applied_generation
                peer.applied_at = now
                if credential is not None:
                    credential.state = ProvisioningState.ACTIVE.value
            else:
                peer.state = ProvisioningState.REVOKED.value
                peer.revoked_at = now
                if credential is not None:
                    credential.state = ProvisioningState.REVOKED.value
                    credential.revoked_at = now
        else:
            peer.state = ProvisioningState.FAILED.value
            if credential is not None:
                credential.state = ProvisioningState.FAILED.value
        if operation is not None:
            operation.state = (
                OperationState.SUCCEEDED.value if succeeded else OperationState.FAILED.value
            )
            operation.finished_at = now
            if not succeeded:
                operation.error_code = "reconciliation_repair_failed"
        add_audit_event(
            session,
            actor_kind="system",
            actor_id=None,
            target_kind="wireguard_peer",
            target_id=peer.id,
            event_code="peer_changed",
            outcome="succeeded" if succeeded else "failed",
            request_id=uuid4(),
            reason_code="reconciliation_repaired" if succeeded else "reconciliation_repair_failed",
        )
        await session.commit()


async def _running_operation(session: AsyncSession, peer_id: UUID) -> AgentOperation | None:
    operation = await session.scalar(
        select(AgentOperation).where(
            AgentOperation.target_kind == "wireguard_peer",
            AgentOperation.target_id == peer_id,
            AgentOperation.state == OperationState.RUNNING.value,
        )
    )
    return operation


def _fingerprint(*parts: str) -> str:
    return sha256("\x00".join(parts).encode()).hexdigest()


def _now(clock: Clock) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("reconciliation clock must be timezone aware")
    return value.astimezone(UTC)
