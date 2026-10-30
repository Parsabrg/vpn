"""One-shot reconciliation pass comparing each in-flight or steady-state
WireGuard peer or Xray client against the agent's observed state, repairing
safe drift and recording ambiguous drift for operator triage
(docs/architecture.md). The two protocols get sibling passes -- see the
"Xray clients" divider below for why they are not one generalized pass.

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
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.agent_client.client import (
    AgentClientBuilder,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentResponseInvalid,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    ExpectedXrayClient,
    ProvisionDeviceRequest,
    ProvisionXrayClientRequest,
    PruneXrayClientsRequest,
    ReconcileRequest,
    ReconcileXrayClientRequest,
    RevokeDeviceRequest,
    RevokeXrayClientRequest,
)
from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.models.operations import AgentOperation, ReconciliationRecord
from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)
from nebula_api.models.topology import ProtocolProfile, VPNServer
from nebula_api.models.types import (
    RUNNING_SERVER_STATES,
    AccountState,
    LifecycleState,
    OperationState,
    ProvisioningState,
)
from nebula_api.provisioning.xray_credentials import (
    EncryptedXrayCredential,
    XrayCredentialEncryptionError,
    decrypt_xray_credential,
)
from nebula_api.settings import Settings

Clock = Callable[[], datetime]

_LOGGER = logging.getLogger(__name__)

_CANDIDATE_STATES = (
    ProvisioningState.ACTIVE.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.REVOKING.value,
)
_RUNNING_STUCK_STATES = (ProvisioningState.APPLYING.value, ProvisioningState.REVOKING.value)

# Live states that an owner check can still act on. REVOKING is excluded
# because it is already on its way out; re-marking it would only churn the row.
_ORPHANABLE_STATES = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
)

# Everything uq_xray_clients_live_device_profile treats as live. Wider than
# _CANDIDATE_STATES on purpose: a REQUESTED row has no credential on the agent
# yet, but it is about to, and a prune racing that provision must not delete
# what it is in the middle of creating.
_LIVE_STATES = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
    ProvisioningState.REVOKING.value,
)

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


# Any fixed key: every pass, scheduled or asked for from the admin panel,
# takes it, so two never repair the same row at once.
_RECONCILIATION_LOCK_KEY = 0x4E42_5243  # "NBRC"


@asynccontextmanager
async def reconciliation_lock(session_factory: SessionFactory) -> AsyncIterator[bool]:
    """Yield whether this caller holds the reconciliation lock.

    A transaction-scoped advisory lock on a session of its own, held for as
    long as the block runs; False when another pass already holds it.
    """

    async with session_factory() as session, session.begin():
        acquired = bool(
            await session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:key)"),
                {"key": _RECONCILIATION_LOCK_KEY},
            )
        )
        yield acquired


class ReconciliationBusy(Exception):
    """Another reconciliation pass is running; try again shortly."""


async def reconcile_now(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    settings: Settings,
    keys: AuthKeyMaterial,
    *,
    target_id: UUID | None = None,
) -> tuple[ReconciliationSummary, ReconciliationSummary]:
    """Both passes, under the lock: what the scheduled sweep does, on demand.

    With `target_id`, only that WireGuard peer or Xray client (the other pass
    finds nothing). Raises ReconciliationBusy instead of waiting.
    """

    async with reconciliation_lock(session_factory) as acquired:
        if not acquired:
            raise ReconciliationBusy
        wireguard = await run_reconciliation(
            session_factory, agent_client_builder, settings, target_id=target_id
        )
        xray = await run_xray_reconciliation(
            session_factory, agent_client_builder, settings, keys, target_id=target_id
        )
    return wireguard, xray


async def run_reconciliation(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    settings: Settings,
    *,
    clock: Clock = lambda: datetime.now(UTC),
    target_id: UUID | None = None,
) -> ReconciliationSummary:
    """Reconcile up to `settings.reconciliation_batch_size` peers, oldest
    first, across every active VPN server -- or only the peer `target_id`,
    for an operator checking one again (same rules, same records)."""

    summary = ReconciliationSummary()
    # Before choosing candidates, not after: a peer marked here lands in this
    # same sweep rather than waiting for the next one.
    await _mark_orphaned_revoking(session_factory, WireGuardPeer, clock)
    async with session_factory() as session:
        peers = (
            await session.scalars(
                select(WireGuardPeer)
                .join(VPNServer, WireGuardPeer.vpn_server_id == VPNServer.id)
                .where(
                    VPNServer.state.in_(RUNNING_SERVER_STATES),
                    WireGuardPeer.state.in_(_CANDIDATE_STATES),
                    *([WireGuardPeer.id == target_id] if target_id is not None else []),
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


async def _mark_orphaned_revoking[Row: (WireGuardPeer, XrayClient)](
    session_factory: SessionFactory,
    model: type[Row],
    clock: Clock,
) -> int:
    """Hand any credential whose owner is gone to the revoke path.

    Revoking a device and disabling a user both mark their credentials
    REVOKING directly, so in the normal case this finds nothing. It exists for
    the cases that marking cannot cover: rows created before that cascade
    existed, a device revoked by a path that has not learned to cascade, and
    any future one that forgets. Those failures are silent and indefinite --
    the credential keeps working while every screen shows the owner as revoked
    -- which is exactly the kind of drift this module exists to correct.

    Deliberately only ever *widens* revocation. There is no reverse rule
    promoting a credential back to ACTIVE because its owner looks fine: drift
    resolved toward less access is safe, and toward more access is not.
    """

    now = _now(clock)
    marked = 0
    async with session_factory() as session:
        rows = (
            await session.scalars(
                select(model)
                .join(Device, model.device_id == Device.id)
                .join(User, Device.user_id == User.id)
                .where(
                    model.state.in_(_ORPHANABLE_STATES),
                    (Device.state == LifecycleState.REVOKED)
                    | (User.state == AccountState.DISABLED),
                )
                .with_for_update(of=model)
            )
        ).all()
        for row in rows:
            row.state = ProvisioningState.REVOKING.value
            row.updated_at = now
            credential = await session.scalar(
                select(DeviceProtocolCredential)
                .where(DeviceProtocolCredential.id == row.credential_id)
                .with_for_update()
            )
            if credential is not None:
                credential.state = ProvisioningState.REVOKING.value
            marked += 1
            _LOGGER.warning(
                "%s %s is live but its owner is not; marking revoking",
                model.__name__,
                row.id,
            )
        await session.commit()
    return marked


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
        await _record(
            session_factory,
            server.id,
            peer.id,
            desired_generation,
            None,
            "ambiguous",
            error_code=_reconciliation_error_code(error),
        )
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
            error_code=response.error_code,
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
    outcome, operation_id, error_code = await _repair(
        session_factory,
        agent_client_builder,
        server,
        peer,
        wants_present,
        desired_generation,
        correlation_id,
        clock,
    )
    if outcome == "repair_succeeded":
        summary.repaired += 1
    elif outcome == "repair_failed":
        summary.repair_failed += 1
    else:
        summary.ambiguous += 1
    await _record(
        session_factory,
        server.id,
        peer.id,
        desired_generation,
        None,
        outcome,
        agent_operation_id=operation_id,
        error_code=error_code,
    )


async def _record(
    session_factory: SessionFactory,
    server_id: UUID,
    peer_id: UUID,
    desired_generation: int,
    observed_generation: int | None,
    outcome: str,
    target_kind: str = "wireguard_peer",
    *,
    agent_operation_id: UUID | None = None,
    error_code: str | None = None,
) -> None:
    async with session_factory() as session:
        session.add(
            ReconciliationRecord(
                vpn_server_id=server_id,
                agent_operation_id=agent_operation_id,
                target_kind=target_kind,
                target_id=peer_id,
                desired_generation=desired_generation,
                observed_generation=observed_generation,
                outcome=outcome,
                error_code=error_code,
            )
        )
        await session.commit()


def _reconciliation_error_code(
    error: AgentUnreachable | AgentRejected | AgentResponseAmbiguous | AgentResponseInvalid,
) -> str:
    # Exception details may contain credential material or response bodies.
    # Persist only the locally defined classification, never their text.
    if isinstance(error, AgentUnreachable):
        return "agent_unreachable"
    if isinstance(error, AgentRejected):
        return "agent_rejected"
    if isinstance(error, AgentResponseAmbiguous):
        return "agent_response_ambiguous"
    return "agent_response_invalid"


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
) -> tuple[str, UUID, str | None]:
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
        operation_id = operation.id
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
                error_code = provision_response.error_code
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
                error_code = revoke_response.error_code
    except (AgentUnreachable, AgentRejected) as error:
        error_code = _reconciliation_error_code(error)
        await _finalize_repair(
            session_factory,
            peer.id,
            succeeded=False,
            applied_generation=None,
            wants_present=wants_present,
            now=now,
            error_code=error_code,
        )
        return "repair_failed", operation_id, error_code
    except (AgentResponseAmbiguous, AgentResponseInvalid) as error:
        _LOGGER.warning("repair response ambiguous for peer %s; left running", peer.id)
        return "ambiguous", operation_id, _reconciliation_error_code(error)

    error_code = None if succeeded else error_code or "reconciliation_repair_failed"
    await _finalize_repair(
        session_factory,
        peer.id,
        succeeded=succeeded,
        applied_generation=applied_generation,
        wants_present=wants_present,
        now=now,
        error_code=error_code,
    )
    return "repair_succeeded" if succeeded else "repair_failed", operation_id, error_code


async def _finalize_repair(
    session_factory: SessionFactory,
    peer_id: UUID,
    *,
    succeeded: bool,
    applied_generation: int | None,
    wants_present: bool,
    now: datetime,
    error_code: str | None,
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
            # Removal stays pending for the next sweep after a known failure.
            pending_state = (
                ProvisioningState.FAILED.value
                if wants_present
                else ProvisioningState.REVOKING.value
            )
            peer.state = pending_state
            if credential is not None:
                credential.state = pending_state
        if operation is not None:
            operation.state = (
                OperationState.SUCCEEDED.value if succeeded else OperationState.FAILED.value
            )
            operation.finished_at = now
            operation.error_code = error_code
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


# --- Xray clients ------------------------------------------------------------
#
# A sibling pass rather than a generalization of the WireGuard one above: the
# two agree on the shape of the question (is this target present, at what
# generation, and does that match what the row wants) but share almost none of
# the mechanics. A WireGuard peer is addressed by a public key the API stores
# in clear plus an assigned address; an Xray client is addressed by a UUID that
# only ever exists encrypted at rest, on an inbound named by a profile code
# that may itself be an alias. Threading both through one set of functions
# would put a protocol branch in every one of them -- the same reason the two
# driver contracts in services/vpn-agent were kept separate rather than one
# being made to extend the other.


async def run_xray_reconciliation(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    settings: Settings,
    keys: AuthKeyMaterial,
    *,
    clock: Clock = lambda: datetime.now(UTC),
    target_id: UUID | None = None,
) -> ReconciliationSummary:
    """Reconcile up to `settings.reconciliation_batch_size` Xray clients,
    oldest first, across every active VPN server -- or only `target_id`."""

    summary = ReconciliationSummary()
    await _mark_orphaned_revoking(session_factory, XrayClient, clock)
    async with session_factory() as session:
        rows = (
            await session.execute(
                select(XrayClient, ProtocolProfile.code, ProtocolProfile.agent_profile_code)
                .join(VPNServer, XrayClient.vpn_server_id == VPNServer.id)
                .join(ProtocolProfile, XrayClient.protocol_profile_id == ProtocolProfile.id)
                .where(
                    VPNServer.state.in_(RUNNING_SERVER_STATES),
                    XrayClient.state.in_(_CANDIDATE_STATES),
                    *([XrayClient.id == target_id] if target_id is not None else []),
                )
                .order_by(XrayClient.updated_at)
                .limit(settings.reconciliation_batch_size)
            )
        ).all()
        server_ids = {client.vpn_server_id for client, _, _ in rows}
        servers = {
            server.id: server
            for server in (
                await session.scalars(select(VPNServer).where(VPNServer.id.in_(server_ids)))
            ).all()
        }

    for client, profile_code, agent_profile_code in rows:
        summary.checked += 1
        try:
            await _reconcile_one_xray_client(
                session_factory,
                agent_client_builder,
                servers[client.vpn_server_id],
                client,
                # The agent has no concept of an ad-block sibling profile: it
                # serves the underlying inbound, so a sibling has to be asked
                # about under the code the agent actually knows -- the same
                # redirect provisioning/service.py applies when provisioning.
                agent_profile_code or profile_code,
                keys,
                summary,
                clock,
            )
        except Exception:
            # Same batch-isolation boundary as the WireGuard pass: one bad row
            # must never strand every row queued behind it.
            summary.errored += 1
            _LOGGER.exception("reconciliation failed unexpectedly for xray client %s", client.id)
    return summary


async def _reconcile_one_xray_client(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    server: VPNServer,
    client: XrayClient,
    agent_profile_code: str,
    keys: AuthKeyMaterial,
    summary: ReconciliationSummary,
    clock: Clock,
) -> None:
    wants_present = client.state != ProvisioningState.REVOKING.value
    desired_generation = client.applied_generation if client.applied_generation > 0 else 1
    correlation_id = uuid4()

    client_uuid = await _decrypt_client_uuid(session_factory, client, keys)
    if client_uuid is None:
        # Without the plaintext UUID there is no way to ask the agent about
        # this client, let alone repair it. Recorded ambiguous rather than
        # repair_failed: the client may be perfectly healthy on the agent, and
        # the defect is on our side (a key that no longer decrypts it).
        summary.ambiguous += 1
        _LOGGER.warning("xray client %s credential could not be decrypted", client.id)
        await _record(
            session_factory,
            server.id,
            client.id,
            desired_generation,
            None,
            "ambiguous",
            target_kind="xray_client",
            error_code="credential_unreadable",
        )
        return

    try:
        async with agent_client_builder(server.agent_host, server.agent_port) as agent:
            response = await agent.reconcile_xray_client(
                ReconcileXrayClientRequest(
                    correlation_id=correlation_id,
                    target_kind="xray_client",
                    target_id=client.id,
                    client_uuid=client_uuid,
                    protocol_profile_code=agent_profile_code,
                    desired_generation=desired_generation,
                )
            )
    except (AgentUnreachable, AgentResponseAmbiguous, AgentResponseInvalid, AgentRejected) as error:
        summary.ambiguous += 1
        _LOGGER.warning("reconciliation could not reach xray client %s: %s", client.id, error)
        await _record(
            session_factory,
            server.id,
            client.id,
            desired_generation,
            None,
            "ambiguous",
            target_kind="xray_client",
            error_code=_reconciliation_error_code(error),
        )
        return

    if response.outcome == "ambiguous":
        summary.ambiguous += 1
        _LOGGER.warning("agent reported ambiguous drift for xray client %s", client.id)
        await _record(
            session_factory,
            server.id,
            client.id,
            desired_generation,
            response.observed_generation,
            "ambiguous",
            target_kind="xray_client",
            error_code=response.error_code,
        )
        return

    agent_reports_present = response.outcome == "in_sync"
    if agent_reports_present == wants_present:
        summary.in_sync += 1
        await _record(
            session_factory,
            server.id,
            client.id,
            desired_generation,
            response.observed_generation,
            "in_sync",
            target_kind="xray_client",
        )
        await _recover_stuck_xray_client(
            session_factory, client, response.observed_generation, clock
        )
        return

    await _record(
        session_factory,
        server.id,
        client.id,
        desired_generation,
        response.observed_generation,
        "repair_requested",
        target_kind="xray_client",
    )
    outcome, operation_id, error_code = await _repair_xray_client(
        session_factory,
        agent_client_builder,
        server,
        client,
        client_uuid,
        agent_profile_code,
        wants_present,
        desired_generation,
        correlation_id,
        clock,
    )
    if outcome == "repair_succeeded":
        summary.repaired += 1
    elif outcome == "repair_failed":
        summary.repair_failed += 1
    else:
        summary.ambiguous += 1
    await _record(
        session_factory,
        server.id,
        client.id,
        desired_generation,
        None,
        outcome,
        target_kind="xray_client",
        agent_operation_id=operation_id,
        error_code=error_code,
    )


async def _decrypt_client_uuid(
    session_factory: SessionFactory, client: XrayClient, keys: AuthKeyMaterial
) -> UUID | None:
    async with session_factory() as session:
        credential = await session.scalar(
            select(DeviceProtocolCredential).where(
                DeviceProtocolCredential.id == client.credential_id
            )
        )
        if credential is None:
            return None
        try:
            return decrypt_xray_credential(
                EncryptedXrayCredential(
                    key_version=int(credential.key_version or 0),
                    nonce=credential.nonce or b"",
                    ciphertext=credential.ciphertext or b"",
                ),
                device_id=credential.device_id,
                credential_id=credential.id,
                key_ring=keys.xray_encryption_keys,
            )
        except (XrayCredentialEncryptionError, ValueError):
            return None


async def _recover_stuck_xray_client(
    session_factory: SessionFactory,
    client: XrayClient,
    observed_generation: int | None,
    clock: Clock,
) -> None:
    """The crash-recovery path: the agent already agrees with what this row was
    trying to reach, so the only thing still wrong is that the row never left
    its in-flight state."""

    if client.state not in _RUNNING_STUCK_STATES:
        return
    now = _now(clock)
    async with session_factory() as session:
        fresh = await session.scalar(
            select(XrayClient).where(XrayClient.id == client.id).with_for_update()
        )
        if fresh is None or fresh.state not in _RUNNING_STUCK_STATES:
            return
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == fresh.credential_id)
            .with_for_update()
        )
        operation = await _running_xray_operation(session, fresh.id)
        if fresh.state == ProvisioningState.APPLYING.value:
            fresh.state = ProvisioningState.ACTIVE.value
            fresh.applied_generation = observed_generation or fresh.applied_generation or 1
            fresh.applied_at = now
            if credential is not None:
                credential.state = ProvisioningState.ACTIVE.value
        else:
            fresh.state = ProvisioningState.REVOKED.value
            fresh.revoked_at = now
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
            target_kind="xray_client",
            target_id=fresh.id,
            event_code="peer_changed",
            outcome="succeeded",
            request_id=uuid4(),
            reason_code="reconciled",
        )
        await session.commit()


async def _repair_xray_client(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    server: VPNServer,
    client: XrayClient,
    client_uuid: UUID,
    agent_profile_code: str,
    wants_present: bool,
    desired_generation: int,
    correlation_id: UUID,
    clock: Clock,
) -> tuple[str, UUID, str | None]:
    now = _now(clock)
    async with session_factory() as session:
        operation = await _running_xray_operation(session, client.id)
        if operation is None:
            operation = AgentOperation(
                vpn_server_id=server.id,
                idempotency_key=uuid4(),
                correlation_id=correlation_id,
                operation_kind="provision_device" if wants_present else "revoke_device",
                target_kind="xray_client",
                target_id=client.id,
                state=OperationState.RUNNING.value,
                desired_generation=desired_generation,
                request_fingerprint=_fingerprint(
                    "reconcile_repair",
                    str(client.id),
                    client.opaque_label,
                    str(desired_generation),
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
        operation_id = operation.id
        await session.commit()

    try:
        async with agent_client_builder(server.agent_host, server.agent_port) as agent:
            if wants_present:
                provision_response = await agent.provision_xray_client(
                    ProvisionXrayClientRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                        target_kind="xray_client",
                        target_id=client.id,
                        desired_generation=desired_generation,
                        client_uuid=client_uuid,
                        protocol_profile_code=agent_profile_code,
                    )
                )
                succeeded = provision_response.state == "active"
                applied_generation = provision_response.applied_generation
                error_code = provision_response.error_code
            else:
                revoke_response = await agent.revoke_xray_client(
                    RevokeXrayClientRequest(
                        idempotency_key=idempotency_key,
                        correlation_id=correlation_id,
                        target_kind="xray_client",
                        target_id=client.id,
                        client_uuid=client_uuid,
                        protocol_profile_code=agent_profile_code,
                        desired_generation=desired_generation,
                    )
                )
                succeeded = revoke_response.state == "revoked"
                applied_generation = revoke_response.applied_generation
                error_code = revoke_response.error_code
    except (AgentUnreachable, AgentRejected) as error:
        error_code = _reconciliation_error_code(error)
        await _finalize_xray_repair(
            session_factory,
            client.id,
            succeeded=False,
            applied_generation=None,
            wants_present=wants_present,
            now=now,
            error_code=error_code,
        )
        return "repair_failed", operation_id, error_code
    except (AgentResponseAmbiguous, AgentResponseInvalid) as error:
        # Deliberately leaves the operation "running" so the next pass retries
        # it rather than recording an outcome that was never actually known.
        _LOGGER.warning("repair response ambiguous for xray client %s; left running", client.id)
        return "ambiguous", operation_id, _reconciliation_error_code(error)

    error_code = None if succeeded else error_code or "reconciliation_repair_failed"
    await _finalize_xray_repair(
        session_factory,
        client.id,
        succeeded=succeeded,
        applied_generation=applied_generation,
        wants_present=wants_present,
        now=now,
        error_code=error_code,
    )
    return "repair_succeeded" if succeeded else "repair_failed", operation_id, error_code


async def _finalize_xray_repair(
    session_factory: SessionFactory,
    client_id: UUID,
    *,
    succeeded: bool,
    applied_generation: int | None,
    wants_present: bool,
    now: datetime,
    error_code: str | None,
) -> None:
    async with session_factory() as session:
        client = await session.scalar(
            select(XrayClient).where(XrayClient.id == client_id).with_for_update()
        )
        if client is None:
            return
        credential = await session.scalar(
            select(DeviceProtocolCredential)
            .where(DeviceProtocolCredential.id == client.credential_id)
            .with_for_update()
        )
        operation = await _running_xray_operation(session, client.id)
        if succeeded:
            if wants_present:
                client.state = ProvisioningState.ACTIVE.value
                client.applied_generation = applied_generation or client.applied_generation
                client.applied_at = now
                if credential is not None:
                    credential.state = ProvisioningState.ACTIVE.value
            else:
                client.state = ProvisioningState.REVOKED.value
                client.revoked_at = now
                if credential is not None:
                    credential.state = ProvisioningState.REVOKED.value
                    credential.revoked_at = now
        else:
            # Removal stays pending for the next sweep after a known failure.
            pending_state = (
                ProvisioningState.FAILED.value
                if wants_present
                else ProvisioningState.REVOKING.value
            )
            client.state = pending_state
            if credential is not None:
                credential.state = pending_state
        if operation is not None:
            operation.state = (
                OperationState.SUCCEEDED.value if succeeded else OperationState.FAILED.value
            )
            operation.finished_at = now
            operation.error_code = error_code
        add_audit_event(
            session,
            actor_kind="system",
            actor_id=None,
            target_kind="xray_client",
            target_id=client.id,
            event_code="peer_changed",
            outcome="succeeded" if succeeded else "failed",
            request_id=uuid4(),
            reason_code="reconciliation_repaired" if succeeded else "reconciliation_repair_failed",
        )
        await session.commit()


async def _running_xray_operation(session: AsyncSession, client_id: UUID) -> AgentOperation | None:
    operation: AgentOperation | None = await session.scalar(
        select(AgentOperation).where(
            AgentOperation.target_kind == "xray_client",
            AgentOperation.target_id == client_id,
            AgentOperation.state == OperationState.RUNNING.value,
        )
    )
    return operation


# --- Orphaned agent-side credentials -----------------------------------------
#
# The passes above sweep rows the database knows about and ask the agent about
# each. Nothing in that direction can see the opposite failure: a credential
# the agent is still serving that the control plane has no live record of --
# left behind by a revoke whose apply failed, a restored backup, or any
# operation that landed on the agent after the row that authorized it was
# already terminal. That is the direction that actually matters for a VPN
# server, because such a credential still works while nothing is tracking it.
#
# This pass answers it by sending the agent the complete set of clients that
# should exist and letting it drop the rest in a single apply. "Complete" is
# load-bearing -- an incomplete set would revoke working clients -- so the
# guards below refuse to send one this service cannot vouch for in full.


@dataclass(slots=True)
class OrphanPruneSummary:
    servers: int = 0
    removed: int = 0
    kept: int = 0
    skipped: int = 0
    errored: int = 0

    @property
    def had_problems(self) -> bool:
        return self.skipped > 0 or self.errored > 0


async def run_xray_orphan_prune(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    keys: AuthKeyMaterial,
    *,
    clock: Clock = lambda: datetime.now(UTC),
) -> OrphanPruneSummary:
    """Remove credentials each active server holds that no live row accounts for."""

    summary = OrphanPruneSummary()
    async with session_factory() as session:
        servers = (
            await session.scalars(
                select(VPNServer).where(VPNServer.state.in_(RUNNING_SERVER_STATES))
            )
        ).all()

    for server in servers:
        summary.servers += 1
        try:
            await _prune_one_server(session_factory, agent_client_builder, server, keys, summary)
        except Exception:
            summary.errored += 1
            _LOGGER.exception("orphan prune failed unexpectedly for server %s", server.id)
    return summary


async def _prune_one_server(
    session_factory: SessionFactory,
    agent_client_builder: AgentClientBuilder,
    server: VPNServer,
    keys: AuthKeyMaterial,
    summary: OrphanPruneSummary,
) -> None:
    async with session_factory() as session:
        # Deliberately unpaginated, unlike the reconcile sweeps' batch_size
        # limit: this set defines what survives, so a page of it would tell the
        # agent to delete every client that happened to fall outside the page.
        rows = (
            await session.execute(
                select(XrayClient, ProtocolProfile.code, ProtocolProfile.agent_profile_code)
                .join(ProtocolProfile, XrayClient.protocol_profile_id == ProtocolProfile.id)
                .where(
                    XrayClient.vpn_server_id == server.id,
                    XrayClient.state.in_(_LIVE_STATES),
                )
            )
        ).all()

    expected: list[ExpectedXrayClient] = []
    for client, profile_code, agent_profile_code in rows:
        client_uuid = await _decrypt_client_uuid(session_factory, client, keys)
        if client_uuid is None:
            # One unreadable credential makes the whole set unverifiable: the
            # client it belongs to is almost certainly live on the agent, and
            # omitting it would ask the agent to revoke a working tunnel. Skip
            # this server entirely rather than prune from an incomplete list.
            summary.skipped += 1
            _LOGGER.warning(
                "skipping orphan prune for server %s: client %s could not be decrypted",
                server.id,
                client.id,
            )
            return
        expected.append(
            ExpectedXrayClient(
                client_uuid=client_uuid,
                protocol_profile_code=agent_profile_code or profile_code,
            )
        )

    try:
        async with agent_client_builder(server.agent_host, server.agent_port) as agent:
            response = await agent.prune_xray_clients(
                PruneXrayClientsRequest(correlation_id=uuid4(), expected=tuple(expected))
            )
    except (AgentUnreachable, AgentResponseAmbiguous, AgentResponseInvalid, AgentRejected) as error:
        summary.errored += 1
        _LOGGER.warning("orphan prune could not reach server %s: %s", server.id, error)
        return

    if response.state == "failed":
        summary.errored += 1
        _LOGGER.warning("orphan prune failed on server %s: %s", server.id, response.error_code)
        return

    summary.removed += response.removed
    summary.kept += response.kept
    if response.removed:
        _LOGGER.warning(
            "orphan prune removed %d untracked credential(s) from server %s",
            response.removed,
            server.id,
        )
        async with session_factory() as session:
            add_audit_event(
                session,
                actor_kind="system",
                actor_id=None,
                target_kind="vpn_server",
                target_id=server.id,
                event_code="peer_changed",
                outcome="succeeded",
                request_id=uuid4(),
                reason_code="orphan_pruned",
            )
            await session.commit()
