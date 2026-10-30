"""Deleting operational history once it is older than the policy allows.

`docs/threat-model.md` commits to a retention period -- 365 days for
administrator audit events, 90 days for the auth and email operational ones
-- and until this module existed nothing enforced it. Every table below grew
for as long as the deployment had been running, on a host whose disk is the
scarcest thing it has and is shared with the database itself.

Two properties shape how this is written.

**The audit table is append-only, and stays that way.** The application
role holds INSERT and SELECT on `audit_logs` and nothing else (migration
20260720_0003 revokes UPDATE and DELETE), which is what makes an audit row
evidence rather than a note. So this module does not ask for that to be
relaxed: run with the application credential it prunes everything else and
reports that it could not touch the audit table; run with the migration
credential -- the compose `prune` service, which is how the timer runs it --
it prunes that too. The refusal is caught and reported rather than raised,
so a misconfigured credential produces a line saying so instead of an
operational table that silently kept growing.

**Deletes are batched.** Sessions run under a five-second statement timeout
(`Settings.database_statement_timeout_ms`), and a first prune on a table
that has never been pruned can be far more rows than that allows. Each pass
deletes a bounded slice and commits, so the work is interruptible and never
holds a long lock on a table the API is still writing to.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Select, delete, exists, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import ProgrammingError

from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import (
    AgentOperation,
    AuditLog,
    EmailDelivery,
    ReconciliationRecord,
    ServerHealth,
)

_LOGGER = logging.getLogger(__name__)

# Rows per statement. Small enough to finish inside the statement timeout on
# a table that has never been pruned, large enough that a routine run is a
# handful of statements.
_BATCH = 2_000

# A ceiling on passes per table, so a bug that deletes nothing cannot spin
# forever against the database. At the batch size above this is four million
# rows in one run, which is far more than a weekly prune will ever find.
_MAXIMUM_BATCHES = 2_000

# Deliveries still in flight are not history, whatever their age: a pending
# row is work the worker has not done yet.
_TERMINAL_EMAIL_STATES = ("sent", "failed", "cancelled")
_TERMINAL_OPERATION_STATES = ("succeeded", "failed", "cancelled")


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """How long each kind of history is kept, in days.

    The defaults are the ones docs/threat-model.md states.
    """

    audit_days: int = 365
    operational_days: int = 90

    def __post_init__(self) -> None:
        if self.audit_days < 1 or self.operational_days < 1:
            raise ValueError("retention periods must be at least one day")


@dataclass(frozen=True, slots=True)
class PruneSummary:
    """What one run deleted, and what it was not allowed to."""

    deleted: Mapping[str, int]
    refused: Mapping[str, str]

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted.values())


async def prune_history(
    session_factory: SessionFactory,
    policy: RetentionPolicy | None = None,
    *,
    now: datetime | None = None,
) -> PruneSummary:
    """Delete history past the policy, oldest tables first.

    Ordering is not cosmetic: `reconciliation_records.agent_operation_id`
    references `agent_operations` with ON DELETE RESTRICT, so the records
    have to go first -- and even then an old operation can still be
    referenced by a reconciliation record newer than the cutoff, which is
    why the operations pass excludes anything still referenced rather than
    assuming one cutoff covers both.
    """

    effective = policy or RetentionPolicy()
    moment = now or datetime.now(UTC)
    operational_cutoff = moment - timedelta(days=effective.operational_days)
    audit_cutoff = moment - timedelta(days=effective.audit_days)

    deleted: dict[str, int] = {}
    refused: dict[str, str] = {}

    passes: Sequence[tuple[str, Select[UUID]]] = (
        (
            ReconciliationRecord.__tablename__,
            select(ReconciliationRecord.id).where(
                ReconciliationRecord.checked_at < operational_cutoff
            ),
        ),
        (
            ServerHealth.__tablename__,
            select(ServerHealth.id).where(ServerHealth.observed_at < operational_cutoff),
        ),
        (
            EmailDelivery.__tablename__,
            select(EmailDelivery.id).where(
                EmailDelivery.state.in_(_TERMINAL_EMAIL_STATES),
                # A delivery may have waited in the queue for a long time.
                # Its successful delivery is still recent history in that
                # case. Failed/cancelled rows have no completion timestamp.
                func.coalesce(EmailDelivery.sent_at, EmailDelivery.available_at)
                < operational_cutoff,
            ),
        ),
        (
            AgentOperation.__tablename__,
            select(AgentOperation.id).where(
                # Pending/running operations remain live work regardless of
                # age. Retain completed operations for the full policy after
                # completion, not merely after the request was queued.
                AgentOperation.state.in_(_TERMINAL_OPERATION_STATES),
                AgentOperation.finished_at < operational_cutoff,
                ~exists().where(ReconciliationRecord.agent_operation_id == AgentOperation.id),
            ),
        ),
        (
            AuditLog.__tablename__,
            select(AuditLog.id).where(AuditLog.recorded_at < audit_cutoff),
        ),
    )

    for table, doomed in passes:
        try:
            deleted[table] = await _delete_in_batches(session_factory, table, doomed)
        except ProgrammingError as error:
            # The application credential cannot delete audit rows, by design.
            # Reported rather than raised so the tables it *can* prune are
            # still pruned, and so the operator sees which credential to use.
            refused[table] = _refusal(error)

    summary = PruneSummary(deleted=deleted, refused=refused)
    _LOGGER.info(
        "pruned %d rows of history (%s)",
        summary.total_deleted,
        ", ".join(f"{table}={count}" for table, count in deleted.items()) or "nothing",
    )
    return summary


async def _delete_in_batches(
    session_factory: SessionFactory,
    table: str,
    doomed: Select[UUID],
) -> int:
    total = 0
    for _ in range(_MAXIMUM_BATCHES):
        async with session_factory() as session:
            # Hold the selected rows until the delete commits: a concurrent
            # update must not turn a selected historical row back into live
            # work between these two statements. Skip busy rows so a prune
            # never waits on a worker's transaction.
            identifiers = (
                await session.scalars(doomed.limit(_BATCH).with_for_update(skip_locked=True))
            ).all()
            if not identifiers:
                return total
            model = _MODELS[table]
            result = cast(
                CursorResult[Any],
                await session.execute(delete(model).where(model.id.in_(identifiers))),
            )
            await session.commit()
            removed = result.rowcount or 0
            total += removed
            if removed < _BATCH:
                return total
    _LOGGER.warning("stopped pruning %s after %d batches", table, _MAXIMUM_BATCHES)
    return total


_MODELS = {
    model.__tablename__: model
    for model in (AgentOperation, AuditLog, EmailDelivery, ReconciliationRecord, ServerHealth)
}


def _refusal(error: ProgrammingError) -> str:
    """The database's own reason, without the statement that provoked it.

    The statement would carry the full parameter list into a log line, and
    these run under an operator's eyes rather than in a structured sink.
    """

    original = getattr(error, "orig", None)
    return str(original).strip().splitlines()[0] if original else "the database refused the delete"
