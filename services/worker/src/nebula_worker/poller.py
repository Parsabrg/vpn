"""Claim, deliver, and finalize queued rows from the `email_deliveries` outbox.

Uses raw SQL rather than the API's ORM models: this service does not import
`nebula_api` (see the package docstring in `outbox.py`), so it only needs to
agree with the API on table/column names, not on shared Python types.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_worker.adapters.base import EmailAdapter, EmailSendError
from nebula_worker.outbox import OutboxRedisClient, read_email_payload
from nebula_worker.settings import Settings
from nebula_worker.templates import UnknownTemplate, render

Clock = Callable[[], datetime]

_LOGGER = logging.getLogger(__name__)
_UNRETRYABLE_RESULT_CODES = frozenset({"payload_unavailable", "unknown_template"})

_CLAIM_SQL = text(
    """
    UPDATE email_deliveries
    SET state = 'sending', leased_until = :leased_until
    WHERE id IN (
        SELECT id FROM email_deliveries
        WHERE state = 'pending' AND available_at <= :now
        ORDER BY available_at
        LIMIT :batch_size
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id, template_code, recipient_address, attempt_count
    """
)

_RECLAIM_EXPIRED_LEASES_SQL = text(
    """
    UPDATE email_deliveries
    SET state = CASE
            WHEN attempt_count + 1 >= :max_attempts THEN 'failed'
            ELSE 'pending'
        END,
        attempt_count = attempt_count + 1,
        result_code = 'lease_expired',
        available_at = :now,
        leased_until = NULL
    WHERE state = 'sending' AND leased_until IS NOT NULL AND leased_until < :now
    RETURNING id, state
    """
)

_MARK_SENT_SQL = text(
    """
    UPDATE email_deliveries
    SET state = 'sent', sent_at = :now, provider_message_id = :provider_message_id,
        attempt_count = attempt_count + 1, result_code = 'delivered'
    WHERE id = :id
    """
)

_RESCHEDULE_SQL = text(
    """
    UPDATE email_deliveries
    SET state = 'pending', available_at = :available_at,
        attempt_count = attempt_count + 1, result_code = :result_code
    WHERE id = :id
    """
)

_MARK_FAILED_SQL = text(
    """
    UPDATE email_deliveries
    SET state = 'failed', attempt_count = attempt_count + 1, result_code = :result_code
    WHERE id = :id
    """
)

_AUDIT_SQL = text(
    """
    INSERT INTO audit_logs
        (id, actor_kind, target_kind, target_id, event_code, outcome, reason_code)
    VALUES
        (:id, 'worker', 'email_delivery', :delivery_id, 'email_delivery_changed',
         :outcome, :reason_code)
    """
)


@dataclass(frozen=True, slots=True)
class ClaimedDelivery:
    id: UUID
    template_code: str
    recipient_address: str
    attempt_count: int


async def reclaim_expired_leases(engine: AsyncEngine, *, max_attempts: int, now: datetime) -> int:
    """Return rows whose lease expired to the queue, or fail them once they
    are out of attempts.

    Without this, a worker that dies between claiming a batch and finalizing
    it (deploy, OOM, container restart) leaves those rows in 'sending'
    forever: never delivered, never retried, and invisible because nothing
    else reads `leased_until`. Reclaiming can re-send an email whose original
    attempt was merely slow rather than dead, which is the standard
    at-least-once tradeoff -- for an activation link a duplicate is strictly
    better than a message that never arrives. `attempt_count` is incremented
    on reclaim so a delivery that reliably kills the worker still exhausts
    its attempts instead of looping forever.
    """

    async with engine.begin() as connection:
        result = await connection.execute(
            _RECLAIM_EXPIRED_LEASES_SQL, {"max_attempts": max_attempts, "now": now}
        )
        rows = result.mappings().all()
        for row in rows:
            await connection.execute(
                _AUDIT_SQL,
                {
                    "id": uuid4(),
                    "delivery_id": row["id"],
                    "outcome": "failed" if row["state"] == "failed" else "denied",
                    "reason_code": "lease_expired",
                },
            )
    if rows:
        _LOGGER.warning("Reclaimed %d email delivery lease(s) after expiry", len(rows))
    return len(rows)


async def claim_batch(
    engine: AsyncEngine, *, batch_size: int, lease_seconds: int, now: datetime
) -> list[ClaimedDelivery]:
    async with engine.begin() as connection:
        result = await connection.execute(
            _CLAIM_SQL,
            {
                "leased_until": now + timedelta(seconds=lease_seconds),
                "now": now,
                "batch_size": batch_size,
            },
        )
        rows = result.mappings().all()
    return [
        ClaimedDelivery(
            id=row["id"],
            template_code=row["template_code"],
            recipient_address=row["recipient_address"],
            attempt_count=row["attempt_count"],
        )
        for row in rows
    ]


async def deliver_one(
    engine: AsyncEngine,
    redis_client: OutboxRedisClient,
    adapter: EmailAdapter,
    delivery: ClaimedDelivery,
    *,
    settings: Settings,
    now: datetime,
) -> None:
    payload = await read_email_payload(redis_client, delivery.id)
    if payload is None:
        await _finalize(
            engine,
            delivery,
            outcome="failed",
            result_code="payload_unavailable",
            now=now,
            settings=settings,
        )
        return
    try:
        rendered = render(delivery.template_code, payload)
    except UnknownTemplate:
        await _finalize(
            engine,
            delivery,
            outcome="failed",
            result_code="unknown_template",
            now=now,
            settings=settings,
        )
        return
    try:
        provider_message_id = await adapter.send(
            to=delivery.recipient_address, subject=rendered.subject, body=rendered.body
        )
    except EmailSendError:
        _LOGGER.warning("Email delivery attempt failed", extra={"delivery_id": str(delivery.id)})
        await _finalize(
            engine,
            delivery,
            outcome="denied",
            result_code="send_failed",
            now=now,
            settings=settings,
        )
        return
    async with engine.begin() as connection:
        await connection.execute(
            _MARK_SENT_SQL,
            {"id": delivery.id, "now": now, "provider_message_id": provider_message_id},
        )
        await connection.execute(
            _AUDIT_SQL,
            {
                "id": uuid4(),
                "delivery_id": delivery.id,
                "outcome": "succeeded",
                "reason_code": "sent",
            },
        )


async def _finalize(
    engine: AsyncEngine,
    delivery: ClaimedDelivery,
    *,
    outcome: str,
    result_code: str,
    now: datetime,
    settings: Settings,
) -> None:
    exhausted = delivery.attempt_count + 1 >= settings.max_attempts
    async with engine.begin() as connection:
        if exhausted or result_code in _UNRETRYABLE_RESULT_CODES:
            await connection.execute(
                _MARK_FAILED_SQL, {"id": delivery.id, "result_code": result_code}
            )
        else:
            backoff_seconds = min(3_600, 30 * (2**delivery.attempt_count))
            await connection.execute(
                _RESCHEDULE_SQL,
                {
                    "id": delivery.id,
                    "available_at": now + timedelta(seconds=backoff_seconds),
                    "result_code": result_code,
                },
            )
        await connection.execute(
            _AUDIT_SQL,
            {
                "id": uuid4(),
                "delivery_id": delivery.id,
                "outcome": outcome,
                "reason_code": result_code,
            },
        )


async def poll_once(
    engine: AsyncEngine,
    redis_client: OutboxRedisClient,
    adapter: EmailAdapter,
    settings: Settings,
    *,
    clock: Clock = lambda: datetime.now(UTC),
) -> int:
    """Claim and deliver one batch; return how many deliveries were processed."""

    now = clock()
    await reclaim_expired_leases(engine, max_attempts=settings.max_attempts, now=now)
    claimed = await claim_batch(
        engine, batch_size=settings.batch_size, lease_seconds=settings.lease_seconds, now=now
    )
    for delivery in claimed:
        try:
            await deliver_one(engine, redis_client, adapter, delivery, settings=settings, now=now)
        except Exception:
            # One delivery must not strand the rest of the claimed batch. Any
            # row left behind here keeps its lease and is picked back up by
            # reclaim_expired_leases once that lease expires, rather than
            # sitting in 'sending' indefinitely.
            _LOGGER.exception(
                "Email delivery raised unexpectedly", extra={"delivery_id": str(delivery.id)}
            )
    return len(claimed)
