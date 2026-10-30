"""Narrow append-only authentication audit-event construction."""

from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.models.operations import AuditLog


def add_audit_event(
    session: AsyncSession,
    *,
    actor_kind: str,
    actor_id: UUID | None,
    target_kind: str,
    target_id: UUID,
    event_code: str,
    outcome: str,
    request_id: UUID,
    reason_code: str | None = None,
) -> None:
    """Append an allowlisted event without accepting payload snapshots."""

    session.add(
        AuditLog(
            id=uuid4(),
            actor_kind=actor_kind,
            actor_id=actor_id,
            target_kind=target_kind,
            target_id=target_id,
            event_code=event_code,
            outcome=outcome,
            request_id=request_id,
            reason_code=reason_code,
        )
    )
