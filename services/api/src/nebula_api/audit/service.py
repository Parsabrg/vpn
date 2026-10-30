"""Read-only, filterable audit log listing for administrators."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select

from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AuditLog

_MAX_LIMIT = 200


@dataclass(frozen=True, slots=True)
class AuditLogFilters:
    actor_kind: str | None = None
    target_kind: str | None = None
    event_code: str | None = None
    outcome: str | None = None
    actor_id: UUID | None = None
    target_id: UUID | None = None
    recorded_after: datetime | None = None
    recorded_before: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    id: UUID
    actor_kind: str
    actor_id: UUID | None
    target_kind: str
    target_id: UUID
    event_code: str
    outcome: str
    reason_code: str | None
    request_id: UUID | None
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class AuditLogPage:
    items: list[AuditLogEntry]
    total: int


class AuditLogService:
    """Own read-only access to the append-only `audit_logs` table."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def list_events(
        self, *, filters: AuditLogFilters, limit: int, offset: int
    ) -> AuditLogPage:
        bounded_limit = max(1, min(limit, _MAX_LIMIT))
        bounded_offset = max(0, offset)
        conditions = _conditions(filters)
        async with self._session_factory() as session:
            statement = select(AuditLog).where(*conditions)
            count_statement = select(func.count()).select_from(AuditLog).where(*conditions)
            statement = (
                statement.order_by(AuditLog.recorded_at.desc())
                .limit(bounded_limit)
                .offset(bounded_offset)
            )
            rows = (await session.scalars(statement)).all()
            total = await session.scalar(count_statement)
        return AuditLogPage(items=[_to_entry(row) for row in rows], total=total or 0)


def _conditions(filters: AuditLogFilters) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if filters.actor_kind is not None:
        conditions.append(AuditLog.actor_kind == filters.actor_kind)
    if filters.target_kind is not None:
        conditions.append(AuditLog.target_kind == filters.target_kind)
    if filters.event_code is not None:
        conditions.append(AuditLog.event_code == filters.event_code)
    if filters.outcome is not None:
        conditions.append(AuditLog.outcome == filters.outcome)
    if filters.actor_id is not None:
        conditions.append(AuditLog.actor_id == filters.actor_id)
    if filters.target_id is not None:
        conditions.append(AuditLog.target_id == filters.target_id)
    if filters.recorded_after is not None:
        conditions.append(AuditLog.recorded_at >= filters.recorded_after)
    if filters.recorded_before is not None:
        conditions.append(AuditLog.recorded_at <= filters.recorded_before)
    return conditions


def _to_entry(row: AuditLog) -> AuditLogEntry:
    return AuditLogEntry(
        id=row.id,
        actor_kind=row.actor_kind,
        actor_id=row.actor_id,
        target_kind=row.target_kind,
        target_id=row.target_id,
        event_code=row.event_code,
        outcome=row.outcome,
        reason_code=row.reason_code,
        request_id=row.request_id,
        recorded_at=row.recorded_at,
    )
