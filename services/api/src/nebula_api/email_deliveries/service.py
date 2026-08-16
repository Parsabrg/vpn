"""Read-only, filterable email delivery status listing for administrators."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select

from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import EmailDelivery

_MAX_LIMIT = 200


@dataclass(frozen=True, slots=True)
class EmailDeliveryFilters:
    state: str | None = None
    template_code: str | None = None
    subject_kind: str | None = None
    recipient_address: str | None = None


@dataclass(frozen=True, slots=True)
class EmailDeliveryEntry:
    id: UUID
    template_code: str
    recipient_address: str
    subject_kind: str
    subject_id: UUID
    state: str
    attempt_count: int
    available_at: datetime
    sent_at: datetime | None
    provider_message_id: str | None
    result_code: str | None


@dataclass(frozen=True, slots=True)
class EmailDeliveryPage:
    items: list[EmailDeliveryEntry]
    total: int


class EmailDeliveryService:
    """Own read-only access to the `email_deliveries` outbox table."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def list_events(
        self, *, filters: EmailDeliveryFilters, limit: int, offset: int
    ) -> EmailDeliveryPage:
        bounded_limit = max(1, min(limit, _MAX_LIMIT))
        bounded_offset = max(0, offset)
        conditions = _conditions(filters)
        async with self._session_factory() as session:
            statement = select(EmailDelivery).where(*conditions)
            count_statement = select(func.count()).select_from(EmailDelivery).where(*conditions)
            statement = (
                statement.order_by(EmailDelivery.available_at.desc())
                .limit(bounded_limit)
                .offset(bounded_offset)
            )
            rows = (await session.scalars(statement)).all()
            total = await session.scalar(count_statement)
        return EmailDeliveryPage(items=[_to_entry(row) for row in rows], total=total or 0)


def _conditions(filters: EmailDeliveryFilters) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if filters.state is not None:
        conditions.append(EmailDelivery.state == filters.state)
    if filters.template_code is not None:
        conditions.append(EmailDelivery.template_code == filters.template_code)
    if filters.subject_kind is not None:
        conditions.append(EmailDelivery.subject_kind == filters.subject_kind)
    if filters.recipient_address is not None:
        conditions.append(EmailDelivery.recipient_address == filters.recipient_address)
    return conditions


def _to_entry(row: EmailDelivery) -> EmailDeliveryEntry:
    return EmailDeliveryEntry(
        id=row.id,
        template_code=row.template_code,
        recipient_address=row.recipient_address,
        subject_kind=row.subject_kind,
        subject_id=row.subject_id,
        state=row.state,
        attempt_count=row.attempt_count,
        available_at=row.available_at,
        sent_at=row.sent_at,
        provider_message_id=row.provider_message_id,
        result_code=row.result_code,
    )
