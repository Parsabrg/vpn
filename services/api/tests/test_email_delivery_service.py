import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from nebula_api.db.engine import SessionFactory
from nebula_api.email_deliveries.service import EmailDeliveryFilters, EmailDeliveryService
from nebula_api.models.operations import EmailDelivery

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class ScalarRows:
    def __init__(self, values: Iterable[object]) -> None:
        self._values = list(values)

    def all(self) -> list[object]:
        return self._values


class ScriptedSession:
    def __init__(
        self,
        *,
        scalar_values: Iterable[object] = (),
        scalars_values: Iterable[Iterable[object]] = (),
    ) -> None:
        self.scalar_values = list(scalar_values)
        self.scalars_values = [list(values) for values in scalars_values]

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        return self.scalar_values.pop(0)

    async def scalars(self, _statement: object) -> ScalarRows:
        return ScalarRows(self.scalars_values.pop(0))


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        return self.sessions.pop(0)


def delivery_row(**overrides: object) -> EmailDelivery:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        deduplication_key=uuid4(),
        template_code="user_activation",
        recipient_address="user@example.com",
        subject_kind="user",
        subject_id=uuid4(),
        state="sent",
        attempt_count=1,
        available_at=NOW,
        sent_at=NOW,
        provider_message_id="canary-id",
        result_code="delivered",
    )
    defaults.update(overrides)
    return EmailDelivery(**defaults)


def test_list_events_returns_page_with_total() -> None:
    row = delivery_row()
    session = ScriptedSession(scalar_values=[1], scalars_values=[[row]])
    service = EmailDeliveryService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=EmailDeliveryFilters(), limit=50, offset=0))

    assert page.total == 1
    assert page.items[0].id == row.id
    assert page.items[0].state == "sent"


def test_list_events_bounds_limit_and_offset() -> None:
    session = ScriptedSession(scalar_values=[0], scalars_values=[[]])
    service = EmailDeliveryService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=EmailDeliveryFilters(), limit=10_000, offset=-5))

    assert page.total == 0
    assert page.items == []


def test_list_events_applies_filters_without_error() -> None:
    session = ScriptedSession(scalar_values=[0], scalars_values=[[]])
    service = EmailDeliveryService(cast(SessionFactory, ScriptedFactory(session)))

    filters = EmailDeliveryFilters(
        state="failed",
        template_code="user_activation",
        subject_kind="user",
        recipient_address="user@example.com",
    )

    page = asyncio.run(service.list_events(filters=filters, limit=50, offset=0))

    assert page.total == 0


def test_list_events_defaults_missing_total_to_zero() -> None:
    session = ScriptedSession(scalar_values=[None], scalars_values=[[]])
    service = EmailDeliveryService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=EmailDeliveryFilters(), limit=50, offset=0))

    assert page.total == 0
