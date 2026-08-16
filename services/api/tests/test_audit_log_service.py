import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from nebula_api.audit.service import AuditLogFilters, AuditLogService
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AuditLog

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


def audit_row(**overrides: object) -> AuditLog:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        actor_kind="admin",
        actor_id=uuid4(),
        target_kind="user",
        target_id=uuid4(),
        event_code="identity_state_changed",
        outcome="succeeded",
        reason_code="disabled",
        request_id=uuid4(),
        recorded_at=NOW,
    )
    defaults.update(overrides)
    return AuditLog(**defaults)


def test_list_events_returns_page_with_total() -> None:
    row = audit_row()
    session = ScriptedSession(scalar_values=[1], scalars_values=[[row]])
    service = AuditLogService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=AuditLogFilters(), limit=50, offset=0))

    assert page.total == 1
    assert page.items[0].id == row.id
    assert page.items[0].event_code == "identity_state_changed"


def test_list_events_bounds_limit_and_offset() -> None:
    session = ScriptedSession(scalar_values=[0], scalars_values=[[]])
    service = AuditLogService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=AuditLogFilters(), limit=10_000, offset=-5))

    assert page.total == 0
    assert page.items == []


def test_list_events_applies_filters_without_error() -> None:
    session = ScriptedSession(scalar_values=[0], scalars_values=[[]])
    service = AuditLogService(cast(SessionFactory, ScriptedFactory(session)))

    filters = AuditLogFilters(
        actor_kind="admin",
        target_kind="user",
        event_code="identity_state_changed",
        outcome="succeeded",
        actor_id=UUID(int=1),
        target_id=UUID(int=2),
        recorded_after=NOW,
        recorded_before=NOW,
    )

    page = asyncio.run(service.list_events(filters=filters, limit=50, offset=0))

    assert page.total == 0


def test_list_events_defaults_missing_total_to_zero() -> None:
    session = ScriptedSession(scalar_values=[None], scalars_values=[[]])
    service = AuditLogService(cast(SessionFactory, ScriptedFactory(session)))

    page = asyncio.run(service.list_events(filters=AuditLogFilters(), limit=50, offset=0))

    assert page.total == 0
