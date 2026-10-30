"""The lapsed-access sweep, without a database.

The PostgreSQL test proves which rows the query selects. These pin what is
done with them, and the query's shape where a mistake would be silent: the
lock must be on the credential alone, and the assignment and permission must
be existence checks, not joins.
"""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy.dialects import postgresql

from nebula_api.access.expiry import _lapsed, enforce_access_expiry
from nebula_api.db.engine import SessionFactory
from nebula_api.models.provisioning import WireGuardPeer, XrayClient
from nebula_api.models.types import ProvisioningState
from nebula_api.provisioning.revocation import credentials_awaiting_removal

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class _Result:
    def __init__(self, rows: list[tuple[object, UUID]]) -> None:
        self._rows = rows

    def tuples(self) -> list[tuple[object, UUID]]:
        return self._rows


class ScriptedSession:
    def __init__(self, per_model: list[list[tuple[object, UUID]]]) -> None:
        self._per_model = per_model
        self.credentials: dict[UUID, SimpleNamespace] = {}
        self.added: list[Any] = []
        self.commits = 0
        self.scalar_answers: list[object] = []

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, _statement: object) -> _Result:
        return _Result(self._per_model.pop(0))

    async def scalar(self, statement: object) -> object:
        if self.scalar_answers:
            return self.scalar_answers.pop(0)
        credential = SimpleNamespace(state=ProvisioningState.ACTIVE.value)
        self.credentials[uuid4()] = credential
        return credential

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1


def _factory(session: ScriptedSession) -> SessionFactory:
    return cast(SessionFactory, lambda: session)


def _row() -> SimpleNamespace:
    return SimpleNamespace(
        state=ProvisioningState.ACTIVE.value, updated_at=None, credential_id=uuid4()
    )


def test_each_lapsed_credential_goes_to_revoking_once_per_account_audited() -> None:
    first, second = uuid4(), uuid4()
    peer, client_a, client_b = _row(), _row(), _row()
    session = ScriptedSession([[(peer, first)], [(client_a, first), (client_b, second)]])

    summary = asyncio.run(enforce_access_expiry(_factory(session), clock=lambda: NOW))

    assert summary.credentials_revoked == 3
    assert set(summary.account_ids) == {first, second}
    for row in (peer, client_a, client_b):
        assert row.state == ProvisioningState.REVOKING.value
        assert row.updated_at == NOW
    assert all(c.state == ProvisioningState.REVOKING.value for c in session.credentials.values())
    # One audit event per account, not per credential.
    assert len(session.added) == 2
    assert {event.reason_code for event in session.added} == {"access_lapsed"}
    assert session.commits == 1


def test_nothing_lapsed_changes_nothing_and_audits_nothing() -> None:
    session = ScriptedSession([[], []])

    summary = asyncio.run(enforce_access_expiry(_factory(session), clock=lambda: NOW))

    assert summary.credentials_revoked == 0
    assert summary.account_ids == []
    assert session.added == []


def test_the_query_locks_only_the_credential_and_checks_access_by_existence() -> None:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = {
        "wireguard_peers": str(_lapsed(WireGuardPeer, NOW).compile(dialect=dialect)),
        "xray_clients": str(_lapsed(XrayClient, NOW).compile(dialect=dialect)),
    }
    for table, sql in compiled.items():
        # Locking the joined users or devices rows would serialize this with
        # every sign-in and connect for as long as the sweep runs.
        assert f"FOR UPDATE OF {table}" in sql
        # A join to assignments would match an old revoked row next to the
        # active one, and cut off somebody who still has access.
        assert "JOIN user_server_assignments" not in sql
        assert "JOIN user_protocol_permissions" not in sql
        assert sql.count("NOT (EXISTS") == 2


def test_waiting_removals_are_noticed_on_either_credential_table() -> None:
    session = ScriptedSession([])
    session.scalar_answers = [False, True]
    assert asyncio.run(credentials_awaiting_removal(_factory(session))) is True

    session.scalar_answers = [False, False]
    assert asyncio.run(credentials_awaiting_removal(_factory(session))) is False
