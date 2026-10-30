"""Running reconciliation from the admin panel: all of it, or one credential."""

import asyncio
import os
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.db.engine import SessionFactory, create_database_engine, create_session_factory
from nebula_api.models.operations import AuditLog
from nebula_api.models.types import AdminRole
from nebula_api.provisioning import reconciliation
from nebula_api.provisioning.reconciliation import (
    ReconciliationBusy,
    ReconciliationSummary,
    reconcile_now,
    reconciliation_lock,
)
from nebula_api.settings import Settings
from nebula_api.topology_admin.routes import router
from nebula_api.topology_admin.service import TopologyAdminService

ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
TARGET_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ORIGIN = "http://localhost:3000"


def _summary(**counts: int) -> ReconciliationSummary:
    return ReconciliationSummary(**counts)


# --- route -----------------------------------------------------------------


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.OPERATOR) -> None:
        self.role = role

    async def principal(self, _session_token: str) -> AdminPrincipal:
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, False, "totp")

    async def validate_and_rotate_csrf(self, _session: str, _csrf: str) -> str:
        return "v1.csrf-replacement"


class FakeTopology:
    def __init__(self, result: object = None, *, busy: bool = False) -> None:
        self.result = result
        self.busy = busy
        self.calls: list[UUID | None] = []

    async def reconcile_now(self, *, target_id: UUID | None, **_kwargs: object) -> object:
        self.calls.append(target_id)
        if self.busy:
            raise ReconciliationBusy
        return self.result


def _post(
    body: dict[str, object], topology: FakeTopology, *, role: AdminRole = AdminRole.OPERATOR
) -> tuple[int, Any]:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService(role=role))
    app.state.topology_admin_service = cast(TopologyAdminService, topology)
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")
        response = client.post(
            "/v1/admin/reconciliation/run",
            json=body,
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
        )
    return response.status_code, response.json()


def test_runs_everything_and_reports_both_passes() -> None:
    topology = FakeTopology((_summary(checked=2, in_sync=2), _summary(checked=12, repaired=1)))

    status, body = _post({}, topology)

    assert status == 200
    assert topology.calls == [None]
    assert body["wireguard"]["in_sync"] == 2
    assert body["xray"] == {
        "checked": 12,
        "in_sync": 0,
        "repaired": 1,
        "repair_failed": 0,
        "ambiguous": 0,
        "errored": 0,
    }


def test_checks_one_target() -> None:
    topology = FakeTopology((_summary(), _summary(checked=1, in_sync=1)))

    status, _body = _post({"target_id": str(TARGET_ID)}, topology)

    assert status == 200
    assert topology.calls == [TARGET_ID]


def test_a_target_that_is_not_live_is_not_found() -> None:
    status, _body = _post({"target_id": str(TARGET_ID)}, FakeTopology((_summary(), _summary())))

    assert status == 404


def test_a_pass_already_running_is_a_conflict() -> None:
    status, _body = _post({}, FakeTopology(busy=True))

    assert status == 409


def test_without_agent_wiring_it_is_unavailable() -> None:
    status, _body = _post({}, FakeTopology(None))

    assert status == 503


def test_an_auditor_cannot_run_it() -> None:
    topology = FakeTopology((_summary(), _summary()))

    status, _body = _post({}, topology, role=AdminRole.AUDITOR)

    assert status == 403
    assert topology.calls == []


# --- service ---------------------------------------------------------------


class _Session:
    def __init__(self, store: list[object]) -> None:
        self.store = store

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def add(self, row: object) -> None:
        self.store.append(row)

    async def commit(self) -> None:
        return None


def _service(
    result: tuple[ReconciliationSummary, ReconciliationSummary],
) -> tuple[TopologyAdminService, list[object]]:
    added: list[object] = []

    async def reconciler(
        _target: UUID | None,
    ) -> tuple[ReconciliationSummary, ReconciliationSummary]:
        return result

    factory = cast(SessionFactory, lambda: _Session(added))
    return TopologyAdminService(factory, reconciler=reconciler), added


def _audit(added: list[object]) -> AuditLog:
    [row] = added
    assert isinstance(row, AuditLog)
    return row


def test_a_full_run_is_audited_against_the_request() -> None:
    service, added = _service((_summary(checked=1, in_sync=1), _summary()))
    request_id = uuid4()

    asyncio.run(service.reconcile_now(target_id=None, admin_id=ADMIN_ID, request_id=request_id))

    row = _audit(added)
    assert (row.target_kind, row.target_id, row.reason_code, row.outcome) == (
        "agent_operation",
        request_id,
        "reconciliation_run",
        "succeeded",
    )
    assert row.actor_id == ADMIN_ID


def test_a_checked_xray_client_with_problems_is_audited_as_failed() -> None:
    service, added = _service((_summary(), _summary(checked=1, ambiguous=1)))

    asyncio.run(service.reconcile_now(target_id=TARGET_ID, admin_id=ADMIN_ID, request_id=uuid4()))

    row = _audit(added)
    assert (row.target_kind, row.target_id, row.reason_code, row.outcome) == (
        "xray_client",
        TARGET_ID,
        "reconciliation_target",
        "failed",
    )


def test_a_checked_wireguard_peer_is_audited_as_one() -> None:
    service, added = _service((_summary(checked=1, in_sync=1), _summary()))

    asyncio.run(service.reconcile_now(target_id=TARGET_ID, admin_id=ADMIN_ID, request_id=uuid4()))

    assert _audit(added).target_kind == "wireguard_peer"


def test_a_target_nothing_matched_writes_no_audit() -> None:
    service, added = _service((_summary(), _summary()))

    asyncio.run(service.reconcile_now(target_id=TARGET_ID, admin_id=ADMIN_ID, request_id=uuid4()))

    assert added == []


def test_no_reconciler_means_none() -> None:
    service = TopologyAdminService(cast(SessionFactory, lambda: None))

    result = asyncio.run(
        service.reconcile_now(target_id=None, admin_id=ADMIN_ID, request_id=uuid4())
    )

    assert result is None


# --- lock and passes ------------------------------------------------------


class _LockSession:
    def __init__(self, acquired: bool) -> None:
        self.acquired = acquired
        self.statements: list[str] = []

    async def __aenter__(self) -> "_LockSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def begin(self) -> "_LockSession":
        return self

    async def scalar(self, statement: object, _params: object = None) -> bool:
        self.statements.append(str(statement))
        return self.acquired


def test_the_lock_is_a_postgres_advisory_lock() -> None:
    session = _LockSession(True)

    async def take() -> bool:
        async with reconciliation_lock(cast(SessionFactory, lambda: session)) as acquired:
            return acquired

    assert asyncio.run(take()) is True
    assert "pg_try_advisory_xact_lock" in session.statements[0]


def test_a_held_lock_makes_reconcile_now_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[str] = []

    async def never(*_args: object, **_kwargs: object) -> ReconciliationSummary:
        ran.append("pass")
        return _summary()

    monkeypatch.setattr(reconciliation, "run_reconciliation", never)
    monkeypatch.setattr(reconciliation, "run_xray_reconciliation", never)

    with pytest.raises(ReconciliationBusy):
        asyncio.run(
            reconcile_now(
                cast(SessionFactory, lambda: _LockSession(False)),
                cast(Any, None),
                Settings(env="test"),
                cast(Any, None),
            )
        )
    assert ran == []


def test_reconcile_now_runs_both_passes_for_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    targets: list[tuple[str, object]] = []

    async def wireguard(*_args: object, target_id: UUID | None = None) -> ReconciliationSummary:
        targets.append(("wireguard", target_id))
        return _summary(checked=1)

    async def xray(*_args: object, target_id: UUID | None = None) -> ReconciliationSummary:
        targets.append(("xray", target_id))
        return _summary()

    monkeypatch.setattr(reconciliation, "run_reconciliation", wireguard)
    monkeypatch.setattr(reconciliation, "run_xray_reconciliation", xray)

    result = asyncio.run(
        reconcile_now(
            cast(SessionFactory, lambda: _LockSession(True)),
            cast(Any, None),
            Settings(env="test"),
            cast(Any, None),
            target_id=TARGET_ID,
        )
    )

    assert targets == [("wireguard", TARGET_ID), ("xray", TARGET_ID)]
    assert result[0].checked == 1


@pytest.mark.skipif(
    not os.environ.get("NEBULA_DATABASE_URL"), reason="PostgreSQL is not configured"
)
def test_the_lock_keeps_a_second_pass_out_until_the_first_ends() -> None:
    engine = create_database_engine(os.environ["NEBULA_DATABASE_URL"])
    factory = create_session_factory(engine)

    async def scenario() -> tuple[bool, bool, bool]:
        try:
            async with reconciliation_lock(factory) as first:
                async with reconciliation_lock(factory) as second:
                    pass
            async with reconciliation_lock(factory) as after:
                pass
            return first, second, after
        finally:
            await engine.dispose()

    assert asyncio.run(scenario()) == (True, False, True)
