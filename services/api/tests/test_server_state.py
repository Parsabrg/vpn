"""Putting a VPN server into service, into maintenance, or out of it."""

import asyncio
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.db.engine import SessionFactory
from nebula_api.models.operations import AuditLog
from nebula_api.models.topology import VPNServer
from nebula_api.models.types import RUNNING_SERVER_STATES, AdminRole, ServerState
from nebula_api.settings import Settings
from nebula_api.topology_admin.routes import router
from nebula_api.topology_admin.service import TopologyAdminService, VpnServerEntry

ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
SERVER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ORIGIN = "http://localhost:3000"


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.OWNER, step_up: bool = True) -> None:
        self.role = role
        self.step_up = step_up

    async def principal(self, _session_token: str) -> AdminPrincipal:
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, self.step_up, "totp")

    async def validate_and_rotate_csrf(self, _session: str, _csrf: str) -> str:
        return "v1.csrf-replacement"


class FakeTopology:
    def __init__(self, *, known: bool = True) -> None:
        self.known = known
        self.calls: list[tuple[UUID, ServerState]] = []

    async def set_vpn_server_state(
        self, *, server_id: UUID, state: ServerState, **_kwargs: object
    ) -> VpnServerEntry | None:
        self.calls.append((server_id, state))
        if not self.known:
            return None
        return VpnServerEntry(
            id=server_id,
            code="de-1",
            display_name="Germany 1",
            state=state.value,
            public_host="de-1.example.test",
            maximum_devices=100,
        )


def _post(
    body: dict[str, object],
    *,
    topology: FakeTopology | None = None,
    admin: FakeAdminAuthService | None = None,
) -> tuple[int, Any, FakeTopology]:
    topology = topology or FakeTopology()
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin or FakeAdminAuthService())
    app.state.topology_admin_service = cast(TopologyAdminService, topology)
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")
        response = client.post(
            f"/v1/admin/vpn-servers/{SERVER_ID}/state",
            json=body,
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
        )
    return response.status_code, response.json(), topology


def test_puts_a_server_into_maintenance() -> None:
    status, body, topology = _post({"state": "maintenance"})

    assert status == 200
    assert body["state"] == "maintenance"
    assert topology.calls == [(SERVER_ID, ServerState.MAINTENANCE)]


def test_an_unknown_state_is_refused() -> None:
    status, _body, topology = _post({"state": "draining"})

    assert status == 422
    assert topology.calls == []


def test_an_unknown_server_is_not_found() -> None:
    status, _body, _topology = _post({"state": "active"}, topology=FakeTopology(known=False))

    assert status == 404


def test_requires_step_up() -> None:
    status, _body, topology = _post(
        {"state": "disabled"}, admin=FakeAdminAuthService(step_up=False)
    )

    assert status == 403
    assert topology.calls == []


def test_an_auditor_cannot_change_it() -> None:
    status, _body, _topology = _post(
        {"state": "disabled"}, admin=FakeAdminAuthService(role=AdminRole.AUDITOR)
    )

    assert status == 403


def test_maintenance_still_counts_and_repairs() -> None:
    # Tunnels on a server under maintenance keep running; their traffic and
    # revocations must not stop with the new connections.
    assert ServerState.MAINTENANCE.value in RUNNING_SERVER_STATES
    assert ServerState.DISABLED.value not in RUNNING_SERVER_STATES


class _Session:
    def __init__(self, server: VPNServer | None) -> None:
        self.server = server
        self.added: list[object] = []
        self.commits = 0

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> VPNServer | None:
        return self.server

    def add(self, item: object) -> None:
        self.added.append(item)

    async def commit(self) -> None:
        self.commits += 1


def _service(session: _Session) -> TopologyAdminService:
    return TopologyAdminService(cast(SessionFactory, lambda: session))


def test_the_service_changes_the_state_and_audits_it() -> None:
    server = VPNServer(
        id=SERVER_ID,
        code="de-1",
        display_name="Germany 1",
        state="active",
        agent_host="10.0.0.5",
        agent_port=9443,
        public_host="de-1.example.test",
        maximum_devices=100,
    )
    session = _Session(server)

    entry = asyncio.run(
        _service(session).set_vpn_server_state(
            server_id=SERVER_ID,
            state=ServerState.MAINTENANCE,
            admin_id=ADMIN_ID,
            request_id=uuid4(),
        )
    )

    assert entry is not None and entry.state == "maintenance"
    assert server.state == "maintenance"
    audit = next(item for item in session.added if isinstance(item, AuditLog))
    assert audit.event_code == "server_changed"
    assert audit.reason_code == "server_maintenance"
    assert session.commits == 1


def test_the_service_returns_none_for_an_unknown_server() -> None:
    session = _Session(None)

    entry = asyncio.run(
        _service(session).set_vpn_server_state(
            server_id=SERVER_ID, state=ServerState.ACTIVE, admin_id=ADMIN_ID, request_id=uuid4()
        )
    )

    assert entry is None
    assert session.commits == 0


# --- Renaming ---------------------------------------------------------------


class FakeRenameTopology:
    def __init__(self, *, known: bool = True) -> None:
        self.known = known
        self.calls: list[tuple[UUID, str]] = []

    async def set_vpn_server_name(
        self, *, server_id: UUID, display_name: str, **_kwargs: object
    ) -> VpnServerEntry | None:
        self.calls.append((server_id, display_name))
        if not self.known:
            return None
        return VpnServerEntry(
            id=server_id,
            code="tehran",
            display_name=display_name,
            state="active",
            public_host="tehran.example.test",
            maximum_devices=100,
        )


def _post_name(
    body: dict[str, object],
    *,
    topology: FakeRenameTopology | None = None,
    admin: FakeAdminAuthService | None = None,
) -> tuple[int, Any, FakeRenameTopology]:
    topology = topology or FakeRenameTopology()
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin or FakeAdminAuthService())
    app.state.topology_admin_service = cast(TopologyAdminService, topology)
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")
        response = client.post(
            f"/v1/admin/vpn-servers/{SERVER_ID}/name",
            json=body,
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
        )
    return response.status_code, response.json(), topology


def test_renames_a_server_without_step_up() -> None:
    status, body, topology = _post_name(
        {"display_name": "  Tehran  "}, admin=FakeAdminAuthService(step_up=False)
    )

    assert status == 200
    assert body["display_name"] == "Tehran"
    assert body["code"] == "tehran"
    assert topology.calls == [(SERVER_ID, "Tehran")]


def test_a_blank_name_is_refused() -> None:
    for name in ("", "   "):
        status, _body, topology = _post_name({"display_name": name})
        assert status == 422
        assert topology.calls == []


def test_renaming_an_unknown_server_is_not_found() -> None:
    status, _body, _topology = _post_name(
        {"display_name": "X"}, topology=FakeRenameTopology(known=False)
    )

    assert status == 404


def test_an_auditor_cannot_rename() -> None:
    status, _body, topology = _post_name(
        {"display_name": "X"}, admin=FakeAdminAuthService(role=AdminRole.AUDITOR)
    )

    assert status == 403
    assert topology.calls == []


def test_the_service_renames_and_audits() -> None:
    server = VPNServer(
        id=SERVER_ID,
        code="tehran",
        display_name="tehran",
        state="active",
        agent_host="10.0.0.6",
        agent_port=9443,
        public_host="tehran.example.test",
        maximum_devices=100,
    )
    session = _Session(server)

    entry = asyncio.run(
        _service(session).set_vpn_server_name(
            server_id=SERVER_ID, display_name="Tehran", admin_id=ADMIN_ID, request_id=uuid4()
        )
    )

    assert entry is not None and entry.display_name == "Tehran"
    assert server.display_name == "Tehran" and server.code == "tehran"
    audit = next(item for item in session.added if isinstance(item, AuditLog))
    assert audit.reason_code == "server_renamed"
    assert session.commits == 1
