from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings
from nebula_api.topology_admin.routes import router
from nebula_api.topology_admin.service import (
    ProtocolEntry,
    ProtocolProfileEntry,
    TopologyAdminService,
    VpnServerEntry,
)

ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.AUDITOR) -> None:
        self.role = role

    async def principal(self, _session_token: str) -> AdminPrincipal:
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, False, "totp")


class FakeTopologyAdminService:
    def __init__(self) -> None:
        self.protocols: list[ProtocolEntry] = []
        self.profiles: list[ProtocolProfileEntry] = []
        self.servers: list[VpnServerEntry] = []

    async def list_protocols(self) -> list[ProtocolEntry]:
        return self.protocols

    async def list_protocol_profiles(self) -> list[ProtocolProfileEntry]:
        return self.profiles

    async def list_vpn_servers(self) -> list[VpnServerEntry]:
        return self.servers


def make_client(topology_service: FakeTopologyAdminService | None = None) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.topology_admin_service = cast(
        TopologyAdminService, topology_service or FakeTopologyAdminService()
    )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def _authenticated(client: TestClient) -> None:
    client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")


def test_protocols_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/protocols")

    assert response.status_code == 401


def test_protocols_returns_empty_list_today() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/protocols")

    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_protocol_profiles_returns_mapped_items() -> None:
    service = FakeTopologyAdminService()
    service.profiles = [
        ProtocolProfileEntry(
            id=uuid4(),
            protocol_id=uuid4(),
            code="wireguard-default",
            version=1,
            display_name="WireGuard default",
            state="draft",
            transport=None,
            transport_security=None,
            requires_udp=True,
            is_full_tunnel=True,
        )
    ]
    with make_client(topology_service=service) as client:
        _authenticated(client)
        response = client.get("/v1/admin/protocol-profiles")

    assert response.status_code == 200
    assert response.json()["items"][0]["code"] == "wireguard-default"
    assert response.headers["cache-control"] == "no-store"


def test_vpn_servers_returns_empty_list_today() -> None:
    with make_client() as client:
        _authenticated(client)
        response = client.get("/v1/admin/vpn-servers")

    assert response.status_code == 200
    assert response.json() == {"items": []}


def test_vpn_servers_service_unavailable() -> None:
    app = FastAPI()
    settings = Settings(env="test")
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.topology_admin_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/vpn-servers")

    assert response.status_code == 503
