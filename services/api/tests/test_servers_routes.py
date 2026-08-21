"""HTTP-layer tests for the user-facing server discovery route."""

from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.user_service import AuthenticatedUser, UserAuthService
from nebula_api.servers.routes import router
from nebula_api.servers.service import (
    AvailableProfileEntry,
    AvailableServerEntry,
    ServerDiscoveryService,
)
from nebula_api.settings import Settings

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")
AUTH_HEADERS = {"Authorization": "Bearer valid-token"}


class FakeUserAuthService:
    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


class FakeServerDiscoveryService:
    def __init__(self) -> None:
        self.entries: list[AvailableServerEntry] = []
        self.received_user_id: UUID | None = None

    async def list_available_servers(self, user_id: UUID) -> list[AvailableServerEntry]:
        self.received_user_id = user_id
        return self.entries


def make_client(
    discovery_service: FakeServerDiscoveryService | None = None,
    *,
    omit_service: bool = False,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, FakeUserAuthService())
    app.state.server_discovery_service = (
        None
        if omit_service
        else cast(ServerDiscoveryService, discovery_service or FakeServerDiscoveryService())
    )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_requires_a_bearer_token() -> None:
    with make_client() as client:
        response = client.get("/v1/servers/")

    assert response.status_code == 401


def test_returns_empty_list_when_nothing_is_assigned() -> None:
    with make_client() as client:
        response = client.get("/v1/servers/", headers=AUTH_HEADERS)

    assert response.status_code == 200
    assert response.json() == {"items": []}
    assert response.headers["cache-control"] == "no-store"


def test_returns_servers_and_profiles_and_scopes_by_caller() -> None:
    protocol_id = uuid4()
    service = FakeServerDiscoveryService()
    service.entries = [
        AvailableServerEntry(
            code="ams-1",
            display_name="Amsterdam 1",
            public_host="ams-1.example.test",
            profiles=[
                AvailableProfileEntry(
                    code="wireguard-default",
                    display_name="WireGuard default",
                    protocol_id=protocol_id,
                )
            ],
        )
    ]
    with make_client(discovery_service=service) as client:
        response = client.get("/v1/servers/", headers=AUTH_HEADERS)

    assert response.status_code == 200
    body = response.json()
    assert body["items"][0]["code"] == "ams-1"
    assert body["items"][0]["profiles"][0]["code"] == "wireguard-default"
    assert service.received_user_id == USER_ID


def test_service_unavailable_returns_503() -> None:
    with make_client(omit_service=True) as client:
        response = client.get("/v1/servers/", headers=AUTH_HEADERS)

    assert response.status_code == 503
