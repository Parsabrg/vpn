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

    async def list_available_servers(
        self, user_id: UUID, *, include_maintenance: bool = False
    ) -> list[AvailableServerEntry]:
        self.received_user_id = user_id
        self.include_maintenance = include_maintenance
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
                    protocol_code="wireguard",
                    ad_block=False,
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
    assert body["items"][0]["profiles"][0]["protocol_code"] == "wireguard"
    assert service.received_user_id == USER_ID


def test_service_unavailable_returns_503() -> None:
    with make_client(omit_service=True) as client:
        response = client.get("/v1/servers/", headers=AUTH_HEADERS)

    assert response.status_code == 503


def test_a_profile_carries_where_it_is_reached() -> None:
    # A client cannot measure a server it has not connected to unless it
    # knows the port. Learning it by provisioning would register a device
    # and start counting traffic, so the choice could not be offered before
    # the cost of making it had already been paid.
    service = FakeServerDiscoveryService()
    service.entries = [
        AvailableServerEntry(
            code="ams-1",
            display_name="Amsterdam 1",
            public_host="ams-1.example.test",
            profiles=[
                AvailableProfileEntry(
                    code="vless-xhttp-tls",
                    display_name="VLESS XHTTP",
                    protocol_id=uuid4(),
                    protocol_code="vless",
                    ad_block=False,
                    required_port=8445,
                    requires_udp=False,
                ),
                AvailableProfileEntry(
                    code="hysteria2",
                    display_name="Hysteria2",
                    protocol_id=uuid4(),
                    protocol_code="hysteria2",
                    ad_block=False,
                    required_port=8450,
                    requires_udp=True,
                ),
            ],
        )
    ]
    with make_client(discovery_service=service) as client:
        profiles = client.get("/v1/servers/", headers=AUTH_HEADERS).json()["items"][0]["profiles"]

    assert profiles[0]["required_port"] == 8445
    assert profiles[0]["requires_udp"] is False
    # Flagged rather than omitted: a UDP socket accepts a connect() whether
    # or not anything is listening, so a client measuring this the way it
    # measures the others would report a dead port as fast.
    assert profiles[1]["requires_udp"] is True


def test_a_profile_with_no_port_is_still_listed() -> None:
    # required_port is nullable, and a profile without one is not broken --
    # it is one nothing can measure. Dropping it from the listing would
    # remove a working profile from the picker.
    service = FakeServerDiscoveryService()
    service.entries = [
        AvailableServerEntry(
            code="ams-1",
            display_name="Amsterdam 1",
            public_host="ams-1.example.test",
            profiles=[
                AvailableProfileEntry(
                    code="wireguard-native",
                    display_name="WireGuard",
                    protocol_id=uuid4(),
                    protocol_code="wireguard",
                    ad_block=False,
                )
            ],
        )
    ]
    with make_client(discovery_service=service) as client:
        body = client.get("/v1/servers/", headers=AUTH_HEADERS).json()

    assert body["items"][0]["profiles"][0]["required_port"] is None


def test_through_the_cdn_every_profile_is_listed() -> None:
    # Every profile is listed, including ones that cannot cross the CDN: they
    # work from other networks and on other deployments, and the app's
    # per-protocol test shows which answer from here. The ones that cross the
    # CDN are listed at its port; the rest keep their own.
    protocol_id = uuid4()
    service = FakeServerDiscoveryService()
    service.entries = [
        AvailableServerEntry(
            code="ams-1",
            display_name="Amsterdam 1",
            public_host="ams-1.example.test",
            profiles=[
                AvailableProfileEntry(
                    code=code,
                    display_name=code,
                    protocol_id=protocol_id,
                    protocol_code="vless",
                    ad_block=False,
                    required_port=port,
                    transport=transport,
                )
                for code, transport, port in (
                    ("hysteria2", "hysteria", 8450),
                    ("vless-tcp-tls", "raw", 8449),
                    ("vless-ws-tls", "websocket", 8448),
                    ("vless-grpc-tls", "grpc", 8447),
                    ("vless-xhttp-tls", "xhttp", 8445),
                )
            ],
        )
    ]
    settings = Settings(env="test", cdn_host="cdn.example.test", front_hosts="front.example.test")
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, FakeUserAuthService())
    app.state.server_discovery_service = cast(ServerDiscoveryService, service)
    install_auth_http_safeguards(app, settings)
    app.include_router(router)

    with TestClient(app) as client:
        via_cdn = client.get("/v1/servers/", headers={**AUTH_HEADERS, "Host": "cdn.example.test"})
        direct = client.get("/v1/servers/", headers=AUTH_HEADERS)
        via_front = client.get(
            "/v1/servers/", headers={**AUTH_HEADERS, "X-Forwarded-Host": "front.example.test"}
        )

    cdn_profiles = {p["code"]: p["required_port"] for p in via_cdn.json()["items"][0]["profiles"]}
    assert cdn_profiles == {
        "hysteria2": 8450,
        "vless-tcp-tls": 8449,
        "vless-ws-tls": 443,
        "vless-grpc-tls": 443,
        "vless-xhttp-tls": 443,
    }
    assert len(direct.json()["items"][0]["profiles"]) == 5
    # Through the web host every tunnel the CDN carries goes through the CDN;
    # what it cannot carry stays direct.
    front_profiles = {
        p["code"]: p["required_port"] for p in via_front.json()["items"][0]["profiles"]
    }
    assert front_profiles == cdn_profiles


def test_maintenance_servers_are_listed_only_when_asked_for_and_flagged() -> None:
    service = FakeServerDiscoveryService()
    service.entries = [
        AvailableServerEntry(
            code="ams-1",
            display_name="Amsterdam 1",
            public_host="ams-1.example.test",
            maintenance=True,
        )
    ]
    with make_client(service) as client:
        plain = client.get("/v1/servers/", headers=AUTH_HEADERS)
        asked = client.get("/v1/servers/?include_maintenance=true", headers=AUTH_HEADERS)

    assert plain.status_code == 200
    assert asked.json()["items"][0]["maintenance"] is True
    assert service.include_maintenance is True
