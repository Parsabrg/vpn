"""HTTP-layer tests for user-facing WireGuard peer provisioning routes."""

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_service import AuthenticatedUser, AuthenticationRejected, UserAuthService
from nebula_api.devices.routes import router
from nebula_api.provisioning.service import (
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningError,
    ProvisioningRateLimited,
    ProvisioningRejected,
    ProvisioningService,
    RequestPeerResult,
    RequestXrayClientResult,
    RevokePeerResult,
    RevokeXrayClientResult,
    ServerUnderMaintenance,
    XrayOperationInProgress,
)
from nebula_api.settings import Settings

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")
PEER_ID = uuid4()
XRAY_CLIENT_ID = uuid4()
XRAY_UUID = uuid4()
AUTH_HEADERS = {"Authorization": "Bearer valid-token"}
VALID_BODY = {
    "server_code": "vps-1",
    "protocol_profile_code": "wireguard-native",
    "public_key": "C" * 43 + "=",
}
VALID_XRAY_BODY = {"server_code": "vps-1", "protocol_profile_code": "vless-xhttp-tls"}


class FakeUserAuthService:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error

    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        if self.error is not None:
            raise self.error
        return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


class FakeProvisioningService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.dns_profile = "default"
        self.request_result = RequestPeerResult(
            peer_id=PEER_ID,
            assigned_address="203.0.113.2",
            server_public_key="B" * 43 + "=",
            listen_port=51820,
            public_endpoint="vps1.example.com:51820",
            client_dns="10.77.0.1",
            client_allowed_ips="0.0.0.0/0,::/0",
            persistent_keepalive_seconds=25,
        )
        self.revoke_result = RevokePeerResult(peer_id=PEER_ID, revoked_at=datetime.now(UTC))
        self.xray_request_result = RequestXrayClientResult(
            client_id=XRAY_CLIENT_ID,
            uuid=XRAY_UUID,
            server_address="vps1.example.com",
            port=8445,
            sni="vps1.example.com",
            transport="xhttp",
            transport_security="none",
            path="/xhttp",
            service_name=None,
            obfs_password=None,
            ad_block=False,
        )
        self.xray_revoke_result = RevokeXrayClientResult(
            client_id=XRAY_CLIENT_ID, revoked_at=datetime.now(UTC)
        )

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def dns_profile_for(self, **_kwargs: object) -> str:
        return self.dns_profile

    async def request_peer(self, **_kwargs: object) -> RequestPeerResult:
        self._raise_if_needed()
        return self.request_result

    async def revoke_peer(self, **_kwargs: object) -> RevokePeerResult:
        self._raise_if_needed()
        return self.revoke_result

    async def request_xray_client(self, **_kwargs: object) -> RequestXrayClientResult:
        self._raise_if_needed()
        return self.xray_request_result

    async def revoke_xray_client(self, **_kwargs: object) -> RevokeXrayClientResult:
        self._raise_if_needed()
        return self.xray_revoke_result


def make_client(
    provisioning_service: FakeProvisioningService | None = None,
    user_auth_service: FakeUserAuthService | None = None,
    *,
    omit_provisioning_service: bool = False,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, user_auth_service or FakeUserAuthService())
    if not omit_provisioning_service:
        app.state.provisioning_service = cast(
            ProvisioningService, provisioning_service or FakeProvisioningService()
        )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_request_wireguard_peer_requires_authentication() -> None:
    with make_client() as client:
        response = client.post(f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY)

    assert response.status_code == 401


def test_request_wireguard_peer_returns_the_peer_profile() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 200
    body = response.json()
    assert body["peer_id"] == str(PEER_ID)
    assert body["assigned_address"] == "203.0.113.2"
    assert body["server_public_key"] == "B" * 43 + "="
    assert body["listen_port"] == 51820


def test_request_wireguard_peer_rejects_a_malformed_public_key() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer",
            json={
                "server_code": "vps-1",
                "protocol_profile_code": "wireguard-native",
                "public_key": "not-a-key",
            },
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 422


def test_request_wireguard_peer_rejects_a_non_json_body() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer",
            content=b"not-json",
            headers={**AUTH_HEADERS, "Content-Type": "text/plain"},
        )

    # Pydantic body validation runs before require_json_request's own check,
    # so a malformed body is always 422 here -- matches
    # test_auth_routes.py's identical, already-documented precedent.
    assert response.status_code == 422


def test_request_wireguard_peer_maps_rate_limited_to_429() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRateLimited(60)
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"


def test_request_wireguard_peer_maps_ambiguous_to_503() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningAmbiguous()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 503


def test_request_wireguard_peer_maps_a_generic_rejection_to_400() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRejected()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 400


def test_request_wireguard_peer_maps_an_internal_invariant_failure_to_500() -> None:
    """A bare ProvisioningError means server-side state is inconsistent, not
    that the request was bad -- and its message must not reach the client."""

    service = FakeProvisioningService()
    service.error = ProvisioningError("provisioning rows disappeared mid-finalization")
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 500
    assert "disappeared" not in response.text


def test_request_wireguard_peer_maps_unavailable_auth_state_to_503() -> None:
    service = FakeProvisioningService()
    service.error = AuthStateUnavailable()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 503


def test_request_wireguard_peer_maps_a_missing_service_to_503() -> None:
    with make_client(omit_provisioning_service=True) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 503


def test_request_wireguard_peer_maps_a_rejected_access_token_to_401() -> None:
    auth_service = FakeUserAuthService(error=AuthenticationRejected())
    with make_client(user_auth_service=auth_service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 401


def test_revoke_wireguard_peer_requires_authentication() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer/revoke", json={"server_code": "vps-1"}
        )

    assert response.status_code == 401


def test_revoke_wireguard_peer_returns_no_content() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer/revoke",
            json={"server_code": "vps-1"},
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 204


def test_revoke_wireguard_peer_maps_operation_in_progress_to_409() -> None:
    service = FakeProvisioningService()
    service.error = OperationInProgress()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer/revoke",
            json={"server_code": "vps-1"},
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 409


def test_revoke_wireguard_peer_maps_a_generic_rejection_to_400() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRejected()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer/revoke",
            json={"server_code": "vps-1"},
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 400


def test_request_xray_client_requires_authentication() -> None:
    with make_client() as client:
        response = client.post(f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY)

    assert response.status_code == 401


def test_request_xray_client_returns_the_client_profile() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 200
    body = response.json()
    assert body["client_id"] == str(XRAY_CLIENT_ID)
    assert body["uuid"] == str(XRAY_UUID)
    assert body["server_address"] == "vps1.example.com"
    assert body["port"] == 8445
    assert body["transport"] == "xhttp"
    assert body["path"] == "/xhttp"
    assert body["transport_security"] == "none"


def test_request_xray_client_rejects_a_non_json_body() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            content=b"not-json",
            headers={**AUTH_HEADERS, "Content-Type": "text/plain"},
        )

    assert response.status_code == 422


def test_request_xray_client_maps_rate_limited_to_429() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRateLimited(60)
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"


def test_request_xray_client_maps_ambiguous_to_503() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningAmbiguous()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 503


def test_request_xray_client_maps_a_generic_rejection_to_400() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRejected()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 400


def test_request_xray_client_maps_a_missing_service_to_503() -> None:
    with make_client(omit_provisioning_service=True) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 503


def test_revoke_xray_client_requires_authentication() -> None:
    with make_client() as client:
        response = client.post(f"/v1/devices/{DEVICE_ID}/xray-client/revoke", json=VALID_XRAY_BODY)

    assert response.status_code == 401


def test_revoke_xray_client_returns_no_content() -> None:
    with make_client() as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client/revoke",
            json=VALID_XRAY_BODY,
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 204


def test_revoke_xray_client_maps_operation_in_progress_to_409() -> None:
    service = FakeProvisioningService()
    service.error = XrayOperationInProgress()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client/revoke",
            json=VALID_XRAY_BODY,
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 409


def test_revoke_xray_client_maps_a_generic_rejection_to_400() -> None:
    service = FakeProvisioningService()
    service.error = ProvisioningRejected()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client/revoke",
            json=VALID_XRAY_BODY,
            headers=AUTH_HEADERS,
        )

    assert response.status_code == 400


def _cdn_client(
    provisioning_service: FakeProvisioningService,
    cdn_host: str = "cdn.example.test",
    front_hosts: str = "",
    xray_client_dns: str = "",
    cdn_servers: str = "",
) -> TestClient:
    settings = Settings(
        env="test",
        cdn_host=cdn_host,
        front_hosts=front_hosts,
        xray_client_dns=xray_client_dns,
        cdn_servers=cdn_servers,
    )
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, FakeUserAuthService())
    app.state.provisioning_service = cast(ProvisioningService, provisioning_service)
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_request_xray_client_through_the_cdn_points_the_tunnel_through_it() -> None:
    # Reaching the API through the CDN hostname means the direct route is
    # blocked for this client, so the tunnel must not point at it either.
    with _cdn_client(FakeProvisioningService()) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "Host": "cdn.example.test"},
        )

    body = response.json()
    assert (body["server_address"], body["port"], body["sni"]) == (
        "cdn.example.test",
        443,
        "cdn.example.test",
    )
    assert body["transport_security"] == "tls"
    assert body["path"] == "/xhttp"
    # Through Cloudflare, with Encrypted Client Hello: without it the tunnel
    # carried nothing from Iran (2026-10-07).
    assert body["ech_config_list"] == "cloudflare-ech.com+udp://1.1.1.1"


def test_a_server_not_behind_the_cdn_is_dialled_itself() -> None:
    # The CDN name points at the first server; a second server's tunnel sent
    # through it reached a server that did not know the credential.
    with _cdn_client(FakeProvisioningService(), cdn_servers="home-1") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "Host": "cdn.example.test"},
        )

    assert response.json()["server_address"] != "cdn.example.test"
    with _cdn_client(FakeProvisioningService(), cdn_servers="home-1, vps-1") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "Host": "cdn.example.test"},
        )

    assert response.json()["server_address"] == "cdn.example.test"


def test_request_xray_client_through_a_second_cdn_host_points_back_through_it() -> None:
    with _cdn_client(
        FakeProvisioningService(), cdn_host="cdn.example.test, d111.cloudfront.example.test"
    ) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "Host": "d111.cloudfront.example.test"},
        )

    body = response.json()
    assert (body["server_address"], body["port"], body["sni"]) == (
        "d111.cloudfront.example.test",
        443,
        "d111.cloudfront.example.test",
    )


@pytest.mark.parametrize(
    "arrival",
    [
        {"X-Forwarded-Host": "front.example.test"},
        {"Host": "cdn.example.test"},
        {},
    ],
    ids=["through the web host", "through the cdn", "directly"],
)
def test_xhttp_goes_through_the_web_host_however_the_api_was_reached(
    arrival: dict[str, str],
) -> None:
    # Cloudflare's ECH was blocked from Iran on 2026-10-21 while XHTTP through
    # the web host carried everything; see nebula_api/cdn.py.
    with _cdn_client(FakeProvisioningService(), front_hosts="front.example.test") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, **arrival},
        )

    body = response.json()
    assert (body["server_address"], body["port"], body["sni"]) == (
        "front.example.test",
        443,
        "front.example.test",
    )
    assert body["transport_security"] == "tls"
    # A web host is not Cloudflare: there is no ECH key to use.
    assert body["ech_config_list"] is None


def test_with_no_cdn_xhttp_keeps_the_web_host() -> None:
    with _cdn_client(
        FakeProvisioningService(), cdn_host="", front_hosts="front.example.test"
    ) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "X-Forwarded-Host": "front.example.test"},
        )

    body = response.json()
    assert body["server_address"] == "front.example.test"
    # Not Cloudflare: no ECH key to use.
    assert body["ech_config_list"] is None


def test_request_xray_client_through_a_web_host_sends_websocket_through_the_cdn() -> None:
    # A web host does not carry the WebSocket upgrade, but the CDN does --
    # and the direct address is usually why the web host was used.
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result, transport="websocket", port=8448, path="/ws"
    )
    with _cdn_client(service, front_hosts="front.example.test") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "X-Forwarded-Host": "front.example.test"},
        )

    assert response.json()["server_address"] == "cdn.example.test"
    assert response.json()["sni"] == "cdn.example.test"
    assert response.json()["port"] == 443


def test_through_a_web_host_with_no_cdn_websocket_stays_direct() -> None:
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result, transport="websocket", port=8448, path="/ws"
    )
    with _cdn_client(service, cdn_host="", front_hosts="front.example.test") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "X-Forwarded-Host": "front.example.test"},
        )

    assert response.json()["server_address"] == "vps1.example.com"
    assert response.json()["port"] == 8448


def test_request_xray_client_directly_still_tunnels_through_the_cdn() -> None:
    # The direct address answered the API while every tunnel through it
    # stalled; with a CDN configured the tunnel always crosses it.
    with _cdn_client(FakeProvisioningService()) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.json()["server_address"] == "cdn.example.test"
    assert response.json()["port"] == 443
    assert response.json()["ech_config_list"] == "cloudflare-ech.com+udp://1.1.1.1"


def test_request_xray_client_through_the_cdn_leaves_a_non_http_transport_alone() -> None:
    # Hysteria2 cannot cross the CDN; rewriting it would point at a CDN edge
    # that does not carry QUIC to this server.
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result, transport="hysteria", port=8450, path=None
    )
    with _cdn_client(service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client",
            json=VALID_XRAY_BODY,
            headers={**AUTH_HEADERS, "Host": "cdn.example.test"},
        )

    assert response.json()["server_address"] == "vps1.example.com"
    assert response.json()["port"] == 8450


def test_the_deployments_resolver_is_handed_to_xray_clients() -> None:
    # Roadmap 26: the agent redirects this address to the server's own
    # resolver, so the app is told to use it.
    with _cdn_client(FakeProvisioningService(), xray_client_dns="198.18.0.53") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.json()["client_dns"] == ["198.18.0.53"]


def test_hysteria_clients_are_not_given_the_xray_resolver() -> None:
    # Hysteria2 runs outside Xray, where the agent's redirect does not reach.
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result, transport="hysteria", port=8450, path=None
    )
    with _cdn_client(service, xray_client_dns="198.18.0.53") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.json()["client_dns"] == []


def test_no_resolver_configured_hands_out_none() -> None:
    with _cdn_client(FakeProvisioningService()) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.json()["client_dns"] == []


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        ("default", ["198.18.0.53"]),
        ("ads", ["94.140.14.14", "94.140.15.15"]),
        ("family", ["94.140.14.15", "94.140.15.16"]),
    ],
)
def test_the_accounts_dns_profile_decides_the_resolver(profile: str, expected: list[str]) -> None:
    # Roadmap 13: an account (or a device) with the ads or family profile gets
    # a filtering resolver; default gets the deployment's own.
    service = FakeProvisioningService()
    service.dns_profile = profile
    with _cdn_client(service, xray_client_dns="198.18.0.53") as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    assert response.json()["client_dns"] == expected


def test_a_server_under_maintenance_is_423_with_a_readable_sentence() -> None:
    # 423 is used for nothing else, so the app can tell it apart; an app from
    # before it shows the sentence.
    service = FakeProvisioningService()
    service.error = ServerUnderMaintenance("This server is under maintenance. Try again later.")
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 423
    assert response.json()["detail"] == "This server is under maintenance. Try again later."


def test_shadowsocks_stays_direct_and_carries_its_key() -> None:
    # No TLS to front: Shadowsocks-2022 goes to the server's own address even
    # when the app reached the API through the CDN.
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result,
        transport="raw",
        transport_security="none",
        port=8451,
        protocol="shadowsocks",
        method="2022-blake3-aes-128-gcm",
        password="server:user",  # noqa: S106 - a test value
    )
    with _cdn_client(service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        )

    body = response.json()
    assert body["server_address"] == "vps1.example.com"
    assert body["port"] == 8451
    assert body["protocol"] == "shadowsocks"
    assert body["method"] == "2022-blake3-aes-128-gcm"
    assert body["password"] == "server:user"  # noqa: S105 - a test value
    assert body["ech_config_list"] is None


def test_vmess_websocket_without_tls_never_goes_through_the_cdn() -> None:
    # The CDN carries TLS only; a VMess WebSocket with its own encryption is
    # dialled at the server even when the app reached the API through the CDN.
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result,
        transport="websocket",
        transport_security="none",
        port=8455,
        path="/vw",
        protocol="vmess",
    )
    with _cdn_client(service) as client:
        body = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        ).json()

    assert (body["server_address"], body["port"], body["protocol"]) == (
        "vps1.example.com",
        8455,
        "vmess",
    )


def test_vless_encryption_carries_its_client_string() -> None:
    service = FakeProvisioningService()
    service.xray_request_result = replace(
        service.xray_request_result,
        transport="raw",
        transport_security="none",
        port=8453,
        encryption="mlkem768x25519plus.native.0rtt.k",
    )
    with _cdn_client(service) as client:
        body = client.post(
            f"/v1/devices/{DEVICE_ID}/xray-client", json=VALID_XRAY_BODY, headers=AUTH_HEADERS
        ).json()

    assert body["encryption"] == "mlkem768x25519plus.native.0rtt.k"
    assert body["server_address"] == "vps1.example.com"
