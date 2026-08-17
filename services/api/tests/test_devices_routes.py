"""HTTP-layer tests for user-facing WireGuard peer provisioning routes."""

from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_service import AuthenticatedUser, AuthenticationRejected, UserAuthService
from nebula_api.devices.routes import router
from nebula_api.provisioning.service import (
    DeviceAlreadyHasPeer,
    OperationInProgress,
    ProvisioningAmbiguous,
    ProvisioningError,
    ProvisioningRateLimited,
    ProvisioningRejected,
    ProvisioningService,
    RequestPeerResult,
    RevokePeerResult,
)
from nebula_api.settings import Settings

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")
PEER_ID = uuid4()
AUTH_HEADERS = {"Authorization": "Bearer valid-token"}
VALID_BODY = {"server_code": "vps-1", "public_key": "C" * 43 + "="}


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

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def request_peer(self, **_kwargs: object) -> RequestPeerResult:
        self._raise_if_needed()
        return self.request_result

    async def revoke_peer(self, **_kwargs: object) -> RevokePeerResult:
        self._raise_if_needed()
        return self.revoke_result


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
            json={"server_code": "vps-1", "public_key": "not-a-key"},
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


def test_request_wireguard_peer_maps_device_already_has_peer_to_409() -> None:
    service = FakeProvisioningService()
    service.error = DeviceAlreadyHasPeer()
    with make_client(provisioning_service=service) as client:
        response = client.post(
            f"/v1/devices/{DEVICE_ID}/wireguard-peer", json=VALID_BODY, headers=AUTH_HEADERS
        )

    assert response.status_code == 409


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
