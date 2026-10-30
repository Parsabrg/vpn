from typing import cast
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser, AuthenticationRejected, UserAuthService

USER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SESSION_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
DEVICE_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class FakeUserAuthService:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.received_token: str | None = None

    async def authenticate_access_token(self, token: str) -> AuthenticatedUser:
        self.received_token = token
        if self.error is not None:
            raise self.error
        return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


def make_app(service: FakeUserAuthService) -> FastAPI:
    app = FastAPI()
    app.state.user_auth_service = cast(UserAuthService, service)

    @app.get("/probe")
    async def probe(request: Request) -> dict[str, str]:
        principal = await require_user_session(request)
        return {"user_id": str(principal.user_id), "device_id": str(principal.device_id)}

    return app


def test_missing_authorization_header_is_rejected() -> None:
    with TestClient(make_app(FakeUserAuthService())) as client:
        response = client.get("/probe")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_non_bearer_scheme_is_rejected() -> None:
    with TestClient(make_app(FakeUserAuthService())) as client:
        response = client.get("/probe", headers={"Authorization": "Basic dXNlcjpwYXNz"})

    assert response.status_code == 401


def test_a_token_containing_whitespace_is_rejected() -> None:
    with TestClient(make_app(FakeUserAuthService())) as client:
        response = client.get("/probe", headers={"Authorization": "Bearer abc def"})

    assert response.status_code == 401


def test_valid_bearer_token_resolves_the_principal() -> None:
    service = FakeUserAuthService()
    with TestClient(make_app(service)) as client:
        response = client.get("/probe", headers={"Authorization": "Bearer valid-token-canary"})

    assert response.status_code == 200
    assert response.json() == {"user_id": str(USER_ID), "device_id": str(DEVICE_ID)}
    assert service.received_token == "valid-token-canary"  # noqa: S105 - test fixture


def test_rejected_token_maps_to_401() -> None:
    service = FakeUserAuthService(error=AuthenticationRejected())
    with TestClient(make_app(service)) as client:
        response = client.get("/probe", headers={"Authorization": "Bearer expired-token"})

    assert response.status_code == 401


def test_unavailable_auth_state_maps_to_503() -> None:
    service = FakeUserAuthService(error=AuthStateUnavailable())
    with TestClient(make_app(service)) as client:
        response = client.get("/probe", headers={"Authorization": "Bearer some-token"})

    assert response.status_code == 503


def test_missing_user_auth_service_maps_to_503() -> None:
    app = FastAPI()

    @app.get("/probe")
    async def probe(request: Request) -> dict[str, str]:
        principal = await require_user_session(request)
        return {"user_id": str(principal.user_id)}

    with TestClient(app) as client:
        response = client.get("/probe", headers={"Authorization": "Bearer some-token"})

    assert response.status_code == 503
