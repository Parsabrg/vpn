"""The address list a client keeps for when it can no longer reach the API."""

from typing import cast
from uuid import UUID

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.api_routes import configured_routes, router
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.user_service import AuthenticatedUser, UserAuthService
from nebula_api.settings import Settings

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")
AUTH_HEADERS = {"Authorization": "Bearer valid-token"}


class FakeUserAuthService:
    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


def make_client(api_routes: str) -> TestClient:
    settings = Settings(env="test", api_routes=api_routes)
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, FakeUserAuthService())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_requires_a_session() -> None:
    # These addresses are what a censor would most like to have. Costing an
    # account to read is the point of the gate.
    with make_client("https://api.example.test:8445") as client:
        response = client.get("/v1/routes/")

    assert response.status_code == 401


def test_returns_the_configured_addresses_in_order() -> None:
    with make_client("https://api.example.test:8445, https://cdn.example.test/") as client:
        response = client.get("/v1/routes/", headers=AUTH_HEADERS)

    assert response.status_code == 200
    # Order is the order to try them in, and the trailing slash is trimmed so
    # the client's own comparison of "am I already on this one" holds.
    assert response.json() == {
        "routes": ["https://api.example.test:8445", "https://cdn.example.test"]
    }


def test_unset_means_no_extra_addresses_rather_than_an_error() -> None:
    with make_client("") as client:
        response = client.get("/v1/routes/", headers=AUTH_HEADERS)

    assert response.json() == {"routes": []}


def test_a_bad_entry_does_not_take_the_others_with_it() -> None:
    # A typo in one address must not cost a client the list it would have
    # used to get back, and plain http is never an address for this API.
    assert configured_routes(
        Settings(
            env="test",
            api_routes="https://good.example.test, http://plain.example.test, nonsense",
        )
    ) == ["https://good.example.test"]


def test_duplicates_are_dropped() -> None:
    assert configured_routes(
        Settings(env="test", api_routes="https://a.example.test,https://a.example.test/")
    ) == ["https://a.example.test"]
