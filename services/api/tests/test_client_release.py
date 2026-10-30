"""The newest client version, for apps that cannot read GitHub's releases."""

from typing import cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.user_service import AuthenticatedUser, UserAuthService
from nebula_api.client_release import router
from nebula_api.settings import Settings

AUTH_HEADERS = {"Authorization": "Bearer valid-token"}


class FakeUserAuthService:
    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        return AuthenticatedUser(
            user_id=UUID("11111111-1111-4111-8111-111111111111"),
            session_id=UUID("22222222-2222-4222-8222-222222222222"),
            device_id=UUID("33333333-3333-4333-8333-333333333333"),
        )


def make_client(version: str) -> TestClient:
    settings = Settings(env="test", client_latest_version=version)
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, FakeUserAuthService())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_requires_a_session() -> None:
    with make_client("0.1.24") as client:
        assert client.get("/v1/client/release").status_code == 401


def test_names_the_configured_version() -> None:
    with make_client("v0.1.24") as client:
        response = client.get("/v1/client/release", headers=AUTH_HEADERS)
    assert response.status_code == 200
    assert response.json() == {"version": "0.1.24"}
    assert response.headers["cache-control"] == "no-store"


def test_nothing_configured_offers_nothing() -> None:
    with make_client("") as client:
        response = client.get("/v1/client/release", headers=AUTH_HEADERS)
    assert response.json() == {"version": None}


@pytest.mark.parametrize("bad", ["latest", "1", "0.1.24-beta", "0.1.24; rm"])
def test_a_malformed_version_is_refused_at_startup(bad: str) -> None:
    with pytest.raises(ValidationError, match="expected a version"):
        Settings(env="test", client_latest_version=bad)
