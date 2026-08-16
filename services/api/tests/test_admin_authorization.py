from typing import cast
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from nebula_api.auth.admin_authorization import (
    STEP_UP_REQUIRED_DETAIL,
    authorize_admin_mutation,
    require_admin_session,
)
from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings

ORIGIN = "http://localhost:3000"
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.OWNER, step_up: bool = False) -> None:
        self.role = role
        self.step_up = step_up
        self.error: Exception | None = None

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def principal(self, _session_token: str) -> AdminPrincipal:
        self._raise_if_needed()
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, self.step_up, "totp")

    async def validate_and_rotate_csrf(self, _session: str, _csrf: str) -> str:
        self._raise_if_needed()
        return "v1.csrf-replacement"


def make_app(admin_service: FakeAdminAuthService, *, settings: Settings | None = None) -> FastAPI:
    effective_settings = settings or Settings(env="test")
    app = FastAPI()
    app.state.settings = effective_settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service)
    install_auth_http_safeguards(app, effective_settings)

    @app.get("/probe-read")
    async def probe_read(request: Request) -> dict[str, str]:
        principal = await require_admin_session(request)
        return {"role": principal.role.value}

    @app.post("/probe-mutate")
    async def probe_mutate(request: Request) -> dict[str, str]:
        principal = await authorize_admin_mutation(
            request,
            allowed_roles=frozenset({AdminRole.OWNER, AdminRole.OPERATOR}),
            require_step_up=True,
        )
        return {"role": principal.role.value}

    return app


def _authenticated_cookies(client: TestClient, settings: Settings) -> None:
    client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
    client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")


def test_require_admin_session_rejects_missing_cookie() -> None:
    with TestClient(make_app(FakeAdminAuthService())) as client:
        response = client.get("/probe-read")

    assert response.status_code == 401


def test_require_admin_session_succeeds_for_any_role() -> None:
    settings = Settings(env="test")
    service = FakeAdminAuthService(role=AdminRole.AUDITOR)
    with TestClient(make_app(service, settings=settings)) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/probe-read")

    assert response.status_code == 200
    assert response.json() == {"role": "auditor"}


def test_authorize_admin_mutation_requires_origin() -> None:
    settings = Settings(env="test")
    with TestClient(make_app(FakeAdminAuthService(step_up=True), settings=settings)) as client:
        _authenticated_cookies(client, settings)
        response = client.post("/probe-mutate", json={})

    assert response.status_code == 403


def test_authorize_admin_mutation_requires_csrf_match() -> None:
    settings = Settings(env="test")
    with TestClient(make_app(FakeAdminAuthService(step_up=True), settings=settings)) as client:
        _authenticated_cookies(client, settings)
        response = client.post(
            "/probe-mutate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong-token"},
            json={},
        )

    assert response.status_code == 401


def test_authorize_admin_mutation_rejects_disallowed_role() -> None:
    settings = Settings(env="test")
    service = FakeAdminAuthService(role=AdminRole.AUDITOR, step_up=True)
    with TestClient(make_app(service, settings=settings)) as client:
        _authenticated_cookies(client, settings)
        response = client.post(
            "/probe-mutate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
            json={},
        )

    assert response.status_code == 403
    assert response.json()["detail"] != STEP_UP_REQUIRED_DETAIL


def test_authorize_admin_mutation_requires_step_up() -> None:
    settings = Settings(env="test")
    service = FakeAdminAuthService(role=AdminRole.OWNER, step_up=False)
    with TestClient(make_app(service, settings=settings)) as client:
        _authenticated_cookies(client, settings)
        response = client.post(
            "/probe-mutate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
            json={},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == STEP_UP_REQUIRED_DETAIL


def test_authorize_admin_mutation_succeeds_when_stepped_up() -> None:
    settings = Settings(env="test")
    service = FakeAdminAuthService(role=AdminRole.OPERATOR, step_up=True)
    with TestClient(make_app(service, settings=settings)) as client:
        _authenticated_cookies(client, settings)
        response = client.post(
            "/probe-mutate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"},
            json={},
        )

    assert response.status_code == 200
    assert response.headers["x-csrf-token"] == "v1.csrf-replacement"
