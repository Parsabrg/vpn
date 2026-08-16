from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AccountState, AdminRole, LifecycleState
from nebula_api.settings import Settings
from nebula_api.user_management.routes import router
from nebula_api.user_management.service import (
    DeviceSummary,
    UserDetail,
    UserManagementRateLimited,
    UserManagementRejected,
    UserManagementService,
    UserPage,
    UserSessionSummary,
    UserSummary,
)

ORIGIN = "http://localhost:3000"
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.OWNER, step_up: bool = True) -> None:
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


def user_summary(
    *,
    state: AccountState = AccountState.ACTIVE,
    disabled_at: datetime | None = None,
) -> UserSummary:
    return UserSummary(
        id=USER_ID,
        email="user@example.com",
        username=None,
        state=state,
        device_limit=3,
        expires_at=None,
        activated_at=NOW,
        disabled_at=disabled_at,
        created_at=NOW,
    )


class FakeUserManagementService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.page = UserPage(items=[], total=0)
        self.detail: UserDetail | None = None
        self.summary = user_summary()
        self.device_summary = DeviceSummary(
            id=DEVICE_ID,
            name="Laptop",
            platform="windows",
            client_version="1.0.0",
            state=LifecycleState.REVOKED,
            revoked_at=NOW,
        )
        self.session_summary = UserSessionSummary(
            id=uuid4(),
            device_id=DEVICE_ID,
            state=LifecycleState.REVOKED,
            expires_at=NOW,
            last_seen_at=NOW,
            revoked_at=NOW,
        )

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def list_users(self, **_kwargs: object) -> UserPage:
        self._raise_if_needed()
        return self.page

    async def get_user_detail(self, _user_id: UUID) -> UserDetail | None:
        self._raise_if_needed()
        return self.detail

    async def disable_user(self, **_kwargs: object) -> UserSummary:
        self._raise_if_needed()
        return self.summary

    async def reactivate_user(self, **_kwargs: object) -> UserSummary:
        self._raise_if_needed()
        return self.summary

    async def revoke_device(self, **_kwargs: object) -> DeviceSummary:
        self._raise_if_needed()
        return self.device_summary

    async def revoke_session(self, **_kwargs: object) -> UserSessionSummary:
        self._raise_if_needed()
        return self.session_summary


def make_client(
    user_service: FakeUserManagementService | None = None,
    admin_service: FakeAdminAuthService | None = None,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service or FakeAdminAuthService())
    app.state.user_management_service = cast(
        UserManagementService, user_service or FakeUserManagementService()
    )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def _authenticated_headers(client: TestClient) -> dict[str, str]:
    settings = Settings(env="test")
    client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
    client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")
    return {"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"}


def test_list_users_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/users/")

    assert response.status_code == 401


def test_list_users_returns_items() -> None:
    service = FakeUserManagementService()
    service.page = UserPage(items=[user_summary()], total=1)
    with make_client(user_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/users/")

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_get_user_not_found_returns_404() -> None:
    with make_client() as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(f"/v1/admin/users/{USER_ID}")

    assert response.status_code == 404


def test_get_user_returns_detail() -> None:
    service = FakeUserManagementService()
    service.detail = UserDetail(user=user_summary(), devices=[], sessions=[])
    with make_client(user_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(f"/v1/admin/users/{USER_ID}")

    assert response.status_code == 200
    assert response.json()["user"]["id"] == str(USER_ID)


def test_disable_user_requires_step_up() -> None:
    with make_client(admin_service=FakeAdminAuthService(step_up=False)) as client:
        headers = _authenticated_headers(client)
        response = client.post(f"/v1/admin/users/{USER_ID}/disable", headers=headers, json={})

    assert response.status_code == 403
    assert response.json()["detail"] == "step_up_required"


def test_disable_user_rejects_auditor_role() -> None:
    with make_client(admin_service=FakeAdminAuthService(role=AdminRole.AUDITOR)) as client:
        headers = _authenticated_headers(client)
        response = client.post(f"/v1/admin/users/{USER_ID}/disable", headers=headers, json={})

    assert response.status_code == 403


def test_disable_user_succeeds_when_stepped_up() -> None:
    service = FakeUserManagementService()
    service.summary = user_summary(state=AccountState.DISABLED, disabled_at=NOW)
    with make_client(user_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(f"/v1/admin/users/{USER_ID}/disable", headers=headers, json={})

    assert response.status_code == 200
    assert response.json()["state"] == "disabled"
    assert response.headers["x-csrf-token"] == "v1.csrf-replacement"


def test_reactivate_user_maps_domain_rejection() -> None:
    service = FakeUserManagementService()
    service.error = UserManagementRejected("Request was not accepted")
    with make_client(user_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(f"/v1/admin/users/{USER_ID}/reactivate", headers=headers, json={})

    assert response.status_code == 400


def test_revoke_device_maps_rate_limited() -> None:
    service = FakeUserManagementService()
    service.error = UserManagementRateLimited(30)
    with make_client(user_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/devices/{DEVICE_ID}/revoke", headers=headers, json={}
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"


def test_revoke_session_succeeds() -> None:
    service = FakeUserManagementService()
    with make_client(user_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/sessions/{uuid4()}/revoke", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "revoked"
