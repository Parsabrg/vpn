from dataclasses import asdict
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.access.routes import router
from nebula_api.access.service import (
    AccessRateLimited,
    AccessRejected,
    AccessService,
    AssignmentListEntry,
    AssignmentPage,
    AssignmentSummary,
    PermissionListEntry,
    PermissionPage,
    PermissionSummary,
)
from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings

ORIGIN = "http://localhost:3000"
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
PROFILE_ID = UUID("22222222-2222-4222-8222-222222222222")
SERVER_ID = UUID("33333333-3333-4333-8333-333333333333")
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


def permission_summary(*, state: str = "enabled") -> PermissionSummary:
    return PermissionSummary(
        id=uuid4(),
        protocol_profile_id=PROFILE_ID,
        profile_code="wireguard-native",
        profile_display_name="WireGuard",
        state=state,
        granted_by_admin_id=ADMIN_ID,
        granted_at=NOW,
        expires_at=None,
        revoked_at=None,
    )


def assignment_summary(*, state: str = "active") -> AssignmentSummary:
    return AssignmentSummary(
        id=uuid4(),
        vpn_server_id=SERVER_ID,
        server_code="fra-1",
        server_display_name="Frankfurt 1",
        state=state,
        assigned_by_admin_id=ADMIN_ID,
        assigned_at=NOW,
        expires_at=None,
        revoked_at=None,
    )


class FakeAccessService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.permission_items: list[PermissionSummary] = []
        self.assignment_items: list[AssignmentSummary] = []
        self.permission_page = PermissionPage(items=[], total=0)
        self.assignment_page = AssignmentPage(items=[], total=0)
        self.permission_summary = permission_summary()
        self.assignment_summary = assignment_summary()

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def list_user_permissions(self, _user_id: UUID) -> list[PermissionSummary]:
        self._raise_if_needed()
        return self.permission_items

    async def list_user_assignments(self, _user_id: UUID) -> list[AssignmentSummary]:
        self._raise_if_needed()
        return self.assignment_items

    async def list_all_permissions(self, **_kwargs: object) -> PermissionPage:
        self._raise_if_needed()
        return self.permission_page

    async def list_all_assignments(self, **_kwargs: object) -> AssignmentPage:
        self._raise_if_needed()
        return self.assignment_page

    async def grant_permission(self, **_kwargs: object) -> PermissionSummary:
        self._raise_if_needed()
        return self.permission_summary

    async def revoke_permission(self, **_kwargs: object) -> PermissionSummary:
        self._raise_if_needed()
        return self.permission_summary

    async def assign_server(self, **_kwargs: object) -> AssignmentSummary:
        self._raise_if_needed()
        return self.assignment_summary

    async def revoke_assignment(self, **_kwargs: object) -> AssignmentSummary:
        self._raise_if_needed()
        return self.assignment_summary


def make_client(
    access_service: FakeAccessService | None = None,
    admin_service: FakeAdminAuthService | None = None,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service or FakeAdminAuthService())
    app.state.access_service = cast(AccessService, access_service or FakeAccessService())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def _authenticated_headers(client: TestClient) -> dict[str, str]:
    settings = Settings(env="test")
    client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
    client.cookies.set(settings.admin_csrf_cookie_name, "v1.csrf-canary")
    return {"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"}


def test_list_permissions_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/permissions")

    assert response.status_code == 401


def test_list_permissions_returns_items() -> None:
    service = FakeAccessService()
    service.permission_page = PermissionPage(
        items=[
            PermissionListEntry(
                **asdict(permission_summary()), user_id=USER_ID, user_email="user@example.com"
            )
        ],
        total=1,
    )
    with make_client(access_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/permissions")

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_list_assignments_returns_items() -> None:
    service = FakeAccessService()
    service.assignment_page = AssignmentPage(
        items=[
            AssignmentListEntry(
                **asdict(assignment_summary()), user_id=USER_ID, user_email="user@example.com"
            )
        ],
        total=1,
    )
    with make_client(access_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/assignments")

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_list_user_permissions_returns_items() -> None:
    service = FakeAccessService()
    service.permission_items = [permission_summary()]
    with make_client(access_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(f"/v1/admin/users/{USER_ID}/permissions")

    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


def test_list_user_assignments_returns_items() -> None:
    service = FakeAccessService()
    service.assignment_items = [assignment_summary()]
    with make_client(access_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(f"/v1/admin/users/{USER_ID}/assignments")

    assert response.status_code == 200
    assert len(response.json()["items"]) == 1


def test_grant_permission_requires_step_up() -> None:
    with make_client(admin_service=FakeAdminAuthService(step_up=False)) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/grant", headers=headers, json={}
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "step_up_required"


def test_grant_permission_rejects_auditor_role() -> None:
    with make_client(admin_service=FakeAdminAuthService(role=AdminRole.AUDITOR)) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/grant", headers=headers, json={}
        )

    assert response.status_code == 403


def test_grant_permission_succeeds_when_stepped_up() -> None:
    service = FakeAccessService()
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/grant", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "enabled"
    assert response.headers["x-csrf-token"] == "v1.csrf-replacement"


def test_revoke_permission_succeeds() -> None:
    service = FakeAccessService()
    service.permission_summary = permission_summary(state="disabled")
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/revoke", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "disabled"


def test_assign_server_succeeds() -> None:
    service = FakeAccessService()
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/assignments/{SERVER_ID}/assign", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "active"


def test_revoke_permission_maps_domain_rejection() -> None:
    service = FakeAccessService()
    service.error = AccessRejected("Request was not accepted")
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/revoke", headers=headers, json={}
        )

    assert response.status_code == 400


def test_assign_server_maps_rate_limited() -> None:
    service = FakeAccessService()
    service.error = AccessRateLimited(30)
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/assignments/{SERVER_ID}/assign", headers=headers, json={}
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"


def test_revoke_assignment_succeeds() -> None:
    service = FakeAccessService()
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/assignments/{SERVER_ID}/revoke", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "active"


def test_grant_permission_maps_domain_rejection() -> None:
    service = FakeAccessService()
    service.error = AccessRejected("Request was not accepted")
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/grant", headers=headers, json={}
        )

    assert response.status_code == 400


def test_revoke_assignment_maps_domain_rejection() -> None:
    service = FakeAccessService()
    service.error = AccessRejected("Request was not accepted")
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/assignments/{SERVER_ID}/revoke", headers=headers, json={}
        )

    assert response.status_code == 400


def test_grant_permission_maps_auth_state_unavailable() -> None:
    service = FakeAccessService()
    service.error = AuthStateUnavailable("redis is down")
    with make_client(access_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/permissions/{PROFILE_ID}/grant", headers=headers, json={}
        )

    assert response.status_code == 503


def test_service_unavailable_returns_503() -> None:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.access_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)

    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/permissions")

    assert response.status_code == 503
