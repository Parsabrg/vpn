from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.audit.routes import router
from nebula_api.audit.service import AuditLogEntry, AuditLogFilters, AuditLogPage, AuditLogService
from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AdminRole
from nebula_api.settings import Settings

ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.AUDITOR) -> None:
        self.role = role
        self.error: Exception | None = None

    async def principal(self, _session_token: str) -> AdminPrincipal:
        if self.error is not None:
            raise self.error
        return AdminPrincipal(ADMIN_ID, SESSION_ID, self.role, False, "totp")


class FakeAuditLogService:
    def __init__(self) -> None:
        self.page = AuditLogPage(items=[], total=0)
        self.received_filters: AuditLogFilters | None = None

    async def list_events(
        self, *, filters: AuditLogFilters, limit: int, offset: int
    ) -> AuditLogPage:
        self.received_filters = filters
        return self.page


def make_client(
    audit_service: FakeAuditLogService | None = None,
    admin_service: FakeAdminAuthService | None = None,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service or FakeAdminAuthService())
    app.state.audit_log_service = cast(AuditLogService, audit_service or FakeAuditLogService())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_list_audit_log_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/audit-log/")

    assert response.status_code == 401


def test_list_audit_log_returns_items_for_any_role() -> None:
    service = FakeAuditLogService()
    entry = AuditLogEntry(
        id=uuid4(),
        actor_kind="admin",
        actor_id=ADMIN_ID,
        target_kind="user",
        target_id=uuid4(),
        event_code="identity_state_changed",
        outcome="succeeded",
        reason_code="disabled",
        request_id=uuid4(),
        recorded_at=NOW,
    )
    service.page = AuditLogPage(items=[entry], total=1)
    with make_client(audit_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/audit-log/")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["event_code"] == "identity_state_changed"
    assert response.headers["cache-control"] == "no-store"


def test_list_audit_log_forwards_filters_and_pagination() -> None:
    service = FakeAuditLogService()
    with make_client(audit_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(
            "/v1/admin/audit-log/",
            params={"actor_kind": "admin", "limit": 10, "offset": 5},
        )

    assert response.status_code == 200
    assert service.received_filters is not None
    assert service.received_filters.actor_kind == "admin"
    assert response.json()["limit"] == 10
    assert response.json()["offset"] == 5


def test_list_audit_log_service_unavailable() -> None:
    app = FastAPI()
    settings = Settings(env="test")
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.audit_log_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/audit-log/")

    assert response.status_code == 503
