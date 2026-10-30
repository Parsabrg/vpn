from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.email_deliveries.routes import router
from nebula_api.email_deliveries.service import (
    EmailDeliveryEntry,
    EmailDeliveryFilters,
    EmailDeliveryPage,
    EmailDeliveryService,
)
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


class FakeEmailDeliveryService:
    def __init__(self) -> None:
        self.page = EmailDeliveryPage(items=[], total=0)
        self.received_filters: EmailDeliveryFilters | None = None

    async def list_events(
        self, *, filters: EmailDeliveryFilters, limit: int, offset: int
    ) -> EmailDeliveryPage:
        self.received_filters = filters
        return self.page


def make_client(
    delivery_service: FakeEmailDeliveryService | None = None,
    admin_service: FakeAdminAuthService | None = None,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service or FakeAdminAuthService())
    app.state.email_delivery_service = cast(
        EmailDeliveryService, delivery_service or FakeEmailDeliveryService()
    )
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_list_email_deliveries_requires_session() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/email-deliveries/")

    assert response.status_code == 401


def test_list_email_deliveries_returns_items() -> None:
    service = FakeEmailDeliveryService()
    entry = EmailDeliveryEntry(
        id=uuid4(),
        template_code="user_activation",
        recipient_address="user@example.com",
        subject_kind="user",
        subject_id=uuid4(),
        state="sent",
        attempt_count=1,
        available_at=NOW,
        sent_at=NOW,
        provider_message_id="canary-id",
        result_code="delivered",
    )
    service.page = EmailDeliveryPage(items=[entry], total=1)
    with make_client(delivery_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/email-deliveries/")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["state"] == "sent"
    assert response.headers["cache-control"] == "no-store"


def test_list_email_deliveries_forwards_filters_and_pagination() -> None:
    service = FakeEmailDeliveryService()
    with make_client(delivery_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(
            "/v1/admin/email-deliveries/",
            params={"state": "failed", "limit": 10, "offset": 5},
        )

    assert response.status_code == 200
    assert service.received_filters is not None
    assert service.received_filters.state == "failed"
    assert response.json()["limit"] == 10
    assert response.json()["offset"] == 5


def test_list_email_deliveries_service_unavailable() -> None:
    app = FastAPI()
    settings = Settings(env="test")
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, FakeAdminAuthService())
    app.state.email_delivery_service = None
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    with TestClient(app) as client:
        client.cookies.set(settings.admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/email-deliveries/")

    assert response.status_code == 503
