from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from nebula_api.accounts.service import (
    AccountRequestRateLimited,
    AccountRequestRejected,
    AccountRequestService,
    AccountRequestSummary,
)
from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.redis_state import AuthStateUnavailable
from nebula_api.auth.user_service import AuthenticationRejected
from nebula_api.main import create_app
from nebula_api.models.types import AdminRole, RequestState
from nebula_api.settings import Settings

ORIGIN = "http://localhost:3000"
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
ADMIN_SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
REQUEST_ID = UUID("11111111-1111-4111-8111-111111111111")
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


async def ready() -> bool:
    return True


class FakeAdminAuthService:
    def __init__(self, *, role: AdminRole = AdminRole.OWNER) -> None:
        self.role = role
        self.error: Exception | None = None

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def principal(self, _session_token: str) -> AdminPrincipal:
        self._raise_if_needed()
        return AdminPrincipal(ADMIN_ID, ADMIN_SESSION_ID, self.role, False, "totp")

    async def validate_and_rotate_csrf(self, _session: str, _csrf: str) -> str:
        self._raise_if_needed()
        return "v1.csrf-replacement"


class FakeAccountRequestService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.pending: list[AccountRequestSummary] = []
        self.decision: AccountRequestSummary | None = None
        self.approve_calls: list[UUID] = []
        self.reject_calls: list[tuple[UUID, str | None]] = []

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def submit_request(self, **_kwargs: object) -> None:
        self._raise_if_needed()

    async def list_pending(self) -> list[AccountRequestSummary]:
        self._raise_if_needed()
        return self.pending

    async def approve(
        self, *, account_request_id: UUID, admin_id: UUID, **_kwargs: object
    ) -> AccountRequestSummary:
        self._raise_if_needed()
        self.approve_calls.append(account_request_id)
        return self.decision or _summary(account_request_id)

    async def reject(
        self,
        *,
        account_request_id: UUID,
        admin_id: UUID,
        reason: str | None,
        **_kwargs: object,
    ) -> AccountRequestSummary:
        self._raise_if_needed()
        self.reject_calls.append((account_request_id, reason))
        return self.decision or _summary(account_request_id, state=RequestState.REJECTED)

    async def confirm_activation(self, **_kwargs: object) -> None:
        self._raise_if_needed()


def _summary(
    request_id: UUID, *, state: RequestState = RequestState.APPROVED
) -> AccountRequestSummary:
    return AccountRequestSummary(
        id=request_id,
        email="applicant@example.com",
        username=None,
        state=state,
        created_at=NOW,
    )


def make_client(
    account_service: FakeAccountRequestService | None = None,
    admin_service: FakeAdminAuthService | None = None,
    *,
    settings: Settings | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            settings or Settings(env="test"),
            readiness_check=ready,
            admin_auth_service=cast(AdminAuthService, admin_service or FakeAdminAuthService()),
            account_request_service=cast(
                AccountRequestService, account_service or FakeAccountRequestService()
            ),
        )
    )


def _authenticated_admin_headers(client: TestClient) -> dict[str, str]:
    client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
    client.cookies.set(Settings(env="test").admin_csrf_cookie_name, "v1.csrf-canary")
    return {"Origin": ORIGIN, "X-CSRF-Token": "v1.csrf-canary"}


def test_submit_request_and_activate_return_neutral_contracts() -> None:
    with make_client() as client:
        submitted = client.post(
            "/v1/account-requests/",
            json={"email": "applicant@example.com"},
        )
        activated = client.post(
            "/v1/account-requests/activate",
            json={"token": "v1.activation-canary", "new_password": "a-strong-password-123"},
        )

    assert submitted.status_code == 202
    assert submitted.json() == {"status": "accepted"}
    assert activated.status_code == 204
    for response in (submitted, activated):
        assert response.headers["cache-control"] == "no-store"


def test_submit_request_rejects_wrong_media_type() -> None:
    with make_client() as client:
        response = client.post(
            "/v1/account-requests/",
            content="email=applicant@example.com",
            headers={"Content-Type": "text/plain"},
        )

    assert response.status_code == 422  # model validation occurs before the route guard


def test_submit_request_is_rate_limited() -> None:
    service = FakeAccountRequestService()
    service.error = AccountRequestRateLimited(30)
    with make_client(account_service=service) as client:
        response = client.post("/v1/account-requests/", json={"email": "applicant@example.com"})

    assert response.status_code == 429
    assert response.headers["retry-after"] == "30"


def test_submit_request_stays_neutral_when_dependency_is_unavailable() -> None:
    service = FakeAccountRequestService()
    service.error = AuthStateUnavailable("redis down")
    with make_client(account_service=service) as client:
        response = client.post("/v1/account-requests/", json={"email": "applicant@example.com"})

    assert response.status_code == 202


def test_activate_rejects_invalid_token() -> None:
    service = FakeAccountRequestService()
    service.error = AccountRequestRejected("Request was not accepted")
    with make_client(account_service=service) as client:
        response = client.post(
            "/v1/account-requests/activate",
            json={"token": "v1.bad-canary", "new_password": "a-strong-password-123"},
        )

    assert response.status_code == 400


def test_admin_list_requires_session_cookie() -> None:
    with make_client() as client:
        response = client.get("/v1/admin/account-requests/")

    assert response.status_code == 401


def test_admin_list_returns_pending_requests() -> None:
    service = FakeAccountRequestService()
    service.pending = [_summary(uuid4(), state=RequestState.PENDING)]
    with make_client(account_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get("/v1/admin/account-requests/")

    assert response.status_code == 200
    assert response.json()["items"][0]["state"] == "pending"
    assert response.headers["cache-control"] == "no-store"


def test_admin_approve_requires_origin_and_csrf_match() -> None:
    account_request_id = uuid4()
    with make_client() as client:
        missing_origin = client.post(
            f"/v1/admin/account-requests/{account_request_id}/approve", json={}
        )
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        client.cookies.set(Settings(env="test").admin_csrf_cookie_name, "v1.csrf-canary")
        mismatched = client.post(
            f"/v1/admin/account-requests/{account_request_id}/approve",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong-token"},
            json={},
        )

    assert missing_origin.status_code == 403
    assert mismatched.status_code == 401


def test_admin_approve_succeeds_and_rotates_csrf() -> None:
    account_request_id = uuid4()
    service = FakeAccountRequestService()
    service.decision = _summary(account_request_id, state=RequestState.APPROVED)
    with make_client(account_service=service) as client:
        headers = _authenticated_admin_headers(client)
        response = client.post(
            f"/v1/admin/account-requests/{account_request_id}/approve", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "approved"
    assert response.headers["x-csrf-token"] == "v1.csrf-replacement"
    assert service.approve_calls == [account_request_id]


def test_admin_reject_sends_reason_and_requires_review_role() -> None:
    account_request_id = uuid4()
    service = FakeAccountRequestService()
    with make_client(
        account_service=service, admin_service=FakeAdminAuthService(role=AdminRole.AUDITOR)
    ) as client:
        headers = _authenticated_admin_headers(client)
        forbidden = client.post(
            f"/v1/admin/account-requests/{account_request_id}/reject",
            headers=headers,
            json={"reason": "not eligible"},
        )

    assert forbidden.status_code == 403
    assert service.reject_calls == []


def test_admin_reject_succeeds_for_operator() -> None:
    account_request_id = uuid4()
    service = FakeAccountRequestService()
    with make_client(
        account_service=service, admin_service=FakeAdminAuthService(role=AdminRole.OPERATOR)
    ) as client:
        headers = _authenticated_admin_headers(client)
        response = client.post(
            f"/v1/admin/account-requests/{account_request_id}/reject",
            headers=headers,
            json={"reason": "not eligible"},
        )

    assert response.status_code == 200
    assert response.json()["state"] == "rejected"
    assert service.reject_calls == [(account_request_id, "not eligible")]


def test_admin_approve_maps_domain_and_admin_auth_failures() -> None:
    account_request_id = uuid4()
    admin_service = FakeAdminAuthService()
    account_service = FakeAccountRequestService()
    with make_client(account_service=account_service, admin_service=admin_service) as client:
        headers = _authenticated_admin_headers(client)
        admin_service.error = AuthenticationRejected()
        denied = client.post(
            f"/v1/admin/account-requests/{account_request_id}/approve", headers=headers, json={}
        )

        headers = _authenticated_admin_headers(client)
        admin_service.error = None
        account_service.error = AccountRequestRejected("Request was not accepted")
        conflict = client.post(
            f"/v1/admin/account-requests/{account_request_id}/approve", headers=headers, json={}
        )

    assert denied.status_code == 401
    assert conflict.status_code == 400
