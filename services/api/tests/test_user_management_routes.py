from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.models.types import AccountState, AdminRole, LifecycleState
from nebula_api.settings import Settings
from nebula_api.usage.service import AccountUsage, DeviceActivity, UsageService
from nebula_api.user_management.routes import _to_detail, router
from nebula_api.user_management.service import (
    DeviceSummary,
    UserDetail,
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
        dns_profile="default",
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
        self.granted: list[tuple[UUID, int | None]] = []
        self.device_limits: list[tuple[UUID, int]] = []
        self.dns_profiles: list[tuple[UUID, str]] = []
        self.device_dns_profiles: list[tuple[UUID, str | None]] = []
        self.limit_error: Exception | None = None
        self.expiries: list[tuple[UUID, datetime | None]] = []
        self.summary = user_summary()
        self.device_summary = DeviceSummary(
            id=DEVICE_ID,
            name="Laptop",
            platform="windows",
            client_version="1.0.0",
            state=LifecycleState.REVOKED,
            revoked_at=NOW,
            dns_profile=None,
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

    async def grant_traffic_quota(
        self,
        _usage: object,
        *,
        user_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
        quota_bytes: int | None,
    ) -> object:
        self.granted.append((user_id, quota_bytes))
        if self.error is not None:
            raise self.error
        return None

    async def set_dns_profile(self, *, user_id: UUID, dns_profile: str, **_kwargs: object) -> str:
        self.dns_profiles.append((user_id, dns_profile))
        return dns_profile

    async def set_device_dns_profile(
        self, *, user_id: UUID, device_id: UUID, dns_profile: str | None, **_kwargs: object
    ) -> str | None:
        self.device_dns_profiles.append((device_id, dns_profile))
        return dns_profile

    async def set_device_limit(self, *, user_id: UUID, device_limit: int, **_kwargs: object) -> int:
        if self.limit_error is not None:
            raise self.limit_error
        self.device_limits.append((user_id, device_limit))
        return device_limit

    async def set_expiry(
        self, *, user_id: UUID, expires_at: datetime | None, **_kwargs: object
    ) -> datetime | None:
        self.expiries.append((user_id, expires_at))
        return expires_at

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


class FakeUsageService:
    def __init__(self, usage: AccountUsage | None = None) -> None:
        self.usage = usage or AccountUsage(
            rx_bytes=3 * 1024**3,
            tx_bytes=1024**3,
            quota_bytes=100 * 1024**3,
            baseline_bytes=0,
        )
        self.activity: dict[UUID, DeviceActivity] = {}

    async def usage_for_user(self, _user_id: UUID) -> AccountUsage:
        return self.usage

    async def activity_for_devices(self, _device_ids: list[UUID]) -> dict[UUID, DeviceActivity]:
        return self.activity


def make_client(
    user_service: FakeUserManagementService | None = None,
    admin_service: FakeAdminAuthService | None = None,
    usage_service: FakeUsageService | None = None,
    *,
    omit_usage_service: bool = False,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.admin_auth_service = cast(AdminAuthService, admin_service or FakeAdminAuthService())
    app.state.user_management_service = cast(
        UserManagementService, user_service or FakeUserManagementService()
    )
    if not omit_usage_service:
        app.state.usage_service = cast(UsageService, usage_service or FakeUsageService())
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


def test_revoke_session_succeeds() -> None:
    service = FakeUserManagementService()
    with make_client(user_service=service) as client:
        headers = _authenticated_headers(client)
        response = client.post(
            f"/v1/admin/users/{USER_ID}/sessions/{uuid4()}/revoke", headers=headers, json={}
        )

    assert response.status_code == 200
    assert response.json()["state"] == "revoked"


GIGABYTE = 1024**3


def _quota_url(user_id: UUID = USER_ID) -> str:
    return f"/v1/admin/users/{user_id}/traffic-quota"


def _detail() -> UserDetail:
    return UserDetail(user=user_summary(), devices=[], sessions=[])


class TestGrantTrafficQuota:
    def test_grants_an_allowance_and_returns_the_new_figures(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(
                _quota_url(), json={"quota_bytes": 200 * GIGABYTE}, headers=headers
            )

        assert response.status_code == 200
        assert service.granted == [(USER_ID, 200 * GIGABYTE)]
        body = response.json()
        assert body["quota_bytes"] == 100 * GIGABYTE
        assert body["used_bytes"] == 4 * GIGABYTE

    def test_null_means_unmetered_rather_than_leave_it_alone(self) -> None:
        # The field is required and nullable precisely so these two cannot be
        # confused: absent would have to mean one of them.
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": None}, headers=headers)

        assert response.status_code == 200
        assert service.granted == [(USER_ID, None)]

    def test_zero_is_accepted_as_an_allowance_of_nothing(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": 0}, headers=headers)

        assert response.status_code == 200
        assert service.granted == [(USER_ID, 0)]

    def test_a_negative_allowance_is_refused(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": -1}, headers=headers)

        assert response.status_code == 422
        assert service.granted == []

    def test_an_omitted_field_is_refused_rather_than_guessed(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={}, headers=headers)

        assert response.status_code == 422
        assert service.granted == []

    def test_an_unknown_account_is_not_found(self) -> None:
        service = FakeUserManagementService()
        service.detail = None
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": GIGABYTE}, headers=headers)

        assert response.status_code == 404
        assert service.granted == []

    def test_requires_step_up(self) -> None:
        # Granting traffic decides whether somebody can use the service, the
        # same as disabling an account.
        with make_client(admin_service=FakeAdminAuthService(step_up=False)) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": GIGABYTE}, headers=headers)

        assert response.status_code == 403

    def test_rejects_an_auditor(self) -> None:
        with make_client(admin_service=FakeAdminAuthService(role=AdminRole.AUDITOR)) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": GIGABYTE}, headers=headers)

        assert response.status_code == 403

    def test_is_unavailable_without_traffic_accounting(self) -> None:
        # Granting reads what has been used to set the new baseline. Without
        # that, a grant would silently start the new allowance from zero.
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service, omit_usage_service=True) as client:
            headers = _authenticated_headers(client)
            response = client.post(_quota_url(), json={"quota_bytes": GIGABYTE}, headers=headers)

        assert response.status_code == 503


def test_user_detail_reports_the_allowance() -> None:
    service = FakeUserManagementService()
    service.detail = _detail()
    with make_client(user_service=service) as client:
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
        response = client.get(f"/v1/admin/users/{USER_ID}")

    traffic = response.json()["traffic"]
    assert traffic["used_bytes"] == 4 * GIGABYTE
    assert traffic["quota_bytes"] == 100 * GIGABYTE
    assert traffic["remaining_bytes"] == 96 * GIGABYTE
    assert traffic["exhausted_at"] is None


class TestDnsProfile:
    def test_sets_the_accounts_profile(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(
                f"/v1/admin/users/{USER_ID}/dns-profile",
                json={"dns_profile": "family"},
                headers=headers,
            )

        assert response.status_code == 200
        assert service.dns_profiles == [(USER_ID, "family")]

    def test_an_unknown_profile_is_refused(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(
                f"/v1/admin/users/{USER_ID}/dns-profile",
                json={"dns_profile": "everything"},
                headers=headers,
            )

        assert response.status_code == 422
        assert service.dns_profiles == []

    def _device_profile(self, value: str | None) -> tuple[int, FakeUserManagementService]:
        service = FakeUserManagementService()
        service.detail = UserDetail(
            user=user_summary(), devices=[service.device_summary], sessions=[]
        )
        with make_client(user_service=service) as client:
            response = client.post(
                f"/v1/admin/users/{USER_ID}/devices/{DEVICE_ID}/dns-profile",
                json={"dns_profile": value},
                headers=_authenticated_headers(client),
            )
        return response.status_code, service

    def test_a_device_gets_its_own_profile(self) -> None:
        status_code, service = self._device_profile("ads")
        assert status_code == 200
        assert service.device_dns_profiles == [(DEVICE_ID, "ads")]

    def test_a_device_follows_its_account_again_with_null(self) -> None:
        status_code, service = self._device_profile(None)
        assert status_code == 200
        assert service.device_dns_profiles == [(DEVICE_ID, None)]


def _limit_url(user_id: UUID = USER_ID) -> str:
    return f"/v1/admin/users/{user_id}/device-limit"


class TestSetDeviceLimit:
    def test_sets_the_limit(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_limit_url(), json={"device_limit": 5}, headers=headers)

        assert response.status_code == 200
        assert service.device_limits == [(USER_ID, 5)]

    def test_zero_is_refused(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_limit_url(), json={"device_limit": 0}, headers=headers)

        assert response.status_code == 422
        assert service.device_limits == []

    def test_an_unknown_account_is_not_found(self) -> None:
        service = FakeUserManagementService()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_limit_url(), json={"device_limit": 2}, headers=headers)

        assert response.status_code == 404
        assert service.device_limits == []

    def test_requires_step_up(self) -> None:
        with make_client(admin_service=FakeAdminAuthService(step_up=False)) as client:
            headers = _authenticated_headers(client)
            response = client.post(_limit_url(), json={"device_limit": 2}, headers=headers)

        assert response.status_code == 403

    def test_maps_a_domain_rejection(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        service.limit_error = UserManagementRejected("Request was not accepted")
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_limit_url(), json={"device_limit": 2}, headers=headers)

        assert response.status_code == 400


def _expiry_url(user_id: UUID = USER_ID) -> str:
    return f"/v1/admin/users/{user_id}/expiry"


class TestSetExpiry:
    def test_sets_a_date(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(
                _expiry_url(), json={"expires_at": "2027-01-01T00:00:00Z"}, headers=headers
            )

        assert response.status_code == 200
        assert service.expiries == [(USER_ID, datetime(2027, 1, 1, tzinfo=UTC))]

    def test_null_means_never(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_expiry_url(), json={"expires_at": None}, headers=headers)

        assert response.status_code == 200
        assert service.expiries == [(USER_ID, None)]

    def test_a_date_without_a_time_zone_is_refused(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(
                _expiry_url(), json={"expires_at": "2027-01-01T00:00:00"}, headers=headers
            )

        assert response.status_code == 422
        assert service.expiries == []

    def test_an_omitted_field_is_refused(self) -> None:
        service = FakeUserManagementService()
        service.detail = _detail()
        with make_client(user_service=service) as client:
            headers = _authenticated_headers(client)
            response = client.post(_expiry_url(), json={}, headers=headers)

        assert response.status_code == 422

    def test_an_unknown_account_is_not_found(self) -> None:
        with make_client() as client:
            headers = _authenticated_headers(client)
            response = client.post(_expiry_url(), json={"expires_at": None}, headers=headers)

        assert response.status_code == 404

    def test_requires_step_up(self) -> None:
        with make_client(admin_service=FakeAdminAuthService(step_up=False)) as client:
            headers = _authenticated_headers(client)
            response = client.post(_expiry_url(), json={"expires_at": None}, headers=headers)

        assert response.status_code == 403


class TestOnlineStatus:
    """Said from evidence: a status with no recent counter read is "unknown"."""

    def _device(self) -> DeviceSummary:
        return DeviceSummary(
            id=DEVICE_ID,
            name="Phone",
            platform="android",
            client_version="1.0.0",
            state=LifecycleState.ACTIVE,
            revoked_at=None,
            dns_profile=None,
        )

    def _status(self, activity: DeviceActivity | None) -> dict[str, object]:
        detail = UserDetail(user=user_summary(), devices=[self._device()], sessions=[])
        usage = FakeUsageService().usage
        response = _to_detail(detail, usage, {DEVICE_ID: activity} if activity else {}, now=NOW)
        return response.devices[0].model_dump()

    def test_traffic_in_the_last_two_minutes_is_active(self) -> None:
        item = self._status(
            DeviceActivity(
                tunnel_active_at=NOW - timedelta(seconds=30),
                tunnel_checked_at=NOW - timedelta(seconds=10),
            )
        )
        assert item["activity"] == "active"

    def test_fresh_counters_that_did_not_move_are_quiet(self) -> None:
        item = self._status(
            DeviceActivity(
                tunnel_active_at=NOW - timedelta(hours=3),
                tunnel_checked_at=NOW - timedelta(seconds=10),
            )
        )
        assert item["activity"] == "quiet"
        assert item["tunnel_active_at"] == NOW - timedelta(hours=3)

    def test_stale_counters_say_unknown_even_after_recent_traffic(self) -> None:
        # Traffic five minutes ago with no read since says nothing about now.
        item = self._status(
            DeviceActivity(
                tunnel_active_at=NOW - timedelta(minutes=5),
                tunnel_checked_at=NOW - timedelta(minutes=5),
            )
        )
        assert item["activity"] == "unknown"

    def test_no_tunnel_evidence_is_unknown(self) -> None:
        assert self._status(None)["activity"] == "unknown"

    def test_app_seen_is_the_latest_session_of_that_device(self) -> None:
        sessions = [
            UserSessionSummary(
                id=uuid4(),
                device_id=DEVICE_ID,
                state=LifecycleState.ACTIVE,
                expires_at=NOW,
                last_seen_at=NOW - timedelta(minutes=minutes),
                revoked_at=None,
            )
            for minutes in (30, 2, 90)
        ]
        detail = UserDetail(user=user_summary(), devices=[self._device()], sessions=sessions)
        response = _to_detail(detail, FakeUsageService().usage, {}, now=NOW)

        assert response.devices[0].app_seen_at == NOW - timedelta(minutes=2)

    def test_the_detail_route_carries_it(self) -> None:
        service = FakeUserManagementService()
        service.detail = UserDetail(user=user_summary(), devices=[self._device()], sessions=[])
        usage = FakeUsageService()
        with make_client(user_service=service, usage_service=usage) as client:
            client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session-canary")
            response = client.get(f"/v1/admin/users/{USER_ID}")

        assert response.json()["devices"][0]["activity"] == "unknown"
