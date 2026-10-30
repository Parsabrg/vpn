"""HTTP-layer tests for the caller's own account and devices.

The service behind these routes is covered separately; what is pinned here is
the wiring the client actually depends on -- that every field the app renders
survives the trip out, that an unmetered account arrives as a null rather than
a number, and that a refusal keeps the status code it was given a distinct
code for.
"""

from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.account.routes import router
from nebula_api.account.service import (
    AccountEntry,
    AccountService,
    DeviceEntry,
    DeviceRevocationRefused,
)
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.auth.user_service import AuthenticatedUser, AuthenticationRejected, UserAuthService
from nebula_api.settings import Settings

USER_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")
OTHER_DEVICE_ID = UUID("44444444-4444-4444-8444-444444444444")
REGISTERED_AT = datetime(2026, 9, 1, 9, 30, tzinfo=UTC)
AUTH_HEADERS = {"Authorization": "Bearer valid-token"}
GIGABYTE = 1024**3


class FakeUserAuthService:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error

    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        if self.error is not None:
            raise self.error
        return AuthenticatedUser(user_id=USER_ID, session_id=SESSION_ID, device_id=DEVICE_ID)


def _entry(
    *,
    used_bytes: int = 3 * GIGABYTE,
    lifetime_bytes: int = 8 * GIGABYTE,
    quota_bytes: int | None = 10 * GIGABYTE,
    remaining_bytes: int | None = 7 * GIGABYTE,
    expires_at: datetime | None = None,
) -> AccountEntry:
    return AccountEntry(
        email="owner@example.org",
        username="parsa",
        state="active",
        device_limit=5,
        devices_in_use=2,
        expires_at=expires_at,
        used_bytes=used_bytes,
        lifetime_bytes=lifetime_bytes,
        quota_bytes=quota_bytes,
        remaining_bytes=remaining_bytes,
    )


_DEFAULT = cast(AccountEntry, object())


class FakeAccountService:
    def __init__(
        self,
        *,
        account: AccountEntry | None = _DEFAULT,
        devices: list[DeviceEntry] | None = None,
        revoke_error: Exception | None = None,
    ) -> None:
        # A sentinel rather than None, so a test can say "this user is gone"
        # and get a missing account instead of the default one.
        self.account = _entry() if account is _DEFAULT else account
        self.devices = devices if devices is not None else []
        self.revoke_error = revoke_error
        self.revoked: list[tuple[UUID, UUID, UUID]] = []

    async def get_account(self, _user_id: UUID) -> AccountEntry | None:
        return self.account

    async def list_devices(self, _user_id: UUID, _current_device_id: UUID) -> list[DeviceEntry]:
        return self.devices

    async def revoke_device(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        current_device_id: UUID,
        request_id: UUID,
    ) -> None:
        if self.revoke_error is not None:
            raise self.revoke_error
        self.revoked.append((user_id, device_id, current_device_id))


def make_client(
    account_service: FakeAccountService | None = None,
    user_auth_service: FakeUserAuthService | None = None,
    *,
    omit_account_service: bool = False,
) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.user_auth_service = cast(UserAuthService, user_auth_service or FakeUserAuthService())
    if not omit_account_service:
        app.state.account_service = cast(AccountService, account_service or FakeAccountService())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


class TestGetAccount:
    def test_requires_authentication(self) -> None:
        with make_client() as client:
            response = client.get("/v1/account")

        assert response.status_code == 401

    def test_a_rejected_token_does_not_reach_the_service(self) -> None:
        service = FakeAccountService()
        with make_client(
            service, FakeUserAuthService(error=AuthenticationRejected("expired"))
        ) as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.status_code == 401

    def test_returns_the_account_with_its_usage(self) -> None:
        with make_client() as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.status_code == 200
        body = response.json()
        assert body["email"] == "owner@example.org"
        assert body["device_limit"] == 5
        assert body["devices_in_use"] == 2
        assert body["used_bytes"] == 3 * GIGABYTE
        assert body["lifetime_bytes"] == 8 * GIGABYTE
        assert body["quota_bytes"] == 10 * GIGABYTE
        assert body["remaining_bytes"] == 7 * GIGABYTE

    def test_an_unmetered_account_reports_null_rather_than_a_large_number(self) -> None:
        # The client renders null as "no limit" and a number as an allowance.
        # A sentinel here would eventually be shown to somebody as GB left.
        service = FakeAccountService(
            account=_entry(used_bytes=GIGABYTE, quota_bytes=None, remaining_bytes=None)
        )
        with make_client(service) as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        body = response.json()
        assert body["used_bytes"] == GIGABYTE
        assert body["quota_bytes"] is None
        assert body["remaining_bytes"] is None

    def test_an_exhausted_allowance_reports_zero_left_not_a_negative(self) -> None:
        service = FakeAccountService(
            account=_entry(used_bytes=12 * GIGABYTE, quota_bytes=10 * GIGABYTE, remaining_bytes=0)
        )
        with make_client(service) as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.json()["remaining_bytes"] == 0

    def test_an_absent_expiry_stays_null(self) -> None:
        # Null means no expiry was set, which is not the same as an expiry
        # that has passed -- the client must not render "expired" for it.
        with make_client() as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.json()["expires_at"] is None

    def test_a_user_the_session_outlived_is_not_found(self) -> None:
        service = FakeAccountService(account=None)
        with make_client(service) as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.status_code == 404

    def test_an_unconfigured_service_is_unavailable_rather_than_a_crash(self) -> None:
        with make_client(omit_account_service=True) as client:
            response = client.get("/v1/account", headers=AUTH_HEADERS)

        assert response.status_code == 503


class TestListDevices:
    def test_requires_authentication(self) -> None:
        with make_client() as client:
            response = client.get("/v1/account/devices")

        assert response.status_code == 401

    def test_returns_each_device_and_marks_the_current_one(self) -> None:
        service = FakeAccountService(
            devices=[
                DeviceEntry(
                    id=DEVICE_ID,
                    name="Pixel",
                    platform="android",
                    state="active",
                    client_version="0.1.6",
                    registered_at=REGISTERED_AT,
                    is_current=True,
                    server_codes=["vps-1"],
                ),
                DeviceEntry(
                    id=OTHER_DEVICE_ID,
                    name="Laptop",
                    platform="android",
                    state="active",
                    client_version="0.1.5",
                    registered_at=REGISTERED_AT,
                    is_current=False,
                    server_codes=[],
                ),
            ]
        )
        with make_client(service) as client:
            response = client.get("/v1/account/devices", headers=AUTH_HEADERS)

        assert response.status_code == 200
        items = response.json()["items"]
        assert [item["id"] for item in items] == [str(DEVICE_ID), str(OTHER_DEVICE_ID)]
        assert [item["is_current"] for item in items] == [True, False]
        # An empty list is a real state -- registered, provisioned nothing --
        # and must not arrive as null.
        assert items[1]["server_codes"] == []

    def test_an_account_with_no_devices_returns_an_empty_list(self) -> None:
        with make_client() as client:
            response = client.get("/v1/account/devices", headers=AUTH_HEADERS)

        assert response.json() == {"items": []}


class TestRevokeDevice:
    def test_requires_authentication(self) -> None:
        with make_client() as client:
            response = client.post(f"/v1/account/devices/{OTHER_DEVICE_ID}/revoke")

        assert response.status_code == 401

    def test_revokes_and_returns_no_content(self) -> None:
        service = FakeAccountService()
        with make_client(service) as client:
            response = client.post(
                f"/v1/account/devices/{OTHER_DEVICE_ID}/revoke", headers=AUTH_HEADERS
            )

        assert response.status_code == 204
        assert service.revoked == [(USER_ID, OTHER_DEVICE_ID, DEVICE_ID)]

    def test_another_users_device_is_not_found_rather_than_forbidden(self) -> None:
        # 403 would confirm the device exists, which turns this route into a
        # way to probe for device ids on other accounts.
        service = FakeAccountService(revoke_error=DeviceRevocationRefused("not_found"))
        with make_client(service) as client:
            response = client.post(f"/v1/account/devices/{uuid4()}/revoke", headers=AUTH_HEADERS)

        assert response.status_code == 404

    def test_refusing_to_revoke_the_current_device_is_a_conflict(self) -> None:
        # This one the client can word, so it gets a code the client can tell
        # apart from "no such device".
        service = FakeAccountService(revoke_error=DeviceRevocationRefused("current_device"))
        with make_client(service) as client:
            response = client.post(f"/v1/account/devices/{DEVICE_ID}/revoke", headers=AUTH_HEADERS)

        assert response.status_code == 409
        assert response.json()["detail"] == "current_device"

    def test_a_malformed_device_id_is_rejected_before_the_service(self) -> None:
        service = FakeAccountService()
        with make_client(service) as client:
            response = client.post("/v1/account/devices/not-a-uuid/revoke", headers=AUTH_HEADERS)

        assert response.status_code == 422
        assert service.revoked == []
