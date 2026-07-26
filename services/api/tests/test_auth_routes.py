from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import (
    AdminAuthentication,
    AdminAuthService,
    AdminEnrollment,
    AdminPasswordChallenge,
    AdminPrincipal,
)
from nebula_api.auth.redis_state import (
    AdminSessionRecord,
    AuthStateUnavailable,
    IssuedAdminSession,
)
from nebula_api.auth.schemas import PasswordResetConfirmRequest, RefreshRequest, UserLoginRequest
from nebula_api.auth.user_service import (
    AuthenticatedUser,
    AuthenticationRateLimited,
    AuthenticationRejected,
    PasswordResetDelivery,
    PasswordResetIssue,
    UserAuthService,
    UserTokenPair,
)
from nebula_api.main import create_app
from nebula_api.models.types import AdminRole, DevicePlatform
from nebula_api.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
USER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
DEVICE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SESSION_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
ADMIN_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
ADMIN_SESSION_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
ORIGIN = "http://localhost:3000"


async def ready() -> bool:
    return True


class FakeUserAuthService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.reset_issue: PasswordResetIssue | None = None

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    async def login(self, **_kwargs: object) -> UserTokenPair:
        self._raise_if_needed()
        return UserTokenPair("access-canary", "refresh-canary", 900)

    async def refresh(self, **_kwargs: object) -> UserTokenPair:
        self._raise_if_needed()
        return UserTokenPair("access-rotated", "refresh-rotated", 900)

    async def logout(self, **_kwargs: object) -> None:
        self._raise_if_needed()

    async def authenticate_access_token(self, _token: str) -> AuthenticatedUser:
        self._raise_if_needed()
        return AuthenticatedUser(USER_ID, SESSION_ID, DEVICE_ID)

    async def request_password_reset(self, **_kwargs: object) -> PasswordResetIssue | None:
        self._raise_if_needed()
        return self.reset_issue

    async def confirm_password_reset(self, **_kwargs: object) -> None:
        self._raise_if_needed()


class FakeAdminAuthService:
    def __init__(self) -> None:
        self.error: Exception | None = None
        self.action_error: Exception | None = None
        self.step_up_state = False
        self.logged_out = False

    def _raise_if_needed(self) -> None:
        if self.error is not None:
            raise self.error

    def authentication(self, *, stepped_up: bool = False) -> AdminAuthentication:
        record = AdminSessionRecord(
            admin_id=ADMIN_ID,
            session_id=ADMIN_SESSION_ID,
            mfa_method="totp",
            created_at=NOW,
            last_seen_at=NOW,
            absolute_expires_at=NOW + timedelta(hours=8),
            step_up_at=NOW if stepped_up else None,
        )
        return AdminAuthentication(
            session=IssuedAdminSession("v1.session-canary", "v1.csrf-canary", record),
            recovery_codes=("v1.recovery-one", "v1.recovery-two"),
        )

    async def password_challenge(self, **_kwargs: object) -> AdminPasswordChallenge:
        self._raise_if_needed()
        return AdminPasswordChallenge("v1.challenge-canary", "enroll", 300)

    async def start_enrollment(self, **_kwargs: object) -> AdminEnrollment:
        self._raise_if_needed()
        return AdminEnrollment(
            "v1.confirm-canary",
            300,
            "BASE32CANARY",
            "otpauth://totp/Nebula%3Aowner?secret=BASE32CANARY",
        )

    async def confirm_enrollment(self, **_kwargs: object) -> AdminAuthentication:
        self._raise_if_needed()
        return self.authentication()

    async def verify_mfa(self, **_kwargs: object) -> AdminAuthentication:
        self._raise_if_needed()
        return self.authentication()

    async def principal(self, _session_token: str) -> AdminPrincipal:
        self._raise_if_needed()
        return AdminPrincipal(
            ADMIN_ID,
            ADMIN_SESSION_ID,
            AdminRole.OWNER,
            self.step_up_state,
            "totp",
        )

    async def validate_and_rotate_csrf(self, _session: str, _csrf: str) -> str:
        self._raise_if_needed()
        return "v1.csrf-replacement"

    async def step_up(self, **_kwargs: object) -> AdminAuthentication:
        self._raise_if_needed()
        if self.action_error is not None:
            raise self.action_error
        self.step_up_state = True
        return self.authentication(stepped_up=True)

    async def logout(self, _session_token: str, **_kwargs: object) -> None:
        self._raise_if_needed()
        if self.action_error is not None:
            raise self.action_error
        self.logged_out = True

    async def rotate_recovery_codes(self, **_kwargs: object) -> tuple[str, ...]:
        self._raise_if_needed()
        if self.action_error is not None:
            raise self.action_error
        return ("v1.new-one", "v1.new-two")


class RecordingPasswordResetDelivery:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, UUID]] = []
        self.error: Exception | None = None

    async def __call__(self, *, recipient: str, token: str, delivery_id: UUID) -> None:
        self.calls.append((recipient, token, delivery_id))
        if self.error is not None:
            raise self.error


def make_client(
    user_service: FakeUserAuthService | None = None,
    admin_service: FakeAdminAuthService | None = None,
    *,
    settings: Settings | None = None,
    password_reset_delivery: PasswordResetDelivery | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            settings or Settings(env="test"),
            readiness_check=ready,
            user_auth_service=cast(UserAuthService, user_service or FakeUserAuthService()),
            admin_auth_service=cast(AdminAuthService, admin_service or FakeAdminAuthService()),
            password_reset_delivery=password_reset_delivery,
        )
    )


def test_user_login_refresh_me_logout_and_reset_contracts() -> None:
    with make_client() as client:
        login = client.post(
            "/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "long-password-canary",
                "device_name": "Windows laptop",
                "platform": "windows",
                "client_version": "1.0.0",
            },
        )
        refresh = client.post(
            "/v1/auth/refresh",
            json={"refresh_token": login.json()["refresh_token"]},
        )
        me = client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {refresh.json()['access_token']}"},
        )
        logout = client.post(
            "/v1/auth/logout",
            json={"refresh_token": refresh.json()["refresh_token"]},
        )
        reset_request = client.post(
            "/v1/auth/password-reset/request",
            json={"identifier": "user@example.com"},
        )
        reset_confirm = client.post(
            "/v1/auth/password-reset/confirm",
            json={"token": "v1.reset-canary", "new_password": "new-password-canary"},
        )

    assert login.status_code == refresh.status_code == me.status_code == 200
    assert login.json()["token_type"] == "Bearer"  # noqa: S105 - public token type
    assert me.json() == {
        "user_id": str(USER_ID),
        "session_id": str(SESSION_ID),
        "device_id": str(DEVICE_ID),
    }
    assert logout.status_code == reset_confirm.status_code == 204
    assert reset_request.status_code == 202
    for response in (login, refresh, me, logout, reset_request, reset_confirm):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"


def test_user_auth_rejects_wrong_media_bearer_and_redacts_validation_input() -> None:
    canary = "submitted-password-must-not-return"
    with make_client() as client:
        wrong_media = client.post(
            "/v1/auth/login",
            content="identifier=user@example.com",
            headers={"Content-Type": "text/plain"},
        )
        wrong_bearer = client.get(
            "/v1/auth/me",
            headers={"Authorization": "Basic credential-canary"},
        )
        invalid = client.post(
            "/v1/auth/login",
            json={"identifier": "user@example.com", "password": canary},
        )

    assert wrong_media.status_code == 422  # model validation occurs before the route guard
    assert wrong_bearer.status_code == 401
    assert invalid.status_code == 422
    assert canary not in invalid.text
    assert "credential-canary" not in wrong_bearer.text


def test_secret_request_fields_preserve_exact_whitespace() -> None:
    password = "  exact-password-canary  "  # noqa: S105 - test fixture
    opaque_token = "  v1.token-canary  "  # noqa: S105 - test fixture

    login = UserLoginRequest(
        identifier=" user@example.com ",
        password=password,
        device_name="Laptop",
        platform=DevicePlatform.WINDOWS,
        client_version="1.0",
    )
    reset = PasswordResetConfirmRequest(token=opaque_token, new_password=password)
    refresh = RefreshRequest(refresh_token=opaque_token)

    assert login.password.get_secret_value() == password
    assert reset.new_password.get_secret_value() == password
    assert reset.token.get_secret_value() == opaque_token
    assert refresh.refresh_token.get_secret_value() == opaque_token


def test_password_request_fields_reject_oversized_utf8_without_reflection() -> None:
    canary = "密" * 400
    with make_client() as client:
        user = client.post(
            "/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": canary,
                "device_name": "Phone",
                "platform": "android",
                "client_version": "1.0",
            },
        )
        admin = client.post(
            "/v1/admin/auth/login",
            headers={"Origin": ORIGIN},
            json={"identifier": "owner@example.com", "password": canary},
        )
        reset = client.post(
            "/v1/auth/password-reset/confirm",
            json={"token": "v1.reset-canary", "new_password": canary},
        )

    assert user.status_code == admin.status_code == reset.status_code == 422
    assert all(canary not in response.text for response in (user, admin, reset))


def test_user_auth_failures_are_generic_and_no_store() -> None:
    service = FakeUserAuthService()
    service.error = AuthenticationRejected("internal reason canary")
    with make_client(service) as client:
        response = client.post(
            "/v1/auth/login",
            json={
                "identifier": "unknown@example.com",
                "password": "wrong-password-canary",
                "device_name": "Phone",
                "platform": "android",
                "client_version": "1.0.0",
            },
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication was not accepted"}
    assert "internal reason canary" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_missing_user_and_admin_auth_services_fail_closed() -> None:
    application = create_app(Settings(env="test"), readiness_check=ready)
    with TestClient(application) as client:
        user = client.post(
            "/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "password-canary",
                "device_name": "Phone",
                "platform": "android",
                "client_version": "1.0.0",
            },
        )
        admin = client.post(
            "/v1/admin/auth/login",
            headers={"Origin": ORIGIN},
            json={"identifier": "owner@example.com", "password": "password-canary"},
        )

    for response in (user, admin):
        assert response.status_code == 503
        assert response.json() == {"detail": "Authentication is temporarily unavailable"}
        assert response.headers["cache-control"] == "no-store"


def test_user_route_failures_cover_rate_limit_state_and_endpoint_guards() -> None:
    service = FakeUserAuthService()
    login_payload = {
        "identifier": "user@example.com",
        "password": "password-canary",
        "device_name": "Phone",
        "platform": "android",
        "client_version": "1.0.0",
    }
    with make_client(service) as client:
        service.error = AuthenticationRateLimited(17)
        limited_login = client.post("/v1/auth/login", json=login_payload)

        service.error = AuthenticationRejected()
        rejected_refresh = client.post(
            "/v1/auth/refresh", json={"refresh_token": "v1.refresh-canary"}
        )

        service.error = AuthStateUnavailable()
        unavailable_logout = client.post(
            "/v1/auth/logout", json={"refresh_token": "v1.refresh-canary"}
        )
        unavailable_me = client.get(
            "/v1/auth/me", headers={"Authorization": "Bearer access-canary"}
        )

        service.error = AuthenticationRateLimited(23)
        limited_reset = client.post(
            "/v1/auth/password-reset/request", json={"identifier": "user@example.com"}
        )

        service.error = AuthStateUnavailable()
        neutral_reset = client.post(
            "/v1/auth/password-reset/request", json={"identifier": "user@example.com"}
        )

        service.error = AuthenticationRejected()
        rejected_confirm = client.post(
            "/v1/auth/password-reset/confirm",
            json={"token": "v1.reset-canary", "new_password": "new-password-canary"},
        )

    assert limited_login.status_code == 429
    assert limited_login.headers["retry-after"] == "17"
    assert rejected_refresh.status_code == 401
    assert rejected_refresh.headers["www-authenticate"] == "Bearer"
    assert unavailable_logout.status_code == unavailable_me.status_code == 503
    assert limited_reset.status_code == 429
    assert limited_reset.headers["retry-after"] == "23"
    assert neutral_reset.status_code == 202
    assert neutral_reset.json() == {"status": "accepted"}
    assert rejected_confirm.status_code == 401


def test_password_reset_delivery_success_and_failure_remain_neutral() -> None:
    delivery_id = UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
    service = FakeUserAuthService()
    service.reset_issue = PasswordResetIssue(
        "user@example.com",
        "v1.reset-delivery-canary",
        delivery_id,
    )
    dispatcher = RecordingPasswordResetDelivery()
    with make_client(
        service,
        password_reset_delivery=cast(PasswordResetDelivery, dispatcher),
    ) as client:
        delivered = client.post(
            "/v1/auth/password-reset/request", json={"identifier": "user@example.com"}
        )
        dispatcher.error = RuntimeError("delivery transport failed")
        delivery_failed = client.post(
            "/v1/auth/password-reset/request", json={"identifier": "user@example.com"}
        )

    assert delivered.status_code == delivery_failed.status_code == 202
    assert dispatcher.calls == [
        ("user@example.com", "v1.reset-delivery-canary", delivery_id),
        ("user@example.com", "v1.reset-delivery-canary", delivery_id),
    ]
    assert "v1.reset-delivery-canary" not in delivered.text
    assert "v1.reset-delivery-canary" not in delivery_failed.text


def test_admin_login_requires_exact_origin_and_enrollment_is_secret_safe() -> None:
    with make_client() as client:
        denied = client.post(
            "/v1/admin/auth/login",
            json={"identifier": "owner@example.com", "password": "password-canary"},
        )
        login = client.post(
            "/v1/admin/auth/login",
            headers={"Origin": ORIGIN},
            json={"identifier": "owner@example.com", "password": "password-canary"},
        )
        enrollment = client.post(
            "/v1/admin/auth/mfa/enrollment",
            headers={"Origin": ORIGIN},
            json={"challenge": login.json()["challenge"]},
        )

    assert denied.status_code == 403
    assert login.status_code == 200
    assert login.json()["next_step"] == "enroll"
    assert enrollment.status_code == 200
    assert enrollment.json()["secret"] == "BASE32CANARY"  # noqa: S105 - test fixture
    assert "password-canary" not in login.text


def test_admin_mfa_sets_strict_cookies_and_session_realms_remain_separate() -> None:
    settings = Settings(env="staging", allowed_origins=ORIGIN)
    with make_client(settings=settings) as client:
        response = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={
                "challenge": "v1.challenge-canary",
                "code": "123456",
                "method": "totp",
            },
        )

    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(item for item in cookies if "__Host-nebula_admin=" in item)
    csrf_cookie = next(item for item in cookies if "__Host-nebula_csrf=" in item)
    assert response.status_code == 200
    assert "HttpOnly" in session_cookie
    assert "HttpOnly" not in csrf_cookie
    assert "Secure" in session_cookie and "SameSite=strict" in session_cookie
    assert response.headers["x-csrf-token"] == "v1.csrf-canary"


def test_admin_enrollment_confirmation_and_current_session_success() -> None:
    with make_client() as client:
        confirmed = client.post(
            "/v1/admin/auth/mfa/enrollment/confirm",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.confirm-canary", "code": "123456"},
        )
        current = client.get("/v1/admin/auth/session")

    assert confirmed.status_code == 200
    assert confirmed.json() == {
        "admin_id": str(ADMIN_ID),
        "role": "owner",
        "csrf_token": "v1.csrf-canary",
        "step_up": False,
        "recovery_codes": ["v1.recovery-one", "v1.recovery-two"],
    }
    assert current.status_code == 200
    assert current.json() == {
        "admin_id": str(ADMIN_ID),
        "role": "owner",
        "csrf_token": None,
        "step_up": False,
    }


def test_admin_route_failures_map_rate_limit_state_and_rejections() -> None:
    service = FakeAdminAuthService()
    with make_client(admin_service=service) as client:
        service.error = AuthenticationRateLimited(19)
        limited_login = client.post(
            "/v1/admin/auth/login",
            headers={"Origin": ORIGIN},
            json={"identifier": "owner@example.com", "password": "password-canary"},
        )

        service.error = AuthenticationRejected()
        rejected_enrollment = client.post(
            "/v1/admin/auth/mfa/enrollment",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge-canary"},
        )

        service.error = AuthStateUnavailable()
        unavailable_confirmation = client.post(
            "/v1/admin/auth/mfa/enrollment/confirm",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.confirm-canary", "code": "123456"},
        )

        service.error = AuthenticationRejected()
        rejected_mfa = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge-canary", "code": "123456", "method": "totp"},
        )

        service.error = None
        authenticated = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge-canary", "code": "123456", "method": "totp"},
        )
        csrf = authenticated.headers["x-csrf-token"]

        service.error = AuthStateUnavailable()
        unavailable_session = client.get("/v1/admin/auth/session")
        unavailable_step_up = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"code": "654321", "method": "totp"},
        )

        service.error = AuthenticationRejected()
        rejected_logout = client.post(
            "/v1/admin/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={},
        )
        rejected_recovery = client.post(
            "/v1/admin/auth/recovery-codes/rotate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={},
        )

    assert limited_login.status_code == 429
    assert limited_login.headers["retry-after"] == "19"
    assert rejected_enrollment.status_code == rejected_mfa.status_code == 401
    assert unavailable_confirmation.status_code == unavailable_session.status_code == 503
    assert unavailable_step_up.status_code == 503
    assert rejected_logout.status_code == rejected_recovery.status_code == 401


def test_admin_csrf_requires_header_cookie_match_on_every_mutation() -> None:
    settings = Settings(env="test")
    with make_client(settings=settings) as client:
        authenticated = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge-canary", "code": "123456", "method": "totp"},
        )
        csrf = authenticated.headers["x-csrf-token"]

        client.cookies.delete(settings.admin_csrf_cookie_name)
        missing_cookie = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"code": "654321", "method": "totp"},
        )

        client.cookies.set(settings.admin_csrf_cookie_name, csrf)
        mismatched = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "v1.different-canary"},
            json={"code": "654321", "method": "totp"},
        )

    assert missing_cookie.status_code == mismatched.status_code == 401


def test_admin_csrf_rotation_step_up_recovery_rotation_and_logout() -> None:
    service = FakeAdminAuthService()
    with make_client(admin_service=service) as client:
        authenticated = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge", "code": "123456", "method": "totp"},
        )
        csrf = authenticated.headers["x-csrf-token"]
        missing_csrf = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN},
            json={"code": "654321", "method": "totp"},
        )
        stepped_up = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
            json={"code": "654321", "method": "totp"},
        )
        rotated_csrf = stepped_up.headers["x-csrf-token"]
        recovery = client.post(
            "/v1/admin/auth/recovery-codes/rotate",
            headers={"Origin": ORIGIN, "X-CSRF-Token": rotated_csrf},
            json={},
        )
        logout_csrf = recovery.headers["x-csrf-token"]
        logout = client.post(
            "/v1/admin/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": logout_csrf},
            json={},
        )

    assert missing_csrf.status_code == 401
    assert stepped_up.status_code == 200 and stepped_up.json()["step_up"]
    assert recovery.json()["recovery_codes"] == ["v1.new-one", "v1.new-two"]
    assert logout.status_code == 204 and service.logged_out
    assert "Max-Age=0" in " ".join(logout.headers.get_list("set-cookie"))


def test_failed_admin_mutation_returns_consumed_csrf_replacement() -> None:
    service = FakeAdminAuthService()
    service.action_error = AuthenticationRejected()
    with make_client(admin_service=service) as client:
        authenticated = client.post(
            "/v1/admin/auth/mfa/verify",
            headers={"Origin": ORIGIN},
            json={"challenge": "v1.challenge", "code": "123456", "method": "totp"},
        )
        failed = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": authenticated.headers["x-csrf-token"]},
            json={"code": "654321", "method": "totp"},
        )

        assert failed.status_code == 401
        assert failed.headers["x-csrf-token"] == "v1.csrf-replacement"
        assert client.cookies.get(Settings(env="test").admin_csrf_cookie_name) == (
            "v1.csrf-replacement"
        )

        service.action_error = None
        retried = client.post(
            "/v1/admin/auth/step-up",
            headers={"Origin": ORIGIN, "X-CSRF-Token": failed.headers["x-csrf-token"]},
            json={"code": "654321", "method": "totp"},
        )

    assert retried.status_code == 200


def test_admin_session_endpoint_rejects_user_bearer_without_admin_cookie() -> None:
    with make_client() as client:
        response = client.get(
            "/v1/admin/auth/session",
            headers={"Authorization": "Bearer user-access-canary"},
        )

    assert response.status_code == 401
    assert "user-access-canary" not in response.text
