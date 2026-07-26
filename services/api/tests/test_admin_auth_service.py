import asyncio
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession

import nebula_api.auth.admin_service as admin_service_module
from nebula_api.auth.admin_service import AdminAuthService
from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.mfa import encrypt_mfa_seed, totp_at_counter
from nebula_api.auth.opaque_tokens import digest_opaque_token
from nebula_api.auth.redis_state import (
    AdminSessionRecord,
    ConsumedPreAuth,
    IssuedAdminSession,
    LockoutState,
    PreAuthChallenge,
    RateBucket,
    RedisAuthState,
)
from nebula_api.auth.user_service import AuthenticationRateLimited, AuthenticationRejected
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import AdminMfaRecoveryCode, AdminTotpCredential, AdminUser
from nebula_api.models.operations import AuditLog
from nebula_api.models.types import AdminRole, AdminState
from nebula_api.passwords import hash_password
from nebula_api.settings import Settings

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
ADMIN_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
CREDENTIAL_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SESSION_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
PASSWORD = "correct-admin-password"  # noqa: S105 - test fixture
SEED = b"12345678901234567890"


class ScalarRows:
    def __init__(self, values: Iterable[object]) -> None:
        self.values = list(values)

    def all(self) -> list[object]:
        return self.values


class ScriptedSession:
    def __init__(
        self,
        *,
        scalar_values: Iterable[object] = (),
        scalars_values: Iterable[Iterable[object]] = (),
        fail_commit: bool = False,
    ) -> None:
        self.scalar_values = list(scalar_values)
        self.scalars_values = [list(value) for value in scalars_values]
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0
        self.fail_commit = fail_commit

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        if not self.scalar_values:
            raise AssertionError("unexpected scalar query")
        return self.scalar_values.pop(0)

    async def scalars(self, _statement: object) -> ScalarRows:
        if not self.scalars_values:
            raise AssertionError("unexpected scalars query")
        return ScalarRows(self.scalars_values.pop(0))

    async def execute(self, statement: object) -> object:
        self.executed.append(statement)
        return object()

    def add(self, value: object) -> None:
        self.added.append(value)

    def add_all(self, values: Iterable[object]) -> None:
        self.added.extend(values)

    async def commit(self) -> None:
        self.commits += 1
        if self.fail_commit:
            raise RuntimeError("commit failed canary")


class ScriptedFactory:
    def __init__(self, *sessions: ScriptedSession) -> None:
        self.sessions = list(sessions)

    def __call__(self) -> ScriptedSession:
        if not self.sessions:
            raise AssertionError("unexpected database session")
        return self.sessions.pop(0)


class AdminRedis:
    def __init__(self) -> None:
        self.allowed = True
        self.locked = False
        self.challenge_admin_id = ADMIN_ID
        self.consume_available = True
        self.session_available = True
        self.csrf_available = True
        self.rotation_available = True
        self.revoked: list[str] = []
        self.cleared: list[str] = []
        self.failures = 0
        self.rate_calls: list[tuple[RateBucket, ...]] = []
        self.record = AdminSessionRecord(
            ADMIN_ID,
            SESSION_ID,
            "totp",
            NOW,
            NOW,
            NOW + timedelta(hours=8),
            None,
        )

    async def rate_limit(
        self,
        buckets: tuple[RateBucket, ...],
        *,
        limit: int,
        window_seconds: int,
    ) -> bool:
        assert buckets and limit > 0 and window_seconds > 0
        self.rate_calls.append(buckets)
        return self.allowed

    async def lockout_status(self, _account: str) -> LockoutState:
        return LockoutState(self.locked, 60 if self.locked else 0)

    async def record_admin_failure(
        self, _account: str, *, threshold: int, lock_seconds: int
    ) -> LockoutState:
        assert threshold > 1 and lock_seconds > 0
        self.failures += 1
        return LockoutState(self.failures >= threshold, lock_seconds)

    async def clear_admin_failures(self, account: str) -> None:
        self.cleared.append(account)

    async def issue_preauth(
        self,
        *,
        admin_id: UUID,
        purpose: Literal["login", "enroll", "step-up"],
        context: str,
        ttl_seconds: int,
    ) -> PreAuthChallenge:
        assert admin_id == ADMIN_ID and context and ttl_seconds > 0
        return PreAuthChallenge(f"v1.{purpose}-challenge", ttl_seconds)

    async def consume_preauth(
        self,
        _token: str,
        *,
        purpose: Literal["login", "enroll", "step-up"],
        context: str,
    ) -> ConsumedPreAuth | None:
        assert context
        return ConsumedPreAuth(self.challenge_admin_id, purpose) if self.consume_available else None

    async def issue_admin_session(
        self,
        *,
        admin_id: UUID,
        mfa_method: Literal["totp", "recovery"],
        idle_ttl: timedelta,
        absolute_ttl: timedelta,
        stepped_up: bool = False,
    ) -> IssuedAdminSession:
        assert idle_ttl < absolute_ttl
        self.record = AdminSessionRecord(
            admin_id,
            uuid4(),
            mfa_method,
            NOW,
            NOW,
            NOW + absolute_ttl,
            NOW if stepped_up else None,
        )
        return IssuedAdminSession("v1.session", "v1.csrf", self.record)

    async def get_admin_session(
        self, _token: str, *, idle_ttl: timedelta
    ) -> AdminSessionRecord | None:
        assert idle_ttl > timedelta(0)
        return self.record if self.session_available else None

    async def validate_and_rotate_csrf(
        self, _session: str, _csrf: str, *, idle_ttl: timedelta
    ) -> str | None:
        assert idle_ttl > timedelta(0)
        return "v1.csrf-next" if self.csrf_available else None

    async def rotate_admin_session(
        self, _token: str, *, idle_ttl: timedelta, stepped_up: bool
    ) -> IssuedAdminSession | None:
        if not self.rotation_available:
            return None
        return await self.issue_admin_session(
            admin_id=ADMIN_ID,
            mfa_method="totp",
            idle_ttl=idle_ttl,
            absolute_ttl=timedelta(hours=8),
            stepped_up=stepped_up,
        )

    async def revoke_admin_session(self, token: str) -> None:
        self.revoked.append(token)


def keys() -> AuthKeyMaterial:
    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32})


def admin(*, state: AdminState = AdminState.ACTIVE) -> AdminUser:
    return AdminUser(
        id=ADMIN_ID,
        email="owner@example.com",
        email_normalized="owner@example.com",
        username="owner",
        username_normalized="owner",
        password_hash=hash_password(PASSWORD),
        role=AdminRole.OWNER,
        state=state,
        disabled_at=NOW if state is AdminState.DISABLED else None,
    )


def credential(*, state: str = "active") -> AdminTotpCredential:
    envelope = encrypt_mfa_seed(
        SEED,
        admin_id=ADMIN_ID,
        credential_id=CREDENTIAL_ID,
        key_version=1,
        key_ring={1: b"m" * 32},
        random_bytes=lambda size: b"n" * size,
    )
    return AdminTotpCredential(
        id=CREDENTIAL_ID,
        admin_user_id=ADMIN_ID,
        state=state,
        secret_ciphertext=envelope.ciphertext,
        secret_nonce=envelope.nonce,
        key_version=1,
        confirmed_at=NOW - timedelta(days=1) if state == "active" else None,
    )


def current_code() -> str:
    return totp_at_counter(SEED, int(NOW.timestamp()) // 30)


def service(
    factory: ScriptedFactory,
    redis: AdminRedis | None = None,
    *,
    clock: Callable[[], datetime] = lambda: NOW,
) -> tuple[AdminAuthService, AdminRedis]:
    effective = redis or AdminRedis()
    instance = AdminAuthService(
        cast(SessionFactory, factory),
        cast(RedisAuthState, effective),
        keys(),
        Settings(env="test"),
        clock=clock,
    )
    return instance, effective


def test_password_challenge_is_not_a_session_and_routes_seeded_admin_to_enrollment() -> None:
    database = ScriptedSession(scalar_values=(admin(), None))
    auth, redis = service(ScriptedFactory(database))

    challenge = asyncio.run(
        auth.password_challenge(
            identifier="OWNER@example.com",
            password=PASSWORD,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert challenge.next_step == "enroll"
    assert challenge.token not in repr(challenge)
    assert database.commits == 1
    assert redis.cleared == []


def test_password_challenge_for_enrolled_admin_requires_mfa() -> None:
    database = ScriptedSession(scalar_values=(admin(), credential()))
    auth, _redis = service(ScriptedFactory(database))

    challenge = asyncio.run(
        auth.password_challenge(
            identifier="owner",
            password=PASSWORD,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert challenge.next_step == "mfa"


def test_unknown_admin_and_rate_limit_have_generic_failures_with_audit() -> None:
    denied_database = ScriptedSession(scalar_values=(None,))
    denied, redis = service(ScriptedFactory(denied_database))
    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            denied.password_challenge(
                identifier="missing@example.com",
                password="wrong-password",  # noqa: S106 - test fixture
                network_prefix="unknown",
                request_id=uuid4(),
            )
        )
    assert redis.failures == 1
    assert any(isinstance(value, AuditLog) for value in denied_database.added)

    limited_database = ScriptedSession(scalar_values=(admin(),))
    limited, limited_redis = service(ScriptedFactory(limited_database))
    limited_redis.allowed = False
    with pytest.raises(AuthenticationRateLimited):
        asyncio.run(
            limited.password_challenge(
                identifier="owner@example.com",
                password=PASSWORD,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert [bucket.namespace for bucket in limited_redis.rate_calls[0]] == [
        "admin-account",
        "admin-login-network",
    ]


def test_start_enrollment_persists_only_encrypted_seed_and_returns_secret_once() -> None:
    database = ScriptedSession(scalar_values=(admin(), None))
    auth, _redis = service(ScriptedFactory(database))

    enrollment = asyncio.run(
        auth.start_enrollment(
            challenge="v1.enroll",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    stored = next(value for value in database.added if isinstance(value, AdminTotpCredential))
    assert stored.secret_ciphertext is not None and SEED not in stored.secret_ciphertext
    assert enrollment.base32_secret not in repr(enrollment)
    assert enrollment.provisioning_uri.startswith("otpauth://totp/")
    assert database.executed and database.commits == 1


def test_confirm_enrollment_enforces_totp_and_returns_recovery_codes_once() -> None:
    pending = credential(state="pending")
    database = ScriptedSession(scalar_values=(admin(), pending))
    auth, redis = service(ScriptedFactory(database))

    result = asyncio.run(
        auth.confirm_enrollment(
            challenge="v1.confirm",
            code=current_code(),
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert pending.state == "active"
    assert pending.last_accepted_timestep == int(NOW.timestamp()) // 30
    assert len(result.recovery_codes) == 10
    assert result.recovery_codes[0] not in repr(result)
    assert len([value for value in database.added if isinstance(value, AdminMfaRecoveryCode)]) == 10
    assert redis.cleared == [str(ADMIN_ID)]


def test_invalid_enrollment_totp_records_failure_without_creating_session() -> None:
    database = ScriptedSession(scalar_values=(admin(), credential(state="pending")))
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            auth.confirm_enrollment(
                challenge="v1.confirm",
                code="000000",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.failures == 1
    assert database.commits == 1


def test_mfa_login_updates_durable_replay_counter_and_creates_fresh_session() -> None:
    active = credential()
    database = ScriptedSession(scalar_values=(admin(), active))
    auth, redis = service(ScriptedFactory(database))

    result = asyncio.run(
        auth.verify_mfa(
            challenge="v1.login",
            code=current_code(),
            method="totp",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert active.last_accepted_timestep == int(NOW.timestamp()) // 30
    assert result.session.record.admin_id == ADMIN_ID
    assert redis.cleared == [str(ADMIN_ID)]
    assert [bucket.namespace for bucket in redis.rate_calls[-1]] == [
        "mfa-challenge",
        "admin-mfa-network",
    ]


def test_recovery_code_is_consumed_atomically_during_mfa_login() -> None:
    raw = "v1." + "R" * 43
    digest = digest_opaque_token(raw, {1: b"p" * 32}, namespace="mfa-recovery")
    recovery = AdminMfaRecoveryCode(
        id=uuid4(),
        admin_totp_credential_id=CREDENTIAL_ID,
        code_digest=digest.value,
        key_version=1,
        state="active",
    )
    database = ScriptedSession(scalar_values=(admin(), credential(), recovery))
    auth, _redis = service(ScriptedFactory(database))

    asyncio.run(
        auth.verify_mfa(
            challenge="v1.login",
            code=raw,
            method="recovery",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert recovery.state == "consumed" and recovery.consumed_at == NOW
    audit = next(
        value
        for value in database.added
        if isinstance(value, AuditLog) and value.event_code == "admin_recovery_code_used"
    )
    assert audit.target_kind == "admin_recovery_code" and audit.target_id == recovery.id


def test_principal_reloads_current_role_and_disabled_admin_revokes_redis_session() -> None:
    active_database = ScriptedSession(scalar_values=(admin(),))
    auth, _redis = service(ScriptedFactory(active_database))
    principal = asyncio.run(auth.principal("v1.session"))
    assert principal.role is AdminRole.OWNER and not principal.step_up

    disabled_database = ScriptedSession(scalar_values=(None,))
    disabled, redis = service(ScriptedFactory(disabled_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(disabled.principal("v1.session"))
    assert redis.revoked == ["v1.session"]


def test_csrf_step_up_rotates_session_and_makes_proof_fresh() -> None:
    principal_db = ScriptedSession(scalar_values=(admin(),))
    mutation_db = ScriptedSession(scalar_values=(admin(), credential()))
    auth, redis = service(ScriptedFactory(principal_db, mutation_db))

    assert asyncio.run(auth.validate_and_rotate_csrf("v1.session", "v1.csrf")) == "v1.csrf-next"
    result = asyncio.run(
        auth.step_up(
            session_token="v1.session",  # noqa: S106 - test fixture
            code=current_code(),
            method="totp",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert result.session.record.step_up_at == NOW
    assert redis.record.session_id != SESSION_ID
    assert redis.cleared == [str(ADMIN_ID)]
    assert [bucket.namespace for bucket in redis.rate_calls[-1]] == [
        "admin-step-up-account",
        "admin-step-up-network",
    ]


def test_logout_is_idempotent_and_audits_known_session() -> None:
    principal_db = ScriptedSession(scalar_values=(admin(),))
    audit_db = ScriptedSession()
    auth, redis = service(ScriptedFactory(principal_db, audit_db))

    asyncio.run(auth.logout("v1.session", request_id=uuid4()))

    assert redis.revoked == ["v1.session"]
    assert audit_db.commits == 1


def test_step_up_recovery_rotation_revokes_previous_generation() -> None:
    redis = AdminRedis()
    redis.record = AdminSessionRecord(
        ADMIN_ID,
        SESSION_ID,
        "totp",
        NOW,
        NOW,
        NOW + timedelta(hours=8),
        NOW,
    )
    principal_db = ScriptedSession(scalar_values=(admin(),))
    rotate_db = ScriptedSession(scalar_values=(credential(),))
    auth, _ = service(ScriptedFactory(principal_db, rotate_db), redis)

    codes = asyncio.run(
        auth.rotate_recovery_codes(
            session_token="v1.session",  # noqa: S106 - test fixture
            request_id=uuid4(),
        )
    )

    assert len(codes) == 10
    assert rotate_db.executed and rotate_db.commits == 1


def test_session_created_before_failed_commit_is_compensatingly_revoked() -> None:
    database = ScriptedSession(
        scalar_values=(admin(), credential()),
        fail_commit=True,
    )
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(RuntimeError, match="commit failed"):
        asyncio.run(
            auth.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.revoked == ["v1.session"]


def test_password_challenge_rehashes_an_outdated_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = admin()
    old_hash = existing.password_hash
    database = ScriptedSession(scalar_values=(existing, None))
    auth, _redis = service(ScriptedFactory(database))
    monkeypatch.setattr(admin_service_module, "password_hash_needs_rehash", lambda _hash: True)

    asyncio.run(
        auth.password_challenge(
            identifier="owner@example.com",
            password=PASSWORD,
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert existing.password_hash != old_hash


@pytest.mark.parametrize(
    ("state", "locked", "password"),
    [
        (AdminState.DISABLED, False, PASSWORD),
        (AdminState.ACTIVE, True, PASSWORD),
        (AdminState.ACTIVE, False, "incorrect-password"),
    ],
)
def test_password_challenge_rejects_every_ineligible_admin_condition(
    state: AdminState,
    locked: bool,
    password: str,
) -> None:
    database = ScriptedSession(scalar_values=(admin(state=state),))
    redis = AdminRedis()
    redis.locked = locked
    auth, _redis = service(ScriptedFactory(database), redis)

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.password_challenge(
                identifier="owner@example.com",
                password=password,
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.failures == 1


def test_password_failure_that_crosses_threshold_audits_lockout_transition() -> None:
    database = ScriptedSession(scalar_values=(admin(),))
    redis = AdminRedis()
    redis.failures = Settings(env="test").admin_lockout_threshold - 1
    auth, _redis = service(ScriptedFactory(database), redis)

    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            auth.password_challenge(
                identifier="owner@example.com",
                password="incorrect-password",  # noqa: S106 - test fixture
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    audit = next(value for value in database.added if isinstance(value, AuditLog))
    assert audit.event_code == "auth_lockout_changed"


def test_invalid_identifier_is_normalized_to_neutral_unknown_account() -> None:
    database = ScriptedSession(scalar_values=(None,))
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.password_challenge(
                identifier="not valid",
                password="incorrect-password",  # noqa: S106 - test fixture
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.failures == 1


def test_start_enrollment_rejects_missing_challenge_without_database_access() -> None:
    redis = AdminRedis()
    redis.consume_available = False
    auth, _redis = service(ScriptedFactory(), redis)

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.start_enrollment(
                challenge="v1.missing",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


@pytest.mark.parametrize(
    "scalar_values",
    [
        (None,),
        (admin(state=AdminState.DISABLED),),
        (admin(), credential()),
    ],
)
def test_start_enrollment_rejects_ineligible_admin_or_existing_active_credential(
    scalar_values: tuple[object, ...],
) -> None:
    database = ScriptedSession(scalar_values=scalar_values)
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.start_enrollment(
                challenge="v1.enroll",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


@pytest.mark.parametrize(
    "scalar_values",
    [(None, credential(state="pending")), (admin(), None)],
)
def test_confirm_enrollment_requires_active_admin_and_pending_credential(
    scalar_values: tuple[object, ...],
) -> None:
    database = ScriptedSession(scalar_values=scalar_values)
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.confirm_enrollment(
                challenge="v1.confirm",
                code=current_code(),
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_confirm_enrollment_revokes_new_session_when_commit_fails() -> None:
    database = ScriptedSession(
        scalar_values=(admin(), credential(state="pending")),
        fail_commit=True,
    )
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(RuntimeError, match="commit failed"):
        asyncio.run(
            auth.confirm_enrollment(
                challenge="v1.confirm",
                code=current_code(),
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.revoked == ["v1.session"]


@pytest.mark.parametrize(
    "scalar_values",
    [(None, credential()), (admin(), None)],
)
def test_mfa_login_requires_active_admin_and_credential(
    scalar_values: tuple[object, ...],
) -> None:
    database = ScriptedSession(scalar_values=scalar_values)
    auth, _redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_mfa_login_rejects_invalid_totp_and_records_denial() -> None:
    database = ScriptedSession(scalar_values=(admin(), credential()))
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.verify_mfa(
                challenge="v1.login",
                code="000000",
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.failures == 1 and database.commits == 1


def test_mfa_login_rejects_malformed_and_unknown_recovery_codes() -> None:
    malformed_database = ScriptedSession(scalar_values=(admin(), credential()))
    malformed, malformed_redis = service(ScriptedFactory(malformed_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            malformed.verify_mfa(
                challenge="v1.login",
                code="malformed",
                method="recovery",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert malformed_redis.failures == 1

    raw = "v1." + "U" * 43
    missing_database = ScriptedSession(scalar_values=(admin(), credential(), None))
    missing, missing_redis = service(ScriptedFactory(missing_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            missing.verify_mfa(
                challenge="v1.login",
                code=raw,
                method="recovery",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert missing_redis.failures == 1


@pytest.mark.parametrize("missing_field", ["secret_ciphertext", "secret_nonce", "key_version"])
def test_mfa_login_rejects_incomplete_encrypted_credential(missing_field: str) -> None:
    active = credential()
    setattr(active, missing_field, None)
    database = ScriptedSession(scalar_values=(admin(), active))
    auth, redis = service(ScriptedFactory(database))

    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            auth.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.failures == 1


def test_mfa_login_rejects_tampered_seed_and_replayed_timestep() -> None:
    tampered = credential()
    assert tampered.secret_ciphertext is not None
    tampered.secret_ciphertext = tampered.secret_ciphertext[:-1] + bytes(
        [tampered.secret_ciphertext[-1] ^ 1]
    )
    tampered_database = ScriptedSession(scalar_values=(admin(), tampered))
    tampered_auth, tampered_redis = service(ScriptedFactory(tampered_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            tampered_auth.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert tampered_redis.failures == 1

    replayed = credential()
    replayed.last_accepted_timestep = int(NOW.timestamp()) // 30
    replay_database = ScriptedSession(scalar_values=(admin(), replayed))
    replay_auth, replay_redis = service(ScriptedFactory(replay_database))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            replay_auth.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert replay_redis.failures == 1


def test_mfa_challenge_rate_limit_and_missing_challenge_fail_before_database() -> None:
    limited_redis = AdminRedis()
    limited_redis.allowed = False
    limited, _redis = service(ScriptedFactory(), limited_redis)
    with pytest.raises(AuthenticationRateLimited):
        asyncio.run(
            limited.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    missing_redis = AdminRedis()
    missing_redis.consume_available = False
    missing, _redis = service(ScriptedFactory(), missing_redis)
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            missing.verify_mfa(
                challenge="v1.login",
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_missing_session_and_csrf_are_rejected_without_database_access() -> None:
    redis = AdminRedis()
    redis.session_available = False
    auth, _redis = service(ScriptedFactory(), redis)
    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(auth.principal("v1.missing"))

    redis.session_available = True
    redis.csrf_available = False
    with pytest.raises(AuthenticationRejected, match="Request denied"):
        asyncio.run(auth.validate_and_rotate_csrf("v1.session", "v1.bad-csrf"))


@pytest.mark.parametrize(
    "scalar_values",
    [(None, credential()), (admin(), None)],
)
def test_step_up_requires_current_admin_and_credential(
    scalar_values: tuple[object, ...],
) -> None:
    principal_database = ScriptedSession(scalar_values=(admin(),))
    mutation_database = ScriptedSession(scalar_values=scalar_values)
    auth, _redis = service(ScriptedFactory(principal_database, mutation_database))

    with pytest.raises(AuthenticationRejected, match="not accepted"):
        asyncio.run(
            auth.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_step_up_enforces_rate_limit_and_existing_lockout_before_verification() -> None:
    limited_redis = AdminRedis()
    limited_redis.allowed = False
    limited, _redis = service(
        ScriptedFactory(ScriptedSession(scalar_values=(admin(),))),
        limited_redis,
    )
    with pytest.raises(AuthenticationRateLimited):
        asyncio.run(
            limited.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    locked_redis = AdminRedis()
    locked_redis.locked = True
    locked, _redis = service(
        ScriptedFactory(ScriptedSession(scalar_values=(admin(),))),
        locked_redis,
    )
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            locked.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert locked_redis.failures == 0


def test_recovery_code_step_up_is_consumed_and_audited() -> None:
    raw = "v1." + "S" * 43
    digest = digest_opaque_token(raw, {1: b"p" * 32}, namespace="mfa-recovery")
    recovery = AdminMfaRecoveryCode(
        id=uuid4(),
        admin_totp_credential_id=CREDENTIAL_ID,
        code_digest=digest.value,
        key_version=1,
        state="active",
    )
    mutation_database = ScriptedSession(
        scalar_values=(admin(), credential(), recovery),
    )
    auth, _redis = service(
        ScriptedFactory(
            ScriptedSession(scalar_values=(admin(),)),
            mutation_database,
        )
    )

    asyncio.run(
        auth.step_up(
            session_token="v1.session",  # noqa: S106 - test fixture
            code=raw,
            method="recovery",
            network_prefix="203.0.113.0/24",
            request_id=uuid4(),
        )
    )

    assert recovery.state == "consumed" and recovery.consumed_at == NOW
    audit = next(
        value
        for value in mutation_database.added
        if isinstance(value, AuditLog) and value.event_code == "admin_recovery_code_used"
    )
    assert audit.target_kind == "admin_recovery_code" and audit.target_id == recovery.id


def test_step_up_rejects_invalid_code_and_missing_redis_rotation() -> None:
    invalid_database = ScriptedSession(scalar_values=(admin(), credential()))
    invalid_auth, invalid_redis = service(
        ScriptedFactory(
            ScriptedSession(scalar_values=(admin(),)),
            invalid_database,
        )
    )
    invalid_redis.failures = Settings(env="test").admin_lockout_threshold - 1
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            invalid_auth.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code="000000",
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )
    assert invalid_redis.failures == Settings(env="test").admin_lockout_threshold
    lockout_audit = next(value for value in invalid_database.added if isinstance(value, AuditLog))
    assert lockout_audit.event_code == "auth_lockout_changed"

    no_rotation_redis = AdminRedis()
    no_rotation_redis.rotation_available = False
    no_rotation, _redis = service(
        ScriptedFactory(
            ScriptedSession(scalar_values=(admin(),)),
            ScriptedSession(scalar_values=(admin(), credential())),
        ),
        no_rotation_redis,
    )
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            no_rotation.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )


def test_step_up_revokes_replacement_when_commit_fails() -> None:
    principal_database = ScriptedSession(scalar_values=(admin(),))
    mutation_database = ScriptedSession(
        scalar_values=(admin(), credential()),
        fail_commit=True,
    )
    auth, redis = service(ScriptedFactory(principal_database, mutation_database))

    with pytest.raises(RuntimeError, match="commit failed"):
        asyncio.run(
            auth.step_up(
                session_token="v1.session",  # noqa: S106 - test fixture
                code=current_code(),
                method="totp",
                network_prefix="203.0.113.0/24",
                request_id=uuid4(),
            )
        )

    assert redis.revoked == ["v1.session"]


def test_logout_of_missing_session_remains_idempotent() -> None:
    redis = AdminRedis()
    redis.session_available = False
    auth, _redis = service(ScriptedFactory(), redis)

    asyncio.run(auth.logout("v1.missing", request_id=uuid4()))

    assert redis.revoked == ["v1.missing"]


def test_recovery_rotation_requires_fresh_step_up_and_active_credential() -> None:
    not_fresh, _redis = service(ScriptedFactory(ScriptedSession(scalar_values=(admin(),))))
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            not_fresh.rotate_recovery_codes(
                session_token="v1.session",  # noqa: S106 - test fixture
                request_id=uuid4(),
            )
        )

    redis = AdminRedis()
    redis.record = AdminSessionRecord(
        ADMIN_ID,
        SESSION_ID,
        "totp",
        NOW,
        NOW,
        NOW + timedelta(hours=8),
        NOW,
    )
    missing_credential, _redis = service(
        ScriptedFactory(
            ScriptedSession(scalar_values=(admin(),)),
            ScriptedSession(scalar_values=(None,)),
        ),
        redis,
    )
    with pytest.raises(AuthenticationRejected):
        asyncio.run(
            missing_credential.rotate_recovery_codes(
                session_token="v1.session",  # noqa: S106 - test fixture
                request_id=uuid4(),
            )
        )


def test_expired_step_up_is_not_fresh() -> None:
    redis = AdminRedis()
    redis.record = AdminSessionRecord(
        ADMIN_ID,
        SESSION_ID,
        "totp",
        NOW,
        NOW,
        NOW + timedelta(hours=8),
        NOW - timedelta(minutes=Settings(env="test").admin_step_up_ttl_minutes),
    )
    auth, _redis = service(
        ScriptedFactory(ScriptedSession(scalar_values=(admin(),))),
        redis,
    )

    assert not asyncio.run(auth.principal("v1.session")).step_up


def test_private_query_helpers_cover_nonlocking_paths() -> None:
    database = ScriptedSession(scalar_values=(admin(), credential()))
    auth, _redis = service(ScriptedFactory())

    async def exercise() -> None:
        session = cast(AsyncSession, database)
        assert await auth._find_admin(session, "owner", for_update=False) is not None
        assert await auth._active_credential(session, ADMIN_ID, for_update=False) is not None

    asyncio.run(exercise())


def test_naive_authentication_clock_is_rejected() -> None:
    redis = AdminRedis()
    auth, _redis = service(
        ScriptedFactory(ScriptedSession(scalar_values=(admin(),))),
        redis,
        clock=lambda: datetime(2026, 7, 20, 12, 0),
    )

    with pytest.raises(ValueError, match="timezone aware"):
        asyncio.run(auth.principal("v1.session"))
