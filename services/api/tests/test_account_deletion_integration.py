"""Real-PostgreSQL proof that deleting an account leaves nothing naming the person.

What matters here is database behaviour a scripted session cannot show: the
foreign keys between the rows deleted (refresh tokens on sessions, request
events on requests), the check constraints on the rows kept (a disabled user
needs disabled_at, the placeholder must be a valid unique address), and that
the application role may delete each of them.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.auth.user_service import AuthenticatedUser, UserAuthService
from nebula_api.db.engine import create_database_engine, create_session_factory
from nebula_api.passwords import hash_password
from nebula_api.settings import Settings

PASSWORD = "deletion-test-password"  # noqa: S105 - test fixture


def _database_url() -> str:
    return os.environ.get("NEBULA_DATABASE_URL", "")


class _AllowingRedis:
    async def rate_limit(self, *_args: object, **_kwargs: object) -> bool:
        return True


def _keys() -> AuthKeyMaterial:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    return AuthKeyMaterial(
        private, {"v1": private.public_key()}, {1: b"p" * 32}, {1: b"m" * 32}, {1: b"x" * 32}
    )


@pytest.mark.skipif(not _database_url(), reason="PostgreSQL is not configured")
def test_deleting_an_account_leaves_nothing_that_names_the_person() -> None:
    engine = create_database_engine(_database_url())
    unique = uuid4().hex[:10]
    email = f"delete-me-{unique}@example.test"
    user_id, device_id, session_id = uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)

    async def execute(sql: str, **params: object) -> None:
        async with engine.begin() as connection:
            await connection.execute(text(sql), params)

    async def count(sql: str, **params: object) -> int:
        async with engine.begin() as connection:
            return int(await connection.scalar(text(sql), params) or 0)

    async def scenario() -> None:
        await execute(
            """insert into users (id, email, email_normalized, username, username_normalized,
                                  password_hash, state, device_limit, dns_profile,
                                  traffic_baseline_bytes, activated_at)
               values (:id, :email, :email, :name, :name, :hash, 'active', 3, 'default', 0,
                       :now)""",
            id=user_id,
            email=email,
            name=f"del{unique}",
            hash=hash_password(PASSWORD),
            now=now,
        )
        await execute(
            """insert into devices (id, user_id, name, platform, client_version, state,
                                    hardware_hash, hardware_key_version)
               values (:id, :user, 'Parsa phone', 'android', '0.1.33', 'active', :hw, 1)""",
            id=device_id,
            user=user_id,
            hw=b"h" * 32,
        )
        await execute(
            """insert into user_sessions (id, user_id, device_id, family_id, state, expires_at,
                                          last_seen_at)
               values (:id, :user, :device, :family, 'active', :expires, :now)""",
            id=session_id,
            user=user_id,
            device=device_id,
            family=uuid4(),
            expires=now + timedelta(days=30),
            now=now,
        )
        await execute(
            """insert into refresh_tokens (id, session_id, token_digest, key_version, state,
                                           expires_at)
               values (:id, :session, :digest, 1, 'active', :expires)""",
            id=uuid4(),
            session=session_id,
            digest=uuid4().bytes * 2,
            expires=now + timedelta(days=30),
        )
        await execute(
            """insert into password_reset_tokens (id, user_id, token_digest, key_version, state,
                                                  expires_at)
               values (:id, :user, :digest, 1, 'active', :expires)""",
            id=uuid4(),
            user=user_id,
            digest=uuid4().bytes * 2,
            expires=now + timedelta(minutes=30),
        )
        request_id = uuid4()
        await execute(
            """insert into account_requests (id, email, email_normalized, state, expires_at)
               values (:id, :email, :email, 'pending', :expires)""",
            id=request_id,
            email=email,
            expires=now + timedelta(days=7),
        )
        await execute(
            """insert into account_request_events (id, request_id, to_state)
               values (:id, :request, 'pending')""",
            id=uuid4(),
            request=request_id,
        )
        await execute(
            """insert into email_deliveries (id, deduplication_key, template_code,
                                             recipient_address, subject_kind, subject_id, state,
                                             attempt_count, available_at)
               values (:id, :dedup, 'user_activation', :email, 'user', :user, 'sent', 1, :now)""",
            id=uuid4(),
            dedup=uuid4(),
            email=email,
            user=user_id,
            now=now,
        )

        auth = UserAuthService(
            create_session_factory(engine),
            _AllowingRedis(),  # type: ignore[arg-type]
            _keys(),
            Settings(env="test"),
        )
        principal = AuthenticatedUser(user_id=user_id, session_id=session_id, device_id=device_id)
        await auth.delete_account(principal=principal, password=PASSWORD, request_id=uuid4())

        async with engine.begin() as connection:
            row = (
                await connection.execute(
                    text(
                        "select email, username, password_hash, state, disabled_at "
                        "from users where id = :id"
                    ),
                    {"id": user_id},
                )
            ).one()
            device = (
                await connection.execute(
                    text("select name, hardware_hash, state from devices where id = :id"),
                    {"id": device_id},
                )
            ).one()
        assert email not in row.email and row.email.endswith("@deleted.invalid")
        assert row.username is None and row.password_hash is None
        assert row.state == "disabled" and row.disabled_at is not None
        assert device.name == "deleted" and device.hardware_hash is None
        assert device.state == "revoked"
        for table, column, value in (
            ("user_sessions", "user_id", user_id),
            ("password_reset_tokens", "user_id", user_id),
            ("account_requests", "email_normalized", email),
            ("email_deliveries", "recipient_address", email),
        ):
            remaining = await count(
                f"select count(*) from {table} where {column} = :value",  # noqa: S608
                value=value,
            )
            assert remaining == 0, table
        assert (
            await count("select count(*) from refresh_tokens where session_id = :id", id=session_id)
            == 0
        )
        assert (
            await count(
                "select count(*) from audit_logs where target_id = :id "
                "and reason_code = 'account_deleted'",
                id=user_id,
            )
            == 1
        )

    try:
        asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())
