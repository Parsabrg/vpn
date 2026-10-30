import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import nebula_api.seed_admin as seed_module
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import AdminUser
from nebula_api.models.operations import AuditLog
from nebula_api.seed_admin import SeedAdminStatus, seed_initial_admin


def fake_scope_for(
    session: AsyncSession,
) -> Callable[[SessionFactory], AbstractAsyncContextManager[AsyncSession]]:
    @asynccontextmanager
    async def fake_scope(_factory: SessionFactory) -> AsyncIterator[AsyncSession]:
        yield session

    return fake_scope


def test_seed_creates_normalized_owner_and_bootstrap_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = "canary-password-never-stored"
    digest = "argon2id-test-digest"
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=0)

    async def assign_identifier() -> None:
        admin = cast(AdminUser, session.add.call_args_list[0].args[0])
        admin.id = uuid4()

    session.flush = AsyncMock(side_effect=assign_identifier)
    monkeypatch.setattr(seed_module, "session_scope", fake_scope_for(session))
    monkeypatch.setattr(seed_module, "hash_password", lambda _password: digest)

    result = asyncio.run(
        seed_initial_admin(
            cast(SessionFactory, MagicMock()),
            email="  OWNER@Example.COM ",
            username=" Owner.Name ",
            password=candidate,
        )
    )

    assert result.status is SeedAdminStatus.CREATED
    admin = cast(AdminUser, session.add.call_args_list[0].args[0])
    audit = cast(AuditLog, session.add.call_args_list[1].args[0])
    assert admin.email_normalized == "owner@example.com"
    assert admin.username_normalized == "owner.name"
    assert admin.password_hash == digest
    assert "canary-password" not in repr(admin)
    assert audit.actor_kind == "bootstrap"
    assert audit.target_id == admin.id
    assert audit.event_code == "admin_seeded"


def test_seed_is_idempotent_after_store_is_initialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = "canary-password-never-stored"
    digest = "argon2id-test-digest"
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.scalar = AsyncMock(return_value=1)
    monkeypatch.setattr(seed_module, "session_scope", fake_scope_for(session))
    monkeypatch.setattr(seed_module, "hash_password", lambda _password: digest)

    result = asyncio.run(
        seed_initial_admin(
            cast(SessionFactory, MagicMock()),
            email="owner@example.com",
            username=None,
            password=candidate,
        )
    )

    assert result.status is SeedAdminStatus.ALREADY_INITIALIZED
    assert result.admin_id is None
    session.add.assert_not_called()
    session.flush.assert_not_awaited()
