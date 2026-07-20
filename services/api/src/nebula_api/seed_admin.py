"""Transactional initial-administrator bootstrap service."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from sqlalchemy import func, select, text

from nebula_api.db.engine import SessionFactory, session_scope
from nebula_api.identity import normalize_email, normalize_username
from nebula_api.models.identity import AdminUser
from nebula_api.models.operations import AuditLog
from nebula_api.models.types import AdminRole, AdminState
from nebula_api.passwords import hash_password


class SeedAdminStatus(StrEnum):
    """Non-sensitive bootstrap outcome."""

    CREATED = "created"
    ALREADY_INITIALIZED = "already_initialized"


@dataclass(frozen=True, slots=True)
class SeedAdminResult:
    """Bootstrap result without identity or credential values."""

    status: SeedAdminStatus
    admin_id: UUID | None = None


async def seed_initial_admin(
    session_factory: SessionFactory,
    *,
    email: str,
    username: str | None,
    password: str,
) -> SeedAdminResult:
    """Create the sole bootstrap owner under a transaction-scoped advisory lock."""

    normalized_email = normalize_email(email)
    normalized_username = normalize_username(username) if username is not None else None
    password_hash = hash_password(password)

    async with session_scope(session_factory) as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('nebula.initial_admin'))")
        )
        admin_count = await session.scalar(select(func.count(AdminUser.id)))
        if admin_count != 0:
            return SeedAdminResult(status=SeedAdminStatus.ALREADY_INITIALIZED)

        admin = AdminUser(
            email=email.strip(),
            email_normalized=normalized_email,
            username=username.strip() if username is not None else None,
            username_normalized=normalized_username,
            password_hash=password_hash,
            role=AdminRole.OWNER,
            state=AdminState.ACTIVE,
        )
        session.add(admin)
        await session.flush()
        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="admin",
                target_id=admin.id,
                event_code="admin_seeded",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code=None,
            )
        )
        return SeedAdminResult(status=SeedAdminStatus.CREATED, admin_id=admin.id)
