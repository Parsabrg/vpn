"""Session and refresh-token revocation shared by user- and admin-initiated flows.

Extracted from `UserAuthService` (which owns self-service revocation) so the
admin-facing user-management service can cascade a device/session revocation
identically rather than re-implementing this security-sensitive logic.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.models.identity import RefreshToken, UserSession
from nebula_api.models.types import LifecycleState, TokenState


async def revoke_active_device_sessions(
    session: AsyncSession, device_id: UUID, *, now: datetime
) -> None:
    session_ids = list(
        (
            await session.scalars(
                select(UserSession.id)
                .where(
                    UserSession.device_id == device_id,
                    UserSession.state == LifecycleState.ACTIVE,
                )
                .with_for_update()
            )
        ).all()
    )
    if not session_ids:
        return
    await session.execute(
        update(UserSession)
        .where(UserSession.id.in_(session_ids))
        .values(state=LifecycleState.REVOKED, revoked_at=now)
    )
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.session_id.in_(session_ids),
            RefreshToken.state == TokenState.ACTIVE,
        )
        .values(state=TokenState.REVOKED, revoked_at=now)
    )


async def revoke_session(
    session: AsyncSession, user_session: UserSession, *, now: datetime
) -> None:
    if user_session.state is LifecycleState.ACTIVE:
        user_session.state = LifecycleState.REVOKED
        user_session.revoked_at = now
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.session_id == user_session.id,
            RefreshToken.state == TokenState.ACTIVE,
        )
        .values(state=TokenState.REVOKED, revoked_at=now)
    )


async def revoke_all_user_sessions(session: AsyncSession, user_id: UUID, *, now: datetime) -> None:
    session_ids = list(
        (
            await session.scalars(
                select(UserSession.id).where(UserSession.user_id == user_id).with_for_update()
            )
        ).all()
    )
    if session_ids:
        await session.execute(
            update(UserSession)
            .where(
                UserSession.id.in_(session_ids),
                UserSession.state == LifecycleState.ACTIVE,
            )
            .values(state=LifecycleState.REVOKED, revoked_at=now)
        )
        await session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id.in_(session_ids),
                RefreshToken.state == TokenState.ACTIVE,
            )
            .values(state=TokenState.REVOKED, revoked_at=now)
        )
