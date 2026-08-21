"""Admin-facing protocol-permission and server-assignment grants.

Mirrors `user_management.service`'s transaction/audit shape, with one
divergence: those mutations only ever UPDATE a row guaranteed to exist, so a
`.with_for_update()` row lock is sufficient. Granting here may INSERT a row
that doesn't exist yet, where a row lock can't help -- this reuses
`topology_seed.py`'s already-proven technique instead: a Postgres advisory
transaction lock keyed on the (user, target) pair, taken before the
select-then-insert-or-update, shared by both grant and revoke so there is
one concurrency mechanism, not two.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.audit import add_audit_event
from nebula_api.auth.redis_state import RateBucket, RedisAuthState
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import User
from nebula_api.models.topology import (
    ProtocolProfile,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, LifecycleState
from nebula_api.settings import Settings

Clock = Callable[[], datetime]

_MAX_LIMIT = 200


class AccessRejected(Exception):
    """Stable denial for invalid, not-found, or out-of-scope requests."""


class AccessRateLimited(AccessRejected):
    """Generic rate denial with a bounded client retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request was not accepted")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class PermissionSummary:
    id: UUID
    protocol_profile_id: UUID
    profile_code: str
    profile_display_name: str
    state: str
    granted_by_admin_id: UUID | None
    granted_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class PermissionListEntry(PermissionSummary):
    user_id: UUID
    user_email: str


@dataclass(frozen=True, slots=True)
class PermissionPage:
    items: list[PermissionListEntry]
    total: int


@dataclass(frozen=True, slots=True)
class AssignmentSummary:
    id: UUID
    vpn_server_id: UUID
    server_code: str
    server_display_name: str
    state: str
    assigned_by_admin_id: UUID | None
    assigned_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class AssignmentListEntry(AssignmentSummary):
    user_id: UUID
    user_email: str


@dataclass(frozen=True, slots=True)
class AssignmentPage:
    items: list[AssignmentListEntry]
    total: int


class AccessService:
    """Own PostgreSQL protocol-permission/server-assignment grants and their
    audit events."""

    def __init__(
        self,
        session_factory: SessionFactory,
        redis_state: RedisAuthState,
        settings: Settings,
        *,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis_state
        self._settings = settings
        self._clock = clock

    async def list_user_permissions(self, user_id: UUID) -> list[PermissionSummary]:
        statement = (
            select(
                UserProtocolPermission.id,
                UserProtocolPermission.protocol_profile_id,
                ProtocolProfile.code.label("profile_code"),
                ProtocolProfile.display_name.label("profile_display_name"),
                UserProtocolPermission.state,
                UserProtocolPermission.granted_by_admin_id,
                UserProtocolPermission.granted_at,
                UserProtocolPermission.expires_at,
                UserProtocolPermission.revoked_at,
            )
            .select_from(UserProtocolPermission)
            .join(ProtocolProfile, ProtocolProfile.id == UserProtocolPermission.protocol_profile_id)
            .where(UserProtocolPermission.user_id == user_id)
            .order_by(UserProtocolPermission.granted_at.desc())
        )
        async with self._session_factory() as session:
            rows = (await session.execute(statement)).mappings().all()
        return [PermissionSummary(**row) for row in rows]

    async def list_user_assignments(self, user_id: UUID) -> list[AssignmentSummary]:
        statement = (
            select(
                UserServerAssignment.id,
                UserServerAssignment.vpn_server_id,
                VPNServer.code.label("server_code"),
                VPNServer.display_name.label("server_display_name"),
                UserServerAssignment.state,
                UserServerAssignment.assigned_by_admin_id,
                UserServerAssignment.assigned_at,
                UserServerAssignment.expires_at,
                UserServerAssignment.revoked_at,
            )
            .select_from(UserServerAssignment)
            .join(VPNServer, VPNServer.id == UserServerAssignment.vpn_server_id)
            .where(UserServerAssignment.user_id == user_id)
            .order_by(UserServerAssignment.assigned_at.desc())
        )
        async with self._session_factory() as session:
            rows = (await session.execute(statement)).mappings().all()
        return [AssignmentSummary(**row) for row in rows]

    async def list_all_permissions(
        self, *, state: str | None, limit: int, offset: int
    ) -> PermissionPage:
        bounded_limit = max(1, min(limit, _MAX_LIMIT))
        bounded_offset = max(0, offset)
        conditions: list[ColumnElement[bool]] = []
        if state is not None:
            conditions.append(UserProtocolPermission.state == state)
        statement = (
            select(
                UserProtocolPermission.id,
                UserProtocolPermission.user_id,
                User.email.label("user_email"),
                UserProtocolPermission.protocol_profile_id,
                ProtocolProfile.code.label("profile_code"),
                ProtocolProfile.display_name.label("profile_display_name"),
                UserProtocolPermission.state,
                UserProtocolPermission.granted_by_admin_id,
                UserProtocolPermission.granted_at,
                UserProtocolPermission.expires_at,
                UserProtocolPermission.revoked_at,
            )
            .select_from(UserProtocolPermission)
            .join(ProtocolProfile, ProtocolProfile.id == UserProtocolPermission.protocol_profile_id)
            .join(User, User.id == UserProtocolPermission.user_id)
            .where(*conditions)
            .order_by(UserProtocolPermission.granted_at.desc())
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        count_statement = (
            select(func.count()).select_from(UserProtocolPermission).where(*conditions)
        )
        async with self._session_factory() as session:
            rows = (await session.execute(statement)).mappings().all()
            total = await session.scalar(count_statement)
        return PermissionPage(items=[PermissionListEntry(**row) for row in rows], total=total or 0)

    async def list_all_assignments(
        self, *, state: str | None, limit: int, offset: int
    ) -> AssignmentPage:
        bounded_limit = max(1, min(limit, _MAX_LIMIT))
        bounded_offset = max(0, offset)
        conditions: list[ColumnElement[bool]] = []
        if state is not None:
            conditions.append(UserServerAssignment.state == state)
        statement = (
            select(
                UserServerAssignment.id,
                UserServerAssignment.user_id,
                User.email.label("user_email"),
                UserServerAssignment.vpn_server_id,
                VPNServer.code.label("server_code"),
                VPNServer.display_name.label("server_display_name"),
                UserServerAssignment.state,
                UserServerAssignment.assigned_by_admin_id,
                UserServerAssignment.assigned_at,
                UserServerAssignment.expires_at,
                UserServerAssignment.revoked_at,
            )
            .select_from(UserServerAssignment)
            .join(VPNServer, VPNServer.id == UserServerAssignment.vpn_server_id)
            .join(User, User.id == UserServerAssignment.user_id)
            .where(*conditions)
            .order_by(UserServerAssignment.assigned_at.desc())
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        count_statement = select(func.count()).select_from(UserServerAssignment).where(*conditions)
        async with self._session_factory() as session:
            rows = (await session.execute(statement)).mappings().all()
            total = await session.scalar(count_statement)
        return AssignmentPage(items=[AssignmentListEntry(**row) for row in rows], total=total or 0)

    async def grant_permission(
        self,
        *,
        user_id: UUID,
        protocol_profile_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> PermissionSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session, "admin-permission-mutation", admin_id, network_prefix, request_id
            )
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('nebula.permission_grant'), hashtext(:key))"
                ),
                {"key": f"{user_id}:{protocol_profile_id}"},
            )
            profile = await session.scalar(
                select(ProtocolProfile).where(ProtocolProfile.id == protocol_profile_id)
            )
            if profile is None:
                raise AccessRejected("Request was not accepted")
            permission = await session.scalar(
                select(UserProtocolPermission).where(
                    UserProtocolPermission.user_id == user_id,
                    UserProtocolPermission.protocol_profile_id == protocol_profile_id,
                )
            )
            if permission is not None and permission.state == CapabilityState.ENABLED.value:
                summary = _permission_summary(permission, profile)
                await session.commit()
                return summary
            if permission is None:
                permission = UserProtocolPermission(
                    user_id=user_id,
                    protocol_profile_id=protocol_profile_id,
                    granted_by_admin_id=admin_id,
                    state=CapabilityState.ENABLED.value,
                    granted_at=now,
                )
                session.add(permission)
                await session.flush()
            else:
                permission.state = CapabilityState.ENABLED.value
                permission.granted_by_admin_id = admin_id
                permission.granted_at = now
                permission.revoked_at = None
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="permission",
                target_id=permission.id,
                event_code="permission_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="granted",
            )
            summary = _permission_summary(permission, profile)
            await session.commit()
        return summary

    async def revoke_permission(
        self,
        *,
        user_id: UUID,
        protocol_profile_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> PermissionSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session, "admin-permission-mutation", admin_id, network_prefix, request_id
            )
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('nebula.permission_grant'), hashtext(:key))"
                ),
                {"key": f"{user_id}:{protocol_profile_id}"},
            )
            permission = await session.scalar(
                select(UserProtocolPermission)
                .where(
                    UserProtocolPermission.user_id == user_id,
                    UserProtocolPermission.protocol_profile_id == protocol_profile_id,
                )
                .with_for_update()
            )
            if permission is None:
                raise AccessRejected("Request was not accepted")
            profile = await session.scalar(
                select(ProtocolProfile).where(ProtocolProfile.id == protocol_profile_id)
            )
            if profile is None:
                raise AccessRejected("Request was not accepted")
            if permission.state == CapabilityState.DISABLED.value:
                summary = _permission_summary(permission, profile)
                await session.commit()
                return summary
            permission.state = CapabilityState.DISABLED.value
            permission.revoked_at = now
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="permission",
                target_id=permission.id,
                event_code="permission_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="revoked",
            )
            summary = _permission_summary(permission, profile)
            await session.commit()
        return summary

    async def assign_server(
        self,
        *,
        user_id: UUID,
        vpn_server_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> AssignmentSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session, "admin-assignment-mutation", admin_id, network_prefix, request_id
            )
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtext('nebula.server_assign'), hashtext(:key))"
                ),
                {"key": f"{user_id}:{vpn_server_id}"},
            )
            server = await session.scalar(select(VPNServer).where(VPNServer.id == vpn_server_id))
            if server is None:
                raise AccessRejected("Request was not accepted")
            assignment = await session.scalar(
                select(UserServerAssignment).where(
                    UserServerAssignment.user_id == user_id,
                    UserServerAssignment.vpn_server_id == vpn_server_id,
                )
            )
            if assignment is not None and assignment.state == LifecycleState.ACTIVE.value:
                summary = _assignment_summary(assignment, server)
                await session.commit()
                return summary
            if assignment is None:
                assignment = UserServerAssignment(
                    user_id=user_id,
                    vpn_server_id=vpn_server_id,
                    assigned_by_admin_id=admin_id,
                    state=LifecycleState.ACTIVE.value,
                    assigned_at=now,
                )
                session.add(assignment)
                await session.flush()
            else:
                assignment.state = LifecycleState.ACTIVE.value
                assignment.assigned_by_admin_id = admin_id
                assignment.assigned_at = now
                assignment.revoked_at = None
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="assignment",
                target_id=assignment.id,
                event_code="assignment_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="assigned",
            )
            summary = _assignment_summary(assignment, server)
            await session.commit()
        return summary

    async def revoke_assignment(
        self,
        *,
        user_id: UUID,
        vpn_server_id: UUID,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> AssignmentSummary:
        now = self._now()
        async with self._session_factory() as session:
            await self._require_rate_limit(
                session, "admin-assignment-mutation", admin_id, network_prefix, request_id
            )
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtext('nebula.server_assign'), hashtext(:key))"
                ),
                {"key": f"{user_id}:{vpn_server_id}"},
            )
            assignment = await session.scalar(
                select(UserServerAssignment)
                .where(
                    UserServerAssignment.user_id == user_id,
                    UserServerAssignment.vpn_server_id == vpn_server_id,
                )
                .with_for_update()
            )
            if assignment is None:
                raise AccessRejected("Request was not accepted")
            server = await session.scalar(select(VPNServer).where(VPNServer.id == vpn_server_id))
            if server is None:
                raise AccessRejected("Request was not accepted")
            if assignment.state == LifecycleState.REVOKED.value:
                summary = _assignment_summary(assignment, server)
                await session.commit()
                return summary
            assignment.state = LifecycleState.REVOKED.value
            assignment.revoked_at = now
            add_audit_event(
                session,
                actor_kind="admin",
                actor_id=admin_id,
                target_kind="assignment",
                target_id=assignment.id,
                event_code="assignment_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="revoked",
            )
            summary = _assignment_summary(assignment, server)
            await session.commit()
        return summary

    async def _require_rate_limit(
        self,
        session: AsyncSession,
        namespace: str,
        admin_id: UUID,
        network_prefix: str,
        request_id: UUID,
    ) -> None:
        if await self._redis.rate_limit(
            (
                RateBucket(namespace, str(admin_id)),
                RateBucket(f"{namespace}-network", network_prefix),
            ),
            limit=self._settings.admin_user_mutation_rate_limit,
            window_seconds=self._settings.auth_rate_window_seconds,
        ):
            return
        add_audit_event(
            session,
            actor_kind="admin",
            actor_id=admin_id,
            target_kind="admin",
            target_id=admin_id,
            event_code="auth_rate_limited",
            outcome="denied",
            request_id=request_id,
            reason_code="rate_limited",
        )
        await session.commit()
        raise AccessRateLimited(self._settings.auth_rate_window_seconds)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("access clock must be timezone aware")
        return value.astimezone(UTC)


def _permission_summary(row: UserProtocolPermission, profile: ProtocolProfile) -> PermissionSummary:
    return PermissionSummary(
        id=row.id,
        protocol_profile_id=row.protocol_profile_id,
        profile_code=profile.code,
        profile_display_name=profile.display_name,
        state=row.state,
        granted_by_admin_id=row.granted_by_admin_id,
        granted_at=row.granted_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
    )


def _assignment_summary(row: UserServerAssignment, server: VPNServer) -> AssignmentSummary:
    return AssignmentSummary(
        id=row.id,
        vpn_server_id=row.vpn_server_id,
        server_code=server.code,
        server_display_name=server.display_name,
        state=row.state,
        assigned_by_admin_id=row.assigned_by_admin_id,
        assigned_at=row.assigned_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
    )
