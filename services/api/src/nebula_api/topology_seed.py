"""Transactional CLI seed commands for VPN topology: the WireGuard protocol
profile, VPN servers, and per-user permission/assignment grants.

Follows seed_admin.py's shape exactly: a transaction-scoped advisory lock for
uniqueness-sensitive creation, session_scope for commit/rollback, and audit
events written in the same transaction as the mutation they describe.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select, text

from nebula_api.db.engine import SessionFactory, session_scope
from nebula_api.identity import normalize_email
from nebula_api.models.identity import User
from nebula_api.models.operations import AuditLog
from nebula_api.models.topology import (
    Protocol,
    ProtocolProfile,
    ServerProtocolCapability,
    UserProtocolPermission,
    UserServerAssignment,
    VPNServer,
)
from nebula_api.models.types import CapabilityState, LifecycleState, ProfileState, ProtocolEngine

WIREGUARD_PROTOCOL_CODE = "wireguard"
WIREGUARD_PROFILE_CODE = "wireguard-native"
WIREGUARD_PROFILE_DISPLAY_NAME = "WireGuard"
WIREGUARD_PROFILE_VERSION = 1


class SeedProtocolStatus(StrEnum):
    CREATED = "created"
    ALREADY_SEEDED = "already_seeded"


@dataclass(frozen=True, slots=True)
class SeedProtocolResult:
    status: SeedProtocolStatus
    protocol_id: UUID
    protocol_profile_id: UUID


async def seed_wireguard_protocol(session_factory: SessionFactory) -> SeedProtocolResult:
    """Idempotent: creates the canonical WireGuard Protocol + implemented
    ProtocolProfile if absent, otherwise returns the existing ids. Run once
    ever -- Phase 1 has exactly one native WireGuard profile."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext('nebula.wireguard_protocol_seed'))")
        )
        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is not None:
            profile = await session.scalar(
                select(ProtocolProfile).where(ProtocolProfile.protocol_id == protocol.id)
            )
            if profile is None:
                raise ValueError(
                    "a 'wireguard' protocol row exists without a profile; this needs manual repair"
                )
            return SeedProtocolResult(
                status=SeedProtocolStatus.ALREADY_SEEDED,
                protocol_id=protocol.id,
                protocol_profile_id=profile.id,
            )

        protocol = Protocol(
            code=WIREGUARD_PROTOCOL_CODE,
            display_name="WireGuard",
            engine=ProtocolEngine.NATIVE_WIREGUARD.value,
            is_user_selectable=True,
        )
        session.add(protocol)
        await session.flush()

        profile = ProtocolProfile(
            protocol_id=protocol.id,
            code=WIREGUARD_PROFILE_CODE,
            version=WIREGUARD_PROFILE_VERSION,
            display_name=WIREGUARD_PROFILE_DISPLAY_NAME,
            state=ProfileState.IMPLEMENTED.value,
            requires_udp=True,
            is_full_tunnel=True,
        )
        session.add(profile)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="protocol_profile",
                target_id=profile.id,
                event_code="profile_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="seeded",
            )
        )
        return SeedProtocolResult(
            status=SeedProtocolStatus.CREATED,
            protocol_id=protocol.id,
            protocol_profile_id=profile.id,
        )


class CreateServerStatus(StrEnum):
    CREATED = "created"


@dataclass(frozen=True, slots=True)
class CreateServerResult:
    status: CreateServerStatus
    vpn_server_id: UUID


async def create_vpn_server(
    session_factory: SessionFactory,
    *,
    code: str,
    display_name: str,
    agent_host: str,
    agent_port: int,
    public_host: str,
    wireguard_client_pool: str | None,
    wireguard_gateway_address: str | None,
    maximum_devices: int,
    state: str,
) -> CreateServerResult:
    """Creates the VPNServer row and auto-enables its WireGuard
    ServerProtocolCapability in the same transaction -- Phase 1 only ever
    has one protocol, so this collapses two admin concerns into one
    command. Requires seed_wireguard_protocol to have already run. Rejects
    a duplicate code outright rather than silently succeeding -- a typo is
    more likely than an intentional re-run."""

    async with session_scope(session_factory) as session:
        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('nebula.vpn_server_create'), hashtext(:code))"
            ),
            {"code": code},
        )
        existing = await session.scalar(select(VPNServer).where(VPNServer.code == code))
        if existing is not None:
            raise ValueError(f"a VPN server with code {code!r} already exists")

        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is None:
            raise ValueError(
                "no WireGuard protocol is seeded; run `nebula-api seed-wireguard-protocol` first"
            )
        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.state == ProfileState.IMPLEMENTED.value,
            )
        )
        if profile is None:
            raise ValueError(
                "no implemented WireGuard protocol profile found; "
                "run `nebula-api seed-wireguard-protocol` first"
            )

        server = VPNServer(
            code=code,
            display_name=display_name,
            state=state,
            agent_host=agent_host,
            agent_port=agent_port,
            public_host=public_host,
            wireguard_client_pool=wireguard_client_pool,
            wireguard_gateway_address=wireguard_gateway_address,
            maximum_devices=maximum_devices,
        )
        session.add(server)
        await session.flush()

        capability = ServerProtocolCapability(
            vpn_server_id=server.id,
            protocol_profile_id=profile.id,
            state=CapabilityState.ENABLED.value,
            validated_profile_version=str(profile.version),
        )
        session.add(capability)
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="vpn_server",
                target_id=server.id,
                event_code="server_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="created",
            )
        )
        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="server_capability",
                target_id=capability.id,
                event_code="capability_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="enabled",
            )
        )
        return CreateServerResult(status=CreateServerStatus.CREATED, vpn_server_id=server.id)


class GrantAccessStatus(StrEnum):
    GRANTED = "granted"


@dataclass(frozen=True, slots=True)
class GrantAccessResult:
    status: GrantAccessStatus
    user_id: UUID


async def grant_user_server_access(
    session_factory: SessionFactory,
    *,
    user_email: str,
    server_code: str,
) -> GrantAccessResult:
    """Creates or reactivates both UserProtocolPermission and
    UserServerAssignment for the WireGuard profile in one transaction.
    Idempotent -- reactivates a disabled/revoked row rather than erroring."""

    normalized_email = normalize_email(user_email)

    async with session_scope(session_factory) as session:
        await session.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('nebula.grant_user_access'), hashtext(:key))"
            ),
            {"key": f"{normalized_email}:{server_code}"},
        )

        user = await session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is None:
            raise ValueError(f"no user found with email {user_email!r}")

        server = await session.scalar(select(VPNServer).where(VPNServer.code == server_code))
        if server is None:
            raise ValueError(f"no VPN server found with code {server_code!r}")

        protocol = await session.scalar(
            select(Protocol).where(Protocol.code == WIREGUARD_PROTOCOL_CODE)
        )
        if protocol is None:
            raise ValueError(
                "no WireGuard protocol is seeded; run `nebula-api seed-wireguard-protocol` first"
            )
        profile = await session.scalar(
            select(ProtocolProfile).where(
                ProtocolProfile.protocol_id == protocol.id,
                ProtocolProfile.state == ProfileState.IMPLEMENTED.value,
            )
        )
        if profile is None:
            raise ValueError(
                "no implemented WireGuard protocol profile found; "
                "run `nebula-api seed-wireguard-protocol` first"
            )

        now = datetime.now(UTC)

        permission = await session.scalar(
            select(UserProtocolPermission).where(
                UserProtocolPermission.user_id == user.id,
                UserProtocolPermission.protocol_profile_id == profile.id,
            )
        )
        if permission is None:
            permission = UserProtocolPermission(
                user_id=user.id,
                protocol_profile_id=profile.id,
                granted_by_admin_id=None,
                state=CapabilityState.ENABLED.value,
                granted_at=now,
            )
            session.add(permission)
        elif permission.state != CapabilityState.ENABLED.value:
            permission.state = CapabilityState.ENABLED.value
            permission.granted_at = now
            permission.revoked_at = None
        await session.flush()

        assignment = await session.scalar(
            select(UserServerAssignment).where(
                UserServerAssignment.user_id == user.id,
                UserServerAssignment.vpn_server_id == server.id,
            )
        )
        if assignment is None:
            assignment = UserServerAssignment(
                user_id=user.id,
                vpn_server_id=server.id,
                assigned_by_admin_id=None,
                state=LifecycleState.ACTIVE.value,
                assigned_at=now,
            )
            session.add(assignment)
        elif assignment.state != LifecycleState.ACTIVE.value:
            assignment.state = LifecycleState.ACTIVE.value
            assignment.assigned_at = now
            assignment.revoked_at = None
        await session.flush()

        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="permission",
                target_id=permission.id,
                event_code="permission_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="granted",
            )
        )
        session.add(
            AuditLog(
                actor_kind="bootstrap",
                actor_id=None,
                target_kind="assignment",
                target_id=assignment.id,
                event_code="assignment_changed",
                outcome="succeeded",
                request_id=None,
                correlation_id=None,
                reason_code="assigned",
            )
        )
        return GrantAccessResult(status=GrantAccessStatus.GRANTED, user_id=user.id)
