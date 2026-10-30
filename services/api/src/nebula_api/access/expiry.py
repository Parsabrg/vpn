"""Taking away credentials that provisioning would no longer grant.

Provisioning checks, at the moment somebody connects, that the account is
active and not expired, the device is not revoked, and the account holds an
active, unexpired assignment to the server and an enabled, unexpired
permission for the protocol. Nothing checked again afterwards. Disabling an
account and revoking a device mark credentials for removal as they happen,
but expiry is not an action -- it is a timestamp passing -- so a credential
issued to an account that expired an hour later went on working for as long as
the device stayed connected.

This is the afterwards. Each run, a live credential whose grant no longer
holds is marked REVOKING, and the same run hands it to reconciliation, which
takes it off the server. The conditions are the ones provisioning applies, so
a credential is never taken away that a fresh connect would have been given.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Select, and_, exists, or_, select

from nebula_api.auth.audit import add_audit_event
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.models.provisioning import WireGuardPeer, XrayClient
from nebula_api.models.topology import UserProtocolPermission, UserServerAssignment
from nebula_api.models.types import (
    AccountState,
    CapabilityState,
    LifecycleState,
    ProvisioningState,
)
from nebula_api.provisioning.revocation import revoke_credential_row

_LOGGER = logging.getLogger(__name__)

_LIVE = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
)

Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class ExpirySummary:
    credentials_revoked: int = 0
    account_ids: list[UUID] = field(default_factory=list)


async def enforce_access_expiry(
    session_factory: SessionFactory, *, clock: Clock = lambda: datetime.now(UTC)
) -> ExpirySummary:
    now = clock()
    revoked: dict[UUID, int] = {}
    async with session_factory() as session:
        # Value-restricted, as in revocation.py: the two credential tables
        # share no base that declares these columns.
        async def revoke_lapsed[Row: (WireGuardPeer, XrayClient)](model: type[Row]) -> None:
            for row, user_id in (await session.execute(_lapsed(model, now))).tuples():
                await revoke_credential_row(session, row, now)
                revoked[user_id] = revoked.get(user_id, 0) + 1

        await revoke_lapsed(WireGuardPeer)
        await revoke_lapsed(XrayClient)
        for user_id in revoked:
            add_audit_event(
                session,
                actor_kind="system",
                actor_id=None,
                target_kind="user",
                target_id=user_id,
                event_code="identity_state_changed",
                outcome="succeeded",
                request_id=uuid4(),
                reason_code="access_lapsed",
            )
        await session.commit()

    if revoked:
        _LOGGER.info(
            "revoked %d credential(s) whose access had lapsed, across %d account(s)",
            sum(revoked.values()),
            len(revoked),
        )
    return ExpirySummary(credentials_revoked=sum(revoked.values()), account_ids=list(revoked))


def _lapsed[Row: (WireGuardPeer, XrayClient)](model: type[Row], now: datetime) -> Select[Row, UUID]:
    """Live credentials that provisioning would refuse today.

    Existence checks rather than joins for the assignment and the permission:
    an account keeps old revoked assignment rows beside its active one, and a
    join would match those and cut off somebody who still has access.
    """

    has_assignment = exists().where(
        UserServerAssignment.user_id == User.id,
        UserServerAssignment.vpn_server_id == model.vpn_server_id,
        UserServerAssignment.state == LifecycleState.ACTIVE.value,
        or_(UserServerAssignment.expires_at.is_(None), UserServerAssignment.expires_at > now),
    )
    has_permission = exists().where(
        UserProtocolPermission.user_id == User.id,
        UserProtocolPermission.protocol_profile_id == model.protocol_profile_id,
        UserProtocolPermission.state == CapabilityState.ENABLED.value,
        or_(
            UserProtocolPermission.expires_at.is_(None),
            UserProtocolPermission.expires_at > now,
        ),
    )
    return (
        select(model, User.id)
        .join(Device, Device.id == model.device_id)
        .join(User, User.id == Device.user_id)
        .where(model.state.in_(_LIVE))
        .where(
            or_(
                User.state != AccountState.ACTIVE,
                and_(User.expires_at.is_not(None), User.expires_at <= now),
                Device.state == LifecycleState.REVOKED,
                ~has_assignment,
                ~has_permission,
            )
        )
        .with_for_update(of=model)
    )
