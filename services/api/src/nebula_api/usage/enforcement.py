"""Taking access away when an allowance is spent.

A quota nothing enforces is a label. This is the part that makes it a limit:
after each poll folds new counters into the totals, every metered account is
measured against its allowance, and one that has spent it loses its
credentials.

Deliberately not instant. Usage is known only as often as the poll runs, so an
account can overshoot by whatever it moves between two polls. Shortening the
interval shrinks that and cannot remove it -- the alternative is asking a VPN
server for permission on every packet, which is not what this system is. It
runs every fifteen seconds (`nebula-api collect-usage --every 15`); once a
minute let a phone on a 30 MB allowance reach 76 MB at 1 MB/s. The
overshoot is recorded rather than hidden: it goes on accumulating in the
per-credential totals and appears against the next allowance's baseline.
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select

from nebula_api.auth.audit import add_audit_event
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.provisioning.revocation import revoke_device_credentials
from nebula_api.usage.service import AccountUsage, UsageService

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EnforcementSummary:
    accounts_checked: int = 0
    accounts_exhausted: int = 0
    credentials_revoked: int = 0
    already_enforced: int = 0
    account_ids: list[UUID] = field(default_factory=list)

    @property
    def took_action(self) -> bool:
        return bool(self.accounts_exhausted)


async def enforce_traffic_quotas(
    session_factory: SessionFactory, usage: UsageService
) -> EnforcementSummary:
    """Revoke the credentials of every account that has spent its allowance.

    Only metered accounts are looked at. An unmetered account cannot exhaust
    anything, and reading usage for one costs the same decryptions as reading
    it for an account that can.

    An account already marked exhausted is counted and skipped. Its
    credentials went the first time; re-revoking every fifteen minutes would
    write an audit event each pass and say nothing new.
    """

    async with session_factory() as session:
        metered = list(
            (
                await session.scalars(
                    select(User.id).where(
                        User.traffic_quota_bytes.is_not(None),
                        User.quota_exhausted_at.is_(None),
                    )
                )
            ).all()
        )
        already = len(
            (
                await session.scalars(
                    select(User.id).where(
                        User.traffic_quota_bytes.is_not(None),
                        User.quota_exhausted_at.is_not(None),
                    )
                )
            ).all()
        )

    exhausted: list[UUID] = []
    revoked = 0
    for user_id in metered:
        account: AccountUsage = await usage.usage_for_user(user_id)
        if not account.is_exhausted:
            continue
        revoked += await _cut_off(session_factory, user_id, account)
        exhausted.append(user_id)

    return EnforcementSummary(
        accounts_checked=len(metered),
        accounts_exhausted=len(exhausted),
        credentials_revoked=revoked,
        already_enforced=already,
        account_ids=exhausted,
    )


async def _cut_off(session_factory: SessionFactory, user_id: UUID, account: AccountUsage) -> int:
    """Mark the account spent and revoke what it holds.

    Credentials go to REVOKING rather than being removed here, which hands
    them to reconciliation exactly as an admin disabling an account does --
    see `revoke_device_credentials`. An unreachable agent therefore delays the
    cut-off instead of losing it.

    The account's devices are left alone. They are not at fault and the
    account is not disabled; it has simply run out, and a new allowance should
    let it provision again without anything being re-registered.
    """

    now = datetime.now(UTC)
    async with session_factory() as session:
        user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            return 0
        if user.quota_exhausted_at is not None:
            # Won by a concurrent sweep between the read above and this lock.
            return 0

        device_ids = list(
            (await session.scalars(select(Device.id).where(Device.user_id == user_id))).all()
        )
        revoked = 0
        for device_id in device_ids:
            revoked += await revoke_device_credentials(session, device_id, now)

        user.quota_exhausted_at = now
        add_audit_event(
            session,
            actor_kind="system",
            actor_id=None,
            target_kind="user",
            target_id=user_id,
            event_code="identity_state_changed",
            outcome="succeeded",
            request_id=uuid4(),
            reason_code="traffic_quota_exhausted",
        )
        await session.commit()

    _LOGGER.info(
        "revoked %d credential(s) for an account that used %d of %s bytes",
        revoked,
        account.total_bytes,
        account.quota_bytes,
    )
    return revoked
