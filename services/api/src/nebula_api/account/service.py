"""The caller's own account and devices, and revoking one of them.

Everything here is scoped to the authenticated user by a `user_id` the caller
cannot supply -- it comes from the session. There is deliberately no way to
address another user's account through these methods: the admin surface
already exists in `user_management` and is gated differently.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.audit import add_audit_event
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.models.provisioning import DeviceProtocolCredential, WireGuardPeer, XrayClient
from nebula_api.models.topology import VPNServer
from nebula_api.models.types import LifecycleState, ProvisioningState
from nebula_api.usage.service import UsageService

# Mirrors user_management's list, and for the same reason: these three are the
# states in which a credential is either on the VPN server already or on its
# way there, so they are what revocation has to catch.
_LIVE_CREDENTIAL_STATES = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
)


@dataclass(frozen=True, slots=True)
class AccountEntry:
    email: str
    username: str | None
    state: str
    device_limit: int
    devices_in_use: int
    expires_at: datetime | None
    used_bytes: int
    lifetime_bytes: int
    quota_bytes: int | None
    remaining_bytes: int | None


@dataclass(frozen=True, slots=True)
class DeviceEntry:
    id: UUID
    name: str
    platform: str
    state: str
    client_version: str
    registered_at: datetime
    is_current: bool
    # Servers this device currently holds a live credential on. Empty is
    # meaningful: the device is registered and provisioned nothing.
    server_codes: list[str] = field(default_factory=list)


class DeviceRevocationRefused(Exception):
    """The device cannot be revoked, with a reason the caller may be shown."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class AccountService:
    """Read the caller's own account, and revoke one of their devices."""

    def __init__(self, session_factory: SessionFactory, usage: UsageService) -> None:
        self._session_factory = session_factory
        self._usage = usage

    async def get_account(self, user_id: UUID) -> AccountEntry | None:
        """The account, with a device count that matches what `list_devices`
        returns -- both count only devices that are not revoked, so the "3 of
        5" in the header cannot disagree with the rows underneath it."""

        async with self._session_factory() as session:
            user = await session.scalar(select(User).where(User.id == user_id))
            if user is None:
                return None

            devices_in_use = await session.scalar(
                select(func.count())
                .select_from(Device)
                .where(
                    Device.user_id == user_id,
                    Device.state != LifecycleState.REVOKED,
                )
            )

        # Read after the session closes: usage owns its own queries and one
        # of them decrypts, which is not something to hold a lock through.
        usage = await self._usage.usage_for_user(user_id)

        return AccountEntry(
            email=user.email,
            username=user.username,
            state=user.state,
            device_limit=user.device_limit,
            devices_in_use=devices_in_use or 0,
            expires_at=user.expires_at,
            used_bytes=usage.total_bytes,
            lifetime_bytes=usage.lifetime_bytes,
            quota_bytes=usage.quota_bytes,
            remaining_bytes=usage.remaining_bytes,
        )

    async def list_devices(self, user_id: UUID, current_device_id: UUID) -> list[DeviceEntry]:
        """Every device on the account that has not been revoked.

        Revoked devices are omitted rather than shown greyed out. The row
        carries an action, and a list where most rows cannot be acted on
        teaches people to ignore the list.
        """

        async with self._session_factory() as session:
            devices = (
                await session.scalars(
                    select(Device)
                    .where(
                        Device.user_id == user_id,
                        Device.state != LifecycleState.REVOKED,
                    )
                    .order_by(Device.created_at.asc())
                )
            ).all()

            # One query for every device's live credentials rather than one
            # per device: a five-device account would otherwise cost six
            # round trips to render a list.
            credential_rows = (
                await session.execute(
                    select(DeviceProtocolCredential.device_id, VPNServer.code)
                    .join(VPNServer, VPNServer.id == DeviceProtocolCredential.vpn_server_id)
                    .where(
                        DeviceProtocolCredential.device_id.in_([device.id for device in devices]),
                        DeviceProtocolCredential.state.in_(_LIVE_CREDENTIAL_STATES),
                    )
                )
            ).all()

        by_device: dict[UUID, list[str]] = {}
        for device_id, server_code in credential_rows:
            codes = by_device.setdefault(device_id, [])
            if server_code not in codes:
                codes.append(server_code)

        return [
            DeviceEntry(
                id=device.id,
                name=device.name,
                platform=device.platform,
                state=device.state,
                client_version=device.client_version,
                registered_at=device.created_at,
                is_current=device.id == current_device_id,
                server_codes=sorted(by_device.get(device.id, [])),
            )
            for device in devices
        ]

    async def revoke_device(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        current_device_id: UUID,
        request_id: UUID,
    ) -> None:
        """Revoke one of the caller's own devices.

        Refuses the device making the request. Revoking the device you are
        holding would drop your own tunnel and leave you signed in to an
        account whose device row is gone -- and the recovery is not obvious
        from that screen. Signing out is the action for that, and the design
        puts no Revoke on the current row for the same reason. Enforced here
        as well because a client is not a permission boundary.

        Credentials go to REVOKING rather than REVOKED, with no agent call
        from here: reconciliation treats REVOKING as "should be absent from
        the server" and drives it through the agent, retrying until it
        succeeds. An unreachable agent therefore delays revocation instead of
        losing it.
        """

        if device_id == current_device_id:
            raise DeviceRevocationRefused("cannot_revoke_current_device")

        now = datetime.now(UTC)

        async with self._session_factory() as session:
            device = await session.scalar(
                select(Device)
                .where(Device.id == device_id, Device.user_id == user_id)
                .with_for_update()
            )
            # Same error for "not yours" and "does not exist": distinguishing
            # them would confirm the existence of another account's device id.
            if device is None:
                raise DeviceRevocationRefused("not_found")
            if device.state == LifecycleState.REVOKED:
                raise DeviceRevocationRefused("already_revoked")

            device.state = LifecycleState.REVOKED
            device.revoked_at = now
            device.updated_at = now

            await _revoke_device_credentials(session, device_id, now)

            add_audit_event(
                session,
                actor_kind="user",
                actor_id=user_id,
                target_kind="device",
                target_id=device_id,
                event_code="device_state_changed",
                outcome="succeeded",
                request_id=request_id,
                reason_code="revoked",
            )
            await session.commit()


async def _revoke_device_credentials(session: AsyncSession, device_id: UUID, now: datetime) -> int:
    """Move every live VPN credential for this device into REVOKING.

    A near-copy of `user_management._revoke_device_credentials`, imported from
    neither direction: that module is the admin surface and importing it here
    would drag the whole admin service graph into a user-facing request path.
    The duplication is the two tables' column names, which are fixed by the
    schema.
    """

    # Value-restricted: the two credential tables carry the same columns this
    # touches but share no base that declares them, so a union of the two
    # class objects would erase every attribute back to Base.
    async def revoke_rows[Row: (WireGuardPeer, XrayClient)](model: type[Row]) -> int:
        rows = (
            await session.scalars(
                select(model)
                .where(
                    model.device_id == device_id,
                    model.state.in_(_LIVE_CREDENTIAL_STATES),
                )
                .with_for_update()
            )
        ).all()
        for row in rows:
            row.state = ProvisioningState.REVOKING.value
            row.updated_at = now
            credential = await session.scalar(
                select(DeviceProtocolCredential)
                .where(DeviceProtocolCredential.id == row.credential_id)
                .with_for_update()
            )
            if credential is not None:
                credential.state = ProvisioningState.REVOKING.value
                credential.updated_at = now
        return len(rows)

    return await revoke_rows(WireGuardPeer) + await revoke_rows(XrayClient)
