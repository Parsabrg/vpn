"""Taking a device's live VPN credentials away.

Shared because two very different things need it and must do it identically:
an admin disabling an account, and a traffic allowance running out. A second
implementation would be a second chance to leave a credential live on the
server while the database called it revoked.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.db.engine import SessionFactory
from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)
from nebula_api.models.types import ProvisioningState

_LIVE_CREDENTIAL_STATES = (
    ProvisioningState.REQUESTED.value,
    ProvisioningState.APPLYING.value,
    ProvisioningState.ACTIVE.value,
)


async def revoke_device_credentials(session: AsyncSession, device_id: UUID, now: datetime) -> int:
    """Move every live VPN credential for this device into REVOKING.

    Revoking a device used to stop only at the database row and the API
    session: the WireGuard peer and Xray client stayed in the VPN server's
    configuration and kept authenticating, so a revoked device held a working
    tunnel indefinitely while the admin UI showed it as revoked. Killing the
    API session prevents provisioning anything new; it does nothing about the
    credential already on the device.

    REVOKING rather than REVOKED, and no agent call from here: reconciliation
    already treats a credential in this state as one that should be absent
    from the server (`wants_present = state != REVOKING`) and drives it to
    REVOKED through the agent, retrying until it succeeds. Marking the row is
    therefore the whole handover -- and unlike a best-effort call at this
    point, an unreachable agent delays revocation instead of losing it.

    The bound on that delay is how soon reconciliation runs after the mark,
    which makes it a security property rather than a tuning knob. The usage
    loop (the `usage` container, every fifteen seconds) reconciles whenever
    anything is waiting to be removed -- see `credentials_awaiting_removal` --
    so a revoked device loses its tunnel within about fifteen seconds. Before
    that it waited for a one-minute timer, and before that for the
    fifteen-minute sweep.
    """

    # Value-restricted: the two credential tables carry the same columns this
    # touches, but share no base that declares them, so a union of the two
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
            await revoke_credential_row(session, row, now)
        return len(rows)

    return await revoke_rows(WireGuardPeer) + await revoke_rows(XrayClient)


async def revoke_credential_row(
    session: AsyncSession, row: WireGuardPeer | XrayClient, now: datetime
) -> None:
    """Move one live credential, and the credential record behind it, to
    REVOKING. The caller holds the row's lock."""

    row.state = ProvisioningState.REVOKING.value
    row.updated_at = now
    credential = await session.scalar(
        select(DeviceProtocolCredential)
        .where(DeviceProtocolCredential.id == row.credential_id)
        .with_for_update()
    )
    if credential is not None:
        credential.state = ProvisioningState.REVOKING.value


async def credentials_awaiting_removal(session_factory: SessionFactory) -> bool:
    """Whether any credential is marked REVOKING and not yet off its server.

    Cheap to ask every minute, and what decides whether the usage job runs
    reconciliation: whatever marked it -- a spent allowance, an admin, a
    lapsed grant -- the credential leaves the server in the same run.
    """

    async with session_factory() as session:
        for model in (WireGuardPeer, XrayClient):
            waiting = await session.scalar(
                select(exists().where(model.state == ProvisioningState.REVOKING.value))
            )
            if waiting:
                return True
    return False
