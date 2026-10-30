"""Turn resettable counters into totals that only go up.

Every source the agent reads reports a counter since that process started, and
every one of them resets: Xray and Hysteria on restart, WireGuard when a peer
is removed and re-added. This service is the only place that knows how to
survive that, and it does it by remembering the last raw reading alongside the
running total.

The rule, per credential and per direction:

    reading >= last_reading   ->  a normal interval; add the difference
    reading <  last_reading   ->  the source restarted; add the whole reading

The second case alone loses traffic twice over. Bytes served between the last
reading and a restart are gone, and a counter that climbs past its old last
reading before anyone looks again is taken for a normal interval, so the old
reading is subtracted from bytes that were all new. On a server where every
connect and disconnect restarts Xray, that was most of the traffic.

So the changes that restart a process are bracketed (see `usage.counters`): the
counters are recorded just before, and a counter that is gone just after has
its last reading set back to zero with `forget_readings`. What is still lost
is a restart nobody asked for -- a crash, a reboot, an agent upgrade -- which
the periodic poll bounds and cannot close. The totals are accumulated, not
exact, and it is worth saying so.

Readings can overlap, so each carries when it was asked for and a row ignores
one older than its own last reading. Without that, a poll that read a process
just before a restart and was recorded just after would count it twice.
"""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.models.identity import Device, User
from nebula_api.models.provisioning import (
    DeviceProtocolCredential,
    WireGuardPeer,
    XrayClient,
)
from nebula_api.models.usage import CredentialUsage
from nebula_api.provisioning.xray_credentials import (
    EncryptedXrayCredential,
    decrypt_xray_credential,
)

_LOGGER = logging.getLogger(__name__)


def usage_digest(identity: str) -> str:
    """The stable, non-secret handle for a credential's counters.

    For VLESS and Hysteria2 the identity the serving process reports *is* the
    credential -- the same UUID the schema goes to the trouble of storing
    encrypted. Writing it into a usage table would put that secret in a
    second, unencrypted place and quietly undo that decision, so the agent
    hashes before reporting and only digests are stored.

    WireGuard public keys are not secret and would not need this, but they go
    through the same function anyway: one rule is easier to keep than two, and
    a mixed table would invite the wrong one.
    """

    return hashlib.sha256(identity.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class UsageSample:
    protocol: str
    identity: str
    rx_bytes: int
    tx_bytes: int
    # The agent's clock: when the source was read.
    sampled_at: datetime
    # The control plane's clock: when it asked. What readings of one row are
    # ordered by, because every one of them was asked for by this deployment.
    collected_at: datetime


@dataclass(frozen=True, slots=True)
class AccountUsage:
    """What one account has transferred on its current allowance.

    `rx_bytes` and `tx_bytes` are lifetime figures, and `baseline_bytes` is
    where the current allowance started. Everything a caller cares about is
    the difference, because an allowance can be granted more than once: the
    per-credential totals go on accumulating and stay auditable, while what
    the account has "used" begins again at each grant.
    """

    rx_bytes: int
    tx_bytes: int
    quota_bytes: int | None
    baseline_bytes: int = 0
    exhausted_at: datetime | None = None

    @property
    def lifetime_bytes(self) -> int:
        """Everything this account has ever transferred, across every
        allowance it has held."""

        return self.rx_bytes + self.tx_bytes

    @property
    def total_bytes(self) -> int:
        """What has been used on the current allowance.

        Clamped at zero. A baseline above the lifetime total means the
        counters moved backwards underneath a grant -- a credential deleted,
        say -- and a negative "used" would render as a bar drawn the wrong
        way round rather than as the accounting oddity it is.
        """

        return max(self.lifetime_bytes - self.baseline_bytes, 0)

    @property
    def remaining_bytes(self) -> int | None:
        """None when unmetered. Never negative -- an over-quota account has
        nothing left rather than a negative allowance, which is what a
        progress bar and a "GB left" label both need."""

        if self.quota_bytes is None:
            return None
        return max(self.quota_bytes - self.total_bytes, 0)

    @property
    def is_exhausted(self) -> bool:
        """Whether the allowance is spent.

        Unmetered is never exhausted, however much has been transferred. An
        allowance of exactly zero is exhausted immediately, which is the
        point of being able to set one.
        """

        if self.quota_bytes is None:
            return False
        return self.total_bytes >= self.quota_bytes


class UsageLedger:
    """Writes the running totals. Needs no keys, because it never has to
    work out whose a credential is -- which is why the agent client that
    records around a change can be handed one before any key is loaded."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def record(self, samples: list[UsageSample]) -> int:
        """Fold a poll's samples into the running totals.

        Returns the number of credentials whose totals moved, which is what a
        caller wants for a log line: "polled 12, 3 active" says more than a
        count of rows written.
        """

        if not samples:
            return 0

        moved = 0
        async with self._session_factory() as session:
            for sample in samples:
                if await self._apply(session, sample):
                    moved += 1
            await session.commit()
        return moved

    async def _apply(self, session: AsyncSession, sample: UsageSample) -> bool:
        # Insert-then-lock rather than lock-then-insert: two pollers racing on
        # a credential's first ever sample would both find no row, and one of
        # the two inserts would violate the unique constraint and abort the
        # whole poll. ON CONFLICT DO NOTHING makes the row's existence
        # something we can rely on before locking it.
        await session.execute(
            postgres_insert(CredentialUsage)
            .values(
                id=uuid4(),
                protocol=sample.protocol,
                identity=sample.identity,
                rx_bytes=0,
                tx_bytes=0,
                last_rx_reading=0,
                last_tx_reading=0,
            )
            .on_conflict_do_nothing(index_elements=["protocol", "identity"])
        )

        row = await session.scalar(
            select(CredentialUsage)
            .where(
                CredentialUsage.protocol == sample.protocol,
                CredentialUsage.identity == sample.identity,
            )
            .with_for_update()
        )
        if row is None:
            return False
        if _older(sample.collected_at, row.last_collected_at):
            # Read before the reading this row already holds, and recorded
            # after it. Applying it would put an earlier figure back as the
            # last reading; if a restart came in between, the next reading
            # would then count that process's traffic a second time.
            return False

        rx_delta = _delta(reading=sample.rx_bytes, last_reading=row.last_rx_reading)
        tx_delta = _delta(reading=sample.tx_bytes, last_reading=row.last_tx_reading)

        row.rx_bytes += rx_delta
        row.tx_bytes += tx_delta
        row.last_rx_reading = sample.rx_bytes
        row.last_tx_reading = sample.tx_bytes
        row.last_collected_at = sample.collected_at
        row.updated_at = sample.sampled_at

        if rx_delta or tx_delta:
            row.last_active_at = sample.sampled_at
            return True
        return False

    async def forget_readings(self, gone: list[tuple[str, str]], *, collected_at: datetime) -> int:
        """Set these credentials' last readings back to zero.

        For counters a read at `collected_at` no longer found: the process
        serving them restarted, or the peer was removed. Their totals are
        untouched -- whatever they had counted was recorded before the change
        -- but a counter that reappears starts from zero, and without this the
        ordinary rule would subtract the old reading from it for as long as it
        stayed above that figure.

        `gone` is `(protocol, identity)` pairs. A credential with no row has no
        reading to forget and gets none. Returns the number of rows changed.
        """

        if not gone:
            return 0

        forgotten = 0
        async with self._session_factory() as session:
            for protocol, identity in gone:
                row = await session.scalar(
                    select(CredentialUsage)
                    .where(
                        CredentialUsage.protocol == protocol,
                        CredentialUsage.identity == identity,
                    )
                    .with_for_update()
                )
                if row is None or _older(collected_at, row.last_collected_at):
                    continue
                row.last_rx_reading = 0
                row.last_tx_reading = 0
                row.last_collected_at = collected_at
                forgotten += 1
            await session.commit()
        return forgotten


@dataclass(frozen=True, slots=True)
class DeviceActivity:
    tunnel_active_at: datetime | None = None
    tunnel_checked_at: datetime | None = None


class UsageService(UsageLedger):
    def __init__(self, session_factory: SessionFactory, key_material: AuthKeyMaterial) -> None:
        super().__init__(session_factory)
        self._key_material = key_material

    async def usage_for_user(self, user_id: UUID) -> AccountUsage:
        """Every credential this user's devices hold, plus their allowance.

        Counts credentials belonging to revoked devices too. The bytes were
        transferred by this account and a quota that forgets them when a
        device is revoked would be a quota anyone could reset at will.
        """

        async with self._session_factory() as session:
            user = await session.scalar(select(User).where(User.id == user_id))
            if user is None:
                return AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=None)

            device_ids = list(
                (await session.scalars(select(Device.id).where(Device.user_id == user_id))).all()
            )
            digests = [
                digest
                for _device, digest in await _digests_for_devices(
                    session, device_ids, self._key_material
                )
            ]

            rx_total = 0
            tx_total = 0
            if digests:
                rows = (
                    await session.scalars(
                        select(CredentialUsage).where(CredentialUsage.identity.in_(digests))
                    )
                ).all()
                rx_total = sum(row.rx_bytes for row in rows)
                tx_total = sum(row.tx_bytes for row in rows)

        return AccountUsage(
            rx_bytes=rx_total,
            tx_bytes=tx_total,
            quota_bytes=user.traffic_quota_bytes,
            baseline_bytes=user.traffic_baseline_bytes,
            exhausted_at=user.quota_exhausted_at,
        )

    async def activity_for_devices(self, device_ids: list[UUID]) -> dict[UUID, DeviceActivity]:
        """When each device's tunnel traffic last moved, and when it was last read.

        Both, because the first alone cannot tell "quiet" from "not looked at":
        a counter nobody has read lately says nothing about now.
        """

        async with self._session_factory() as session:
            owners = await _digests_for_devices(session, device_ids, self._key_material)
            if not owners:
                return {}
            rows = (
                await session.scalars(
                    select(CredentialUsage).where(
                        CredentialUsage.identity.in_([digest for _device, digest in owners])
                    )
                )
            ).all()
        by_digest = {row.identity: row for row in rows}
        activity: dict[UUID, DeviceActivity] = {}
        for device_id, digest in owners:
            row = by_digest.get(digest)
            if row is None:
                continue
            seen = activity.get(device_id, DeviceActivity())
            activity[device_id] = DeviceActivity(
                tunnel_active_at=_latest(seen.tunnel_active_at, row.last_active_at),
                tunnel_checked_at=_latest(seen.tunnel_checked_at, row.last_collected_at),
            )
        return activity


def _latest(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _delta(*, reading: int, last_reading: int) -> int:
    """How much this reading adds to the running total.

    A reading below the last one means the serving process restarted and began
    counting again from zero, so the whole reading is new traffic.
    """

    if reading >= last_reading:
        return reading - last_reading
    return reading


def _older(collected_at: datetime, last_collected_at: datetime | None) -> bool:
    """Whether a reading was asked for before the one a row already holds.

    Equal is not older: the same read applied twice adds nothing the second
    time, because its figures are already the last reading.
    """

    return last_collected_at is not None and collected_at < last_collected_at


async def _digests_for_devices(
    session: AsyncSession, device_ids: list[UUID], key_material: AuthKeyMaterial
) -> list[tuple[UUID, str]]:
    """The counter digests the agent will report for these devices.

    WireGuard hashes its public key, which is already in plaintext. Xray and
    Hysteria2 hash the client UUID, which is not -- so it is decrypted here,
    for this one user, at read time. That is a handful of decryptions on a
    screen nobody loads in a loop, and it is the price of not keeping a second
    plaintext copy of every credential.
    """

    if not device_ids:
        return []

    digests: list[tuple[UUID, str]] = []

    peers = (
        await session.scalars(select(WireGuardPeer).where(WireGuardPeer.device_id.in_(device_ids)))
    ).all()
    digests.extend((peer.device_id, usage_digest(str(peer.public_key))) for peer in peers)

    clients = (
        await session.scalars(select(XrayClient).where(XrayClient.device_id.in_(device_ids)))
    ).all()
    for client in clients:
        credential = await session.scalar(
            select(DeviceProtocolCredential).where(
                DeviceProtocolCredential.id == client.credential_id
            )
        )
        if credential is None:
            continue
        if credential.key_material_lost_at is not None:
            # Already investigated and recorded: the key that encrypted this
            # is gone, so it will fail on every read from now until the row is
            # deleted. Warning about it each time would bury a decryption
            # failure that is actually new.
            continue
        try:
            client_uuid = decrypt_xray_credential(
                EncryptedXrayCredential(
                    key_version=int(credential.key_version or 0),
                    nonce=credential.nonce or b"",
                    ciphertext=credential.ciphertext or b"",
                ),
                device_id=credential.device_id,
                credential_id=credential.id,
                key_ring=key_material.xray_encryption_keys,
            )
        except Exception:
            # A credential encrypted under a key this process no longer holds
            # is not an error worth failing an account screen over. Its bytes
            # go unattributed, which understates usage rather than inventing
            # it.
            _LOGGER.warning("could not decrypt credential %s for usage", credential.id)
            continue
        digests.append((client.device_id, usage_digest(str(client_uuid))))

    return digests
