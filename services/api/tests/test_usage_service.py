"""Accumulating counters that reset.

The arithmetic is four lines and every one of its failure modes is silent: a
missed reset undercounts forever, a mishandled equal reading double-counts, and
a negative remainder renders as a progress bar past its end. None of it throws.
"""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.models.usage import CredentialUsage
from nebula_api.provisioning.xray_credentials import encrypt_xray_credential
from nebula_api.usage.service import (
    AccountUsage,
    UsageSample,
    UsageService,
    _delta,
    usage_digest,
)

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 9, 7, 12, 5, tzinfo=UTC)
GIGABYTE = 1024**3
USER_ID = UUID("11111111-1111-4111-8111-111111111111")
DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")


class ScriptedSession:
    """Returns the same row object for every lookup, so a test can watch it
    change across several samples the way a real row would."""

    def __init__(self, row: CredentialUsage | None) -> None:
        self.row = row
        self.commits = 0
        self.executed = 0

    async def __aenter__(self) -> "ScriptedSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, _statement: object) -> object:
        self.executed += 1
        return None

    async def scalar(self, _statement: object) -> Any:
        return self.row

    async def commit(self) -> None:
        self.commits += 1


class ScriptedFactory:
    def __init__(self, session: ScriptedSession) -> None:
        self.session = session

    def __call__(self) -> ScriptedSession:
        return self.session


def _row(**overrides: object) -> CredentialUsage:
    defaults: dict[str, object] = dict(
        id=uuid4(),
        protocol="xray",
        identity=usage_digest("some-uuid"),
        rx_bytes=0,
        tx_bytes=0,
        last_rx_reading=0,
        last_tx_reading=0,
        created_at=NOW,
        updated_at=NOW,
    )
    defaults.update(overrides)
    return CredentialUsage(**defaults)


def _service(session: ScriptedSession) -> UsageService:
    return UsageService(
        cast(SessionFactory, ScriptedFactory(session)),
        cast(AuthKeyMaterial, object()),
    )


def _sample(rx: int, tx: int, at: datetime = NOW) -> UsageSample:
    return UsageSample(
        protocol="xray",
        identity=usage_digest("some-uuid"),
        rx_bytes=rx,
        tx_bytes=tx,
        sampled_at=at,
        collected_at=at,
    )


class TestDelta:
    def test_a_rising_counter_contributes_the_difference(self) -> None:
        assert _delta(reading=500, last_reading=200) == 300

    def test_an_unchanged_counter_contributes_nothing(self) -> None:
        # The common case between polls of an idle credential. Adding the
        # reading again here would double the total on every poll.
        assert _delta(reading=200, last_reading=200) == 0

    def test_a_counter_that_went_backwards_contributes_the_whole_reading(self) -> None:
        # The serving process restarted and began counting from zero, so the
        # smaller number is entirely new traffic. Treating it as a negative
        # delta would subtract from a total that only goes up.
        assert _delta(reading=50, last_reading=900) == 50

    def test_the_first_ever_reading_is_all_new(self) -> None:
        assert _delta(reading=1234, last_reading=0) == 1234


class TestRecord:
    def test_accumulates_across_polls(self) -> None:
        row = _row()
        session = ScriptedSession(row)
        service = _service(session)

        asyncio.run(service.record([_sample(100, 200)]))
        asyncio.run(service.record([_sample(150, 260, LATER)]))

        assert row.rx_bytes == 150
        assert row.tx_bytes == 260
        assert row.last_rx_reading == 150

    def test_survives_a_restart_without_losing_the_earlier_total(self) -> None:
        # The reason the row remembers the last reading at all.
        row = _row()
        session = ScriptedSession(row)
        service = _service(session)

        asyncio.run(service.record([_sample(900, 900)]))
        asyncio.run(service.record([_sample(10, 20, LATER)]))

        assert row.rx_bytes == 910
        assert row.tx_bytes == 920

    def test_an_idle_credential_does_not_count_as_active(self) -> None:
        row = _row(rx_bytes=500, tx_bytes=500, last_rx_reading=500, last_tx_reading=500)
        session = ScriptedSession(row)

        moved = asyncio.run(_service(session).record([_sample(500, 500)]))

        assert moved == 0
        assert row.last_active_at is None

    def test_a_credential_that_moved_records_when(self) -> None:
        row = _row()
        session = ScriptedSession(row)

        moved = asyncio.run(_service(session).record([_sample(1, 1, LATER)]))

        assert moved == 1
        assert row.last_active_at == LATER

    def test_an_empty_poll_writes_nothing(self) -> None:
        session = ScriptedSession(None)
        assert asyncio.run(_service(session).record([])) == 0
        assert session.commits == 0

    def test_remembers_when_the_reading_was_asked_for(self) -> None:
        row = _row()
        session = ScriptedSession(row)

        asyncio.run(_service(session).record([_sample(1, 1, LATER)]))

        assert row.last_collected_at == LATER

    def test_a_reading_asked_for_before_the_one_held_is_ignored(self) -> None:
        # A poll that read the old process, recorded after a change had
        # already recorded the new one. Applied, the smaller figure would look
        # like a restart and be added a second time.
        row = _row(
            rx_bytes=900,
            tx_bytes=900,
            last_rx_reading=0,
            last_tx_reading=0,
            last_collected_at=LATER,
        )
        session = ScriptedSession(row)

        moved = asyncio.run(_service(session).record([_sample(850, 850, NOW)]))

        assert moved == 0
        assert (row.rx_bytes, row.tx_bytes) == (900, 900)
        assert (row.last_rx_reading, row.last_tx_reading) == (0, 0)
        assert row.last_collected_at == LATER

    def test_the_same_reading_recorded_twice_adds_nothing_the_second_time(self) -> None:
        row = _row()
        session = ScriptedSession(row)
        service = _service(session)

        asyncio.run(service.record([_sample(100, 100, LATER)]))
        asyncio.run(service.record([_sample(100, 100, LATER)]))

        assert (row.rx_bytes, row.tx_bytes) == (100, 100)


class TestForgetReadings:
    def test_sets_the_last_reading_back_to_zero_and_keeps_the_total(self) -> None:
        row = _row(rx_bytes=900, tx_bytes=400, last_rx_reading=500, last_tx_reading=300)
        session = ScriptedSession(row)

        forgotten = asyncio.run(
            _service(session).forget_readings([("xray", row.identity)], collected_at=LATER)
        )

        assert forgotten == 1
        assert (row.rx_bytes, row.tx_bytes) == (900, 400)
        assert (row.last_rx_reading, row.last_tx_reading) == (0, 0)
        assert row.last_collected_at == LATER
        assert session.commits == 1

    def test_a_counter_that_comes_back_counts_in_full(self) -> None:
        # The reason this exists. Last seen at 500 before a restart, back at
        # 600 by the next reading: all 600 are new, and without forgetting the
        # ordinary rule would add 100.
        row = _row(rx_bytes=500, tx_bytes=0, last_rx_reading=500, last_tx_reading=0)
        session = ScriptedSession(row)
        service = _service(session)

        asyncio.run(service.forget_readings([("xray", row.identity)], collected_at=NOW))
        asyncio.run(service.record([_sample(600, 0, LATER)]))

        assert row.rx_bytes == 1100

    def test_a_forget_older_than_the_reading_held_is_ignored(self) -> None:
        row = _row(last_rx_reading=500, last_tx_reading=300, last_collected_at=LATER)
        session = ScriptedSession(row)

        forgotten = asyncio.run(
            _service(session).forget_readings([("xray", row.identity)], collected_at=NOW)
        )

        assert forgotten == 0
        assert (row.last_rx_reading, row.last_tx_reading) == (500, 300)

    def test_a_credential_with_no_row_has_nothing_to_forget(self) -> None:
        session = ScriptedSession(None)

        forgotten = asyncio.run(
            _service(session).forget_readings([("xray", "a" * 64)], collected_at=NOW)
        )

        assert forgotten == 0

    def test_nothing_gone_opens_no_session(self) -> None:
        session = ScriptedSession(None)

        assert asyncio.run(_service(session).forget_readings([], collected_at=NOW)) == 0
        assert session.commits == 0


class TestAccountUsage:
    def test_total_is_both_directions(self) -> None:
        usage = AccountUsage(rx_bytes=3, tx_bytes=4, quota_bytes=None)
        assert usage.total_bytes == 7

    def test_unmetered_has_no_remainder_rather_than_a_huge_one(self) -> None:
        # None and "a very large number" must stay distinguishable: the client
        # renders one as no figure at all and the other as GB left.
        usage = AccountUsage(rx_bytes=GIGABYTE, tx_bytes=0, quota_bytes=None)
        assert usage.remaining_bytes is None

    def test_remaining_never_goes_negative(self) -> None:
        # An over-quota account has nothing left, not minus three gigabytes --
        # which is what a progress bar and a "GB left" label both need.
        usage = AccountUsage(rx_bytes=5 * GIGABYTE, tx_bytes=0, quota_bytes=2 * GIGABYTE)
        assert usage.remaining_bytes == 0

    def test_remaining_counts_both_directions_against_the_quota(self) -> None:
        # Charging only downloads would let an upload-heavy account exceed its
        # allowance without the figure ever moving.
        usage = AccountUsage(rx_bytes=GIGABYTE, tx_bytes=GIGABYTE, quota_bytes=3 * GIGABYTE)
        assert usage.remaining_bytes == GIGABYTE


def test_digest_is_stable_and_never_the_identity() -> None:
    # The agent hashes the same way; if these two ever disagree, attribution
    # silently returns zero for everybody.
    identity = str(UUID("6f3b1c8e-1111-2222-3333-44444444d410"))
    assert usage_digest(identity) == usage_digest(identity)
    assert identity not in usage_digest(identity)
    assert len(usage_digest(identity)) == 64


class AttributionSession:
    """Answers the queries `usage_for_user` makes, in the order it makes them.

    Order matters and is part of what these tests pin: the user, the device
    ids, the WireGuard keys, the Xray clients, one credential per client, then
    the usage rows.
    """

    def __init__(
        self,
        *,
        user: object | None,
        device_ids: list[UUID] | None = None,
        wireguard_keys: list[str] | None = None,
        xray_clients: list[object] | None = None,
        credentials: list[object | None] | None = None,
        usage_rows: list[CredentialUsage] | None = None,
    ) -> None:
        self._scalar_values: list[object | None] = [user, *(credentials or [])]
        self._scalars_results: list[list[object]] = [
            list(device_ids or []),
            [SimpleNamespace(device_id=DEVICE_ID, public_key=key) for key in wireguard_keys or []],
            [_owned(client) for client in xray_clients or []],
            list(usage_rows or []),
        ]
        self.scalars_calls = 0

    async def __aenter__(self) -> "AttributionSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        return self._scalar_values.pop(0) if self._scalar_values else None

    async def scalars(self, _statement: object) -> Any:
        self.scalars_calls += 1
        rows = self._scalars_results.pop(0) if self._scalars_results else []
        return _Rows(rows)


def _owned(client: object) -> object:
    if not hasattr(client, "device_id"):
        client.device_id = DEVICE_ID  # type: ignore[attr-defined]
    return client


class _Rows:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


def _user(quota: int | None = None, baseline: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        id=USER_ID,
        traffic_quota_bytes=quota,
        traffic_baseline_bytes=baseline,
        quota_exhausted_at=None,
    )


def _usage_row(identity: str, *, rx: int, tx: int) -> CredentialUsage:
    return _row(identity=identity, rx_bytes=rx, tx_bytes=tx)


def _encrypted_credential(client_uuid: UUID) -> tuple[SimpleNamespace, dict[int, bytes]]:
    """A credential encrypted the way provisioning encrypts one.

    Built through the real envelope rather than a stub, because the point of
    the test is that attribution can get the UUID back out of what the schema
    actually stores.
    """

    keys = {1: b"k" * 32}
    credential_id = uuid4()
    envelope = encrypt_xray_credential(
        client_uuid,
        device_id=DEVICE_ID,
        credential_id=credential_id,
        key_version=1,
        key_ring=keys,
    )
    credential = SimpleNamespace(
        id=credential_id,
        device_id=DEVICE_ID,
        key_version=envelope.key_version,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        key_material_lost_at=None,
    )
    return credential, keys


def _attribution_service(
    session: AttributionSession, keys: dict[int, bytes] | None = None
) -> UsageService:
    return UsageService(
        cast(SessionFactory, ScriptedFactory(cast(Any, session))),
        cast(AuthKeyMaterial, SimpleNamespace(xray_encryption_keys=keys or {})),
    )


class TestUsageForUser:
    def test_an_unknown_user_reads_as_unmetered_and_empty(self) -> None:
        # Not an exception: a session can outlive the row it authenticated
        # against, and an account screen should not 500 over it.
        session = AttributionSession(user=None)

        usage = asyncio.run(_attribution_service(session).usage_for_user(USER_ID))

        assert usage == AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=None)

    def test_a_user_with_no_devices_has_no_usage_but_keeps_their_quota(self) -> None:
        # The quota is a property of the account, not of what it has spent.
        session = AttributionSession(user=_user(quota=5 * GIGABYTE), device_ids=[])

        usage = asyncio.run(_attribution_service(session).usage_for_user(USER_ID))

        assert usage.total_bytes == 0
        assert usage.quota_bytes == 5 * GIGABYTE
        assert usage.remaining_bytes == 5 * GIGABYTE

    def test_sums_every_credential_the_account_holds(self) -> None:
        # One account, two protocols, two rows -- the figure on the screen is
        # the sum, not whichever the last poll happened to touch.
        wireguard_key = "w" * 43 + "="
        client_uuid = uuid4()
        credential, keys = _encrypted_credential(client_uuid)
        session = AttributionSession(
            user=_user(quota=10 * GIGABYTE),
            device_ids=[DEVICE_ID],
            wireguard_keys=[wireguard_key],
            xray_clients=[SimpleNamespace(credential_id=credential.id)],
            credentials=[credential],
            usage_rows=[
                _usage_row(usage_digest(wireguard_key), rx=GIGABYTE, tx=0),
                _usage_row(usage_digest(str(client_uuid)), rx=GIGABYTE, tx=GIGABYTE),
            ],
        )

        usage = asyncio.run(_attribution_service(session, keys).usage_for_user(USER_ID))

        assert usage.total_bytes == 3 * GIGABYTE
        assert usage.remaining_bytes == 7 * GIGABYTE

    def test_a_credential_that_cannot_be_decrypted_understates_rather_than_fails(self) -> None:
        # Encrypted under a key this process no longer holds. Its bytes go
        # unattributed, which is the safe direction to be wrong in: the
        # alternative is a 500 on the account screen, or inventing a figure.
        client_uuid = uuid4()
        credential, _ = _encrypted_credential(client_uuid)
        session = AttributionSession(
            user=_user(),
            device_ids=[DEVICE_ID],
            xray_clients=[SimpleNamespace(credential_id=credential.id)],
            credentials=[credential],
            usage_rows=[],
        )

        usage = asyncio.run(
            _attribution_service(session, {2: b"different-key-entirely-32-bytes!"}).usage_for_user(
                USER_ID
            )
        )

        assert usage.total_bytes == 0

    def test_a_credential_already_known_lost_is_skipped_without_retrying(self) -> None:
        # Its key is gone, so it will fail on every read from now until the
        # row is deleted. Re-reporting it each time would bury a decryption
        # failure that is actually new.
        client_uuid = uuid4()
        credential, keys = _encrypted_credential(client_uuid)
        credential.key_material_lost_at = NOW
        session = AttributionSession(
            user=_user(),
            device_ids=[DEVICE_ID],
            xray_clients=[SimpleNamespace(credential_id=credential.id)],
            credentials=[credential],
            usage_rows=[],
        )

        usage = asyncio.run(_attribution_service(session, keys).usage_for_user(USER_ID))

        assert usage.total_bytes == 0
        # The usage table is never consulted, because no digest was produced.
        assert session.scalars_calls == 3

    def test_an_xray_client_whose_credential_row_is_gone_is_skipped(self) -> None:
        session = AttributionSession(
            user=_user(),
            device_ids=[DEVICE_ID],
            xray_clients=[SimpleNamespace(credential_id=uuid4())],
            credentials=[None],
            usage_rows=[],
        )

        usage = asyncio.run(_attribution_service(session).usage_for_user(USER_ID))

        assert usage.total_bytes == 0

    def test_no_credentials_means_the_usage_table_is_not_queried_at_all(self) -> None:
        # `identity.in_([])` matches nothing, so the query would be correct --
        # but it is a pointless round trip on every account screen with a
        # freshly registered device.
        session = AttributionSession(user=_user(), device_ids=[DEVICE_ID])

        asyncio.run(_attribution_service(session).usage_for_user(USER_ID))

        # devices, wireguard keys, xray clients -- and then nothing.
        assert session.scalars_calls == 3

    def test_usage_is_attributed_by_digest_not_by_identity(self) -> None:
        # If the service ever looked rows up by the raw key, this passes only
        # by accident on WireGuard and never on Xray. Pinning it here means
        # the digest boundary cannot be quietly removed.
        wireguard_key = "w" * 43 + "="
        session = AttributionSession(
            user=_user(),
            device_ids=[DEVICE_ID],
            wireguard_keys=[wireguard_key],
            usage_rows=[_usage_row(usage_digest(wireguard_key), rx=7, tx=11)],
        )

        usage = asyncio.run(_attribution_service(session).usage_for_user(USER_ID))

        assert usage.total_bytes == 18


class TestActivityForDevices:
    def test_takes_the_latest_reading_across_a_devices_credentials(self) -> None:
        older_key, newer_key = "a" * 43 + "=", "b" * 43 + "="
        recent, earlier = (
            datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
            datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
        )
        old_row = _usage_row(usage_digest(older_key), rx=1, tx=1)
        old_row.last_active_at, old_row.last_collected_at = earlier, recent
        new_row = _usage_row(usage_digest(newer_key), rx=1, tx=1)
        new_row.last_active_at, new_row.last_collected_at = recent, earlier
        session = AttributionSession(
            user=None, wireguard_keys=[older_key, newer_key], usage_rows=[old_row, new_row]
        )
        # activity_for_devices skips the user and device-id queries.
        session._scalars_results.pop(0)

        activity = asyncio.run(_attribution_service(session, {}).activity_for_devices([DEVICE_ID]))

        assert activity[DEVICE_ID].tunnel_active_at == recent
        assert activity[DEVICE_ID].tunnel_checked_at == recent

    def test_a_device_with_no_credentials_has_no_entry(self) -> None:
        session = AttributionSession(user=None)
        session._scalars_results.pop(0)

        assert asyncio.run(_attribution_service(session, {}).activity_for_devices([])) == {}
