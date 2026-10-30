"""Cutting off an account that has spent its allowance.

The failure modes are asymmetric and both bad. Not revoking means a limit that
is only a label. Revoking the wrong account takes somebody's service away for
no reason -- and unlike most bugs here, that one is visible to a person
immediately and is not self-correcting.
"""

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

import nebula_api.usage.enforcement as enforcement
from nebula_api.db.engine import SessionFactory
from nebula_api.usage.enforcement import EnforcementSummary, enforce_traffic_quotas
from nebula_api.usage.service import AccountUsage, UsageService

GIGABYTE = 1024**3
NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)


class FakeUser:
    def __init__(self, *, quota: int | None, exhausted_at: datetime | None = None) -> None:
        self.id = uuid4()
        self.traffic_quota_bytes = quota
        self.quota_exhausted_at = exhausted_at


class FakeSession:
    """Answers the sweep's queries and records what it revoked."""

    def __init__(self, users: list[FakeUser]) -> None:
        self.users = users
        self.commits = 0
        self.added: list[object] = []
        self.revoked_devices: list[UUID] = []
        self._scalars_calls = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalars(self, statement: object) -> Any:
        self._scalars_calls += 1
        text = str(statement)
        if "devices" in text.lower():
            # One device per account, enough to prove revocation is attempted.
            return _Rows([uuid4()])
        live = [u.id for u in self.users if u.quota_exhausted_at is None]
        spent = [u.id for u in self.users if u.quota_exhausted_at is not None]
        # The sweep asks for the not-yet-enforced set first, then the
        # already-enforced one.
        return _Rows(live if self._scalars_calls == 1 else spent)

    async def scalar(self, statement: object) -> Any:
        for user in self.users:
            if str(user.id) in str(statement.compile().params.values()):  # type: ignore[attr-defined]
                return user
        return self.users[0] if self.users else None

    def add(self, value: object) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        self.commits += 1


class _Rows:
    def __init__(self, rows: Sequence[object]) -> None:
        self._rows = list(rows)

    def all(self) -> list[object]:
        return self._rows


class FakeUsage:
    def __init__(self, usage: dict[UUID, AccountUsage]) -> None:
        self._usage = usage

    async def usage_for_user(self, user_id: UUID) -> AccountUsage:
        return self._usage[user_id]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    session: FakeSession,
    usage: dict[UUID, AccountUsage],
    revoked: list[UUID] | None = None,
) -> EnforcementSummary:
    async def fake_revoke(_session: object, device_id: UUID, _now: datetime) -> int:
        if revoked is not None:
            revoked.append(device_id)
        return 1

    monkeypatch.setattr(enforcement, "revoke_device_credentials", fake_revoke)
    return asyncio.run(
        enforce_traffic_quotas(
            cast(SessionFactory, lambda: session), cast(UsageService, FakeUsage(usage))
        )
    )


def _usage(used: int, quota: int | None) -> AccountUsage:
    return AccountUsage(rx_bytes=used, tx_bytes=0, quota_bytes=quota, baseline_bytes=0)


class TestWhoGetsCutOff:
    def test_an_account_that_spent_its_allowance_loses_its_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user = FakeUser(quota=100 * GIGABYTE)
        session = FakeSession([user])
        revoked: list[UUID] = []

        summary = _run(
            monkeypatch, session, {user.id: _usage(120 * GIGABYTE, 100 * GIGABYTE)}, revoked
        )

        assert summary.accounts_exhausted == 1
        assert summary.credentials_revoked == 1
        assert revoked
        assert user.quota_exhausted_at is not None

    def test_an_account_inside_its_allowance_is_left_alone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user = FakeUser(quota=100 * GIGABYTE)
        session = FakeSession([user])
        revoked: list[UUID] = []

        summary = _run(
            monkeypatch, session, {user.id: _usage(40 * GIGABYTE, 100 * GIGABYTE)}, revoked
        )

        assert summary.accounts_exhausted == 0
        assert revoked == []
        assert user.quota_exhausted_at is None

    def test_exactly_at_the_allowance_counts_as_spent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A limit somebody reaches exactly has been reached. Off-by-one here
        # would let a 100 GB plan carry on at exactly 100 GB forever.
        user = FakeUser(quota=100 * GIGABYTE)
        session = FakeSession([user])

        summary = _run(monkeypatch, session, {user.id: _usage(100 * GIGABYTE, 100 * GIGABYTE)})

        assert summary.accounts_exhausted == 1

    def test_an_account_already_cut_off_is_not_revoked_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Its credentials went the first time. Doing it again every fifteen
        # minutes would write an audit event a pass and say nothing new.
        user = FakeUser(quota=GIGABYTE, exhausted_at=NOW)
        session = FakeSession([user])
        revoked: list[UUID] = []

        summary = _run(monkeypatch, session, {user.id: _usage(9 * GIGABYTE, GIGABYTE)}, revoked)

        assert summary.already_enforced == 1
        assert summary.accounts_exhausted == 0
        assert revoked == []


class TestUnmeteredIsNeverCutOff:
    def test_an_unmetered_account_is_not_even_looked_at(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The query filters on a quota being set, so no amount of traffic
        # reaches the comparison. Unmetered means unmetered.
        session = FakeSession([])

        summary = _run(monkeypatch, session, {})

        assert summary.accounts_checked == 0
        assert summary.accounts_exhausted == 0


def test_a_zero_allowance_is_exhausted_immediately() -> None:
    # Metered at zero is a real state -- a way to stop an account without
    # disabling it -- and it takes effect on the first sweep.
    usage = AccountUsage(rx_bytes=0, tx_bytes=0, quota_bytes=0, baseline_bytes=0)

    assert usage.is_exhausted


def test_an_unmetered_account_is_never_exhausted_however_much_it_moves() -> None:
    usage = AccountUsage(rx_bytes=900 * GIGABYTE, tx_bytes=0, quota_bytes=None, baseline_bytes=0)

    assert not usage.is_exhausted


class TestUsageIsRelativeToTheGrant:
    def test_only_traffic_since_the_grant_counts(self) -> None:
        # 140 GB lifetime, but the current 200 GB allowance began at 100 GB.
        usage = AccountUsage(
            rx_bytes=140 * GIGABYTE,
            tx_bytes=0,
            quota_bytes=200 * GIGABYTE,
            baseline_bytes=100 * GIGABYTE,
        )

        assert usage.total_bytes == 40 * GIGABYTE
        assert usage.remaining_bytes == 160 * GIGABYTE
        assert not usage.is_exhausted

    def test_the_lifetime_figure_survives_a_grant(self) -> None:
        # A top-up must not look like the history was deleted.
        usage = AccountUsage(
            rx_bytes=140 * GIGABYTE,
            tx_bytes=0,
            quota_bytes=200 * GIGABYTE,
            baseline_bytes=140 * GIGABYTE,
        )

        assert usage.total_bytes == 0
        assert usage.lifetime_bytes == 140 * GIGABYTE

    def test_a_baseline_above_the_total_does_not_go_negative(self) -> None:
        # Counters moved backwards under a grant -- a credential deleted, say.
        # A negative "used" would render as a bar drawn the wrong way round.
        usage = AccountUsage(
            rx_bytes=GIGABYTE,
            tx_bytes=0,
            quota_bytes=10 * GIGABYTE,
            baseline_bytes=5 * GIGABYTE,
        )

        assert usage.total_bytes == 0
