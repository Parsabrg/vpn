"""Setting an allowance.

Two hazards, both silent. A misparsed unit is wrong by a factor of a billion
and still looks like a number; and NULL and 0 mean opposite things -- no limit
at all, and nothing allowed -- while rendering almost identically.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from nebula_api.db.engine import SessionFactory
from nebula_api.usage.quota import (
    QuotaValueError,
    UserNotFound,
    parse_quota,
    set_traffic_quota,
)
from nebula_api.usage.service import AccountUsage, UsageService

KIB = 1024
MIB = KIB**2
GIB = KIB**3
TIB = KIB**4
NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
USER_ID = UUID("11111111-1111-4111-8111-111111111111")


class FakeUser:
    def __init__(
        self,
        quota: int | None,
        *,
        baseline: int = 0,
        exhausted_at: object = None,
    ) -> None:
        self.id = USER_ID
        self.email = "Parsa@Example.org"
        self.traffic_quota_bytes = quota
        self.traffic_baseline_bytes = baseline
        self.quota_exhausted_at = exhausted_at


class FakeSession:
    def __init__(self, user: FakeUser | None) -> None:
        self.user = user
        self.commits = 0
        self.scalar_calls = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, _statement: object) -> Any:
        # The lookup by address asks for the id alone before the row is
        # locked; both come back from the same fake user.
        self.scalar_calls += 1
        if self.user is None:
            return None
        return USER_ID if self.scalar_calls == 1 else self.user

    async def commit(self) -> None:
        self.commits += 1


def _factory(session: FakeSession) -> SessionFactory:
    return cast(SessionFactory, lambda: session)


def _usage(lifetime: int = 0, baseline: int = 0) -> UsageService:
    return cast(UsageService, FakeUsage(lifetime, baseline))


class FakeUsage:
    """Reports a fixed lifetime total, which is what a grant reads."""

    def __init__(self, lifetime: int = 0, baseline: int = 0, quota: int | None = None) -> None:
        self._usage = AccountUsage(
            rx_bytes=lifetime,
            tx_bytes=0,
            quota_bytes=quota,
            baseline_bytes=baseline,
        )

    async def usage_for_user(self, _user_id: UUID) -> AccountUsage:
        return self._usage


class TestParseQuota:
    def test_reads_each_unit(self) -> None:
        assert parse_quota("500B") == 500
        assert parse_quota("500KB") == 500 * KIB
        assert parse_quota("500MB") == 500 * MIB
        assert parse_quota("100GB") == 100 * GIB
        assert parse_quota("2TB") == 2 * TIB

    def test_units_are_binary(self) -> None:
        # 1 GB is 1024 MB here, matching what the servers count and what the
        # app displays. Mixing conventions turns a "1 GB" allowance into an
        # argument about seven per cent of it.
        assert parse_quota("1GB") == 1073741824
        assert parse_quota("1024MB") == parse_quota("1GB")

    def test_accepts_a_fraction(self) -> None:
        assert parse_quota("1.5TB") == int(1.5 * TIB)

    def test_is_case_and_space_insensitive(self) -> None:
        assert parse_quota(" 100 gb ") == parse_quota("100GB")

    def test_a_bare_number_is_refused_rather_than_guessed(self) -> None:
        # The whole reason a unit is mandatory: "100" could be a hundred bytes
        # or a hundred gigabytes, and an operator who meant the second would
        # not find out until somebody complained.
        with pytest.raises(QuotaValueError, match="write the unit"):
            parse_quota("100")

    def test_an_unknown_unit_names_the_ones_that_work(self) -> None:
        with pytest.raises(QuotaValueError, match="GB"):
            parse_quota("100gigs")

    def test_a_negative_allowance_is_not_a_number_this_accepts(self) -> None:
        with pytest.raises(QuotaValueError):
            parse_quota("-5GB")

    def test_an_allowance_too_large_to_store_is_refused(self) -> None:
        # BIGINT. Wrapping would store a negative allowance, which every
        # comparison downstream would read as "already over".
        with pytest.raises(QuotaValueError, match="larger than"):
            parse_quota("9999999TB")

    def test_zero_parses_because_it_is_a_real_allowance(self) -> None:
        assert parse_quota("0B") == 0


class TestSetTrafficQuota:
    def test_sets_an_allowance_and_reports_what_it_replaced(self) -> None:
        session = FakeSession(FakeUser(quota=None))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session), _usage(), email="owner@example.org", quota_bytes=100 * GIB
            )
        )

        assert session.user is not None
        assert session.user.traffic_quota_bytes == 100 * GIB
        assert change.previous_bytes is None
        assert change.quota_bytes == 100 * GIB
        assert session.commits >= 1

    def test_unmetered_clears_the_allowance_rather_than_zeroing_it(self) -> None:
        # None and 0 are opposites. Writing 0 here would stop the account
        # transferring anything, which is the reverse of what was asked.
        session = FakeSession(FakeUser(quota=50 * GIB))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session), _usage(), email="owner@example.org", quota_bytes=None
            )
        )

        assert session.user is not None
        assert session.user.traffic_quota_bytes is None
        assert change.quota_bytes is None

    def test_zero_is_stored_as_zero_not_as_unmetered(self) -> None:
        # The other half of the same distinction: a way to stop an account
        # transferring without revoking its devices.
        session = FakeSession(FakeUser(quota=None))

        change = asyncio.run(
            set_traffic_quota(_factory(session), _usage(), email="owner@example.org", quota_bytes=0)
        )

        assert session.user is not None
        assert session.user.traffic_quota_bytes == 0
        assert change.quota_bytes == 0
        assert change.quota_bytes is not None

    def test_setting_the_same_allowance_again_is_reported_as_unchanged(self) -> None:
        session = FakeSession(FakeUser(quota=10 * GIB))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session), _usage(), email="owner@example.org", quota_bytes=10 * GIB
            )
        )

        assert change.unchanged

    def test_an_address_typed_as_received_still_finds_the_account(self) -> None:
        # Registration normalizes; a lookup that did not would report a real
        # account missing because the operator copied it with capitals.
        session = FakeSession(FakeUser(quota=None))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session), _usage(), email="  Parsa@Example.ORG ", quota_bytes=GIB
            )
        )

        assert change.user_id == USER_ID

    def test_an_unknown_address_is_a_lookup_failure_not_a_silent_no_op(self) -> None:
        session = FakeSession(None)

        with pytest.raises(UserNotFound):
            asyncio.run(
                set_traffic_quota(
                    _factory(session), _usage(), email="nobody@example.org", quota_bytes=GIB
                )
            )

        assert session.commits == 0

    def test_a_malformed_address_is_refused_before_any_query(self) -> None:
        session = FakeSession(FakeUser(quota=None))

        with pytest.raises(ValueError):
            asyncio.run(
                set_traffic_quota(
                    _factory(session), _usage(), email="not-an-address", quota_bytes=GIB
                )
            )

        assert session.commits == 0


def test_the_change_carries_the_address_as_stored_not_as_typed() -> None:
    # So the confirmation an operator reads back is the account's own
    # address, which is what they would search for if it were the wrong one.
    session = FakeSession(FakeUser(quota=None))

    change = asyncio.run(
        set_traffic_quota(_factory(session), _usage(), email="owner@example.org", quota_bytes=GIB)
    )

    assert change.email == "Parsa@Example.org"
    assert change.user_id != uuid4()


class TestGrantingStartsOver:
    """Topping up is a grant, not an edit.

    The reported requirement: an account on a 100 GB plan that runs out and is
    given 200 GB should have 200 GB available and read as nothing used --
    without losing the record of what it spent before.
    """

    def test_a_new_allowance_starts_at_zero_used(self) -> None:
        # 100 GB already transferred in this account's lifetime. A fresh
        # 200 GB grant moves the mark to here, so "used" begins again.
        session = FakeSession(FakeUser(quota=100 * GIB, baseline=0))

        asyncio.run(
            set_traffic_quota(
                _factory(session),
                _usage(lifetime=100 * GIB),
                email="owner@example.org",
                quota_bytes=200 * GIB,
            )
        )

        assert session.user is not None
        assert session.user.traffic_quota_bytes == 200 * GIB
        assert session.user.traffic_baseline_bytes == 100 * GIB

    def test_the_grant_reports_what_the_previous_allowance_had_spent(self) -> None:
        # So an operator can see what they are writing off rather than
        # discovering the figure vanished.
        session = FakeSession(FakeUser(quota=100 * GIB, baseline=40 * GIB))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session),
                _usage(lifetime=140 * GIB, baseline=40 * GIB),
                email="owner@example.org",
                quota_bytes=200 * GIB,
            )
        )

        assert change.previous_used_bytes == 100 * GIB

    def test_granting_lifts_a_cut_off(self) -> None:
        # The account was revoked for running out. A new allowance is what
        # lets it provision again; nothing else clears this mark.
        session = FakeSession(FakeUser(quota=GIB, baseline=0, exhausted_at=NOW))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session),
                _usage(lifetime=2 * GIB),
                email="owner@example.org",
                quota_bytes=200 * GIB,
            )
        )

        assert session.user is not None
        assert session.user.quota_exhausted_at is None
        assert change.restored_access

    def test_a_grant_to_an_account_that_was_fine_does_not_claim_to_restore(self) -> None:
        session = FakeSession(FakeUser(quota=GIB, baseline=0))

        change = asyncio.run(
            set_traffic_quota(
                _factory(session),
                _usage(lifetime=0),
                email="owner@example.org",
                quota_bytes=200 * GIB,
            )
        )

        assert not change.restored_access

    def test_going_unmetered_also_starts_the_mark_over(self) -> None:
        # Nothing reads the baseline while unmetered, but leaving a stale one
        # behind would make a later metered grant inherit it.
        session = FakeSession(FakeUser(quota=GIB, baseline=0))

        asyncio.run(
            set_traffic_quota(
                _factory(session),
                _usage(lifetime=7 * GIB),
                email="owner@example.org",
                quota_bytes=None,
            )
        )

        assert session.user is not None
        assert session.user.traffic_baseline_bytes == 7 * GIB
