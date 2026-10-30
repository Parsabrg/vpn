"""Setting how much traffic an account is allowed.

The column has existed since traffic accounting shipped; nothing could write
it, so every account read as unmetered. This is the write.

Two values that look alike and mean opposite things run through here, and
keeping them apart is most of the work:

    NULL      unmetered -- no limit at all
    0         metered at zero -- nothing allowed

Both render as "no number of gigabytes", and confusing them either hands
somebody unlimited traffic or cuts them off entirely. So the caller must say
which it means, and the result says back which one it wrote.
"""

import re
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from nebula_api.db.engine import SessionFactory
from nebula_api.identity import normalize_email
from nebula_api.models.identity import User
from nebula_api.usage.service import UsageService

_KIB = 1024
_UNITS = {
    "B": 1,
    "KB": _KIB,
    "MB": _KIB**2,
    "GB": _KIB**3,
    "TB": _KIB**4,
}
_QUOTA_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)\s*$")

# Postgres BIGINT. A quota above this cannot be stored, and silently wrapping
# a limit is how somebody ends up with a negative allowance.
_MAX_QUOTA_BYTES = 2**63 - 1


class QuotaValueError(ValueError):
    """The requested allowance could not be understood, with a reason to print."""


def parse_quota(text: str) -> int:
    """Turn `100GB` into a byte count.

    Binary units -- 1 GB is 1024 MB here, matching what the servers count and
    what the app displays. Mixing conventions is how a "1 GB" allowance
    becomes an argument about seven per cent of it.

    A bare number is refused rather than guessed at. `100` could be a hundred
    bytes or a hundred gigabytes, the two differ by a factor of a billion, and
    an operator who meant the second would not notice being given the first
    until somebody complained.
    """

    match = _QUOTA_PATTERN.match(text)
    if match is None:
        raise QuotaValueError(
            f"could not read {text!r} as an allowance; write the unit, e.g. 100GB, 1.5TB, 500MB"
        )

    amount, unit = match.group(1), match.group(2).upper()
    if unit not in _UNITS:
        raise QuotaValueError(
            f"unknown unit {match.group(2)!r}; use one of {', '.join(_UNITS)} (1 GB = 1024 MB)"
        )

    quota = int(float(amount) * _UNITS[unit])
    if quota > _MAX_QUOTA_BYTES:
        raise QuotaValueError(f"{text!r} is larger than this system can store as an allowance")
    return quota


@dataclass(frozen=True, slots=True)
class QuotaChange:
    user_id: UUID
    email: str
    previous_bytes: int | None
    quota_bytes: int | None
    # What the account had used on the allowance being replaced. Reported
    # so an operator can see what they are writing off, and because it is
    # the figure that returns to zero.
    previous_used_bytes: int = 0
    # Whether this grant restored access that a spent allowance had taken.
    restored_access: bool = False

    @property
    def unchanged(self) -> bool:
        return self.previous_bytes == self.quota_bytes


class UserNotFound(LookupError):
    """No account with that address."""


async def set_traffic_quota(
    session_factory: SessionFactory,
    usage: UsageService,
    *,
    email: str,
    quota_bytes: int | None,
) -> QuotaChange:
    """Grant an allowance, replacing whatever the account had.

    This is a grant, not an edit. The new allowance starts at zero used: the
    baseline moves to today's lifetime total, so "200GB" means two hundred
    gigabytes from now rather than two hundred counted from whenever the
    account was created. An operator selling a top-up can type the size of the
    thing they sold, which is the only figure they actually know.

    Nothing is reset in place. Per-credential totals go on accumulating and
    stay auditable; only the mark they are read against moves.

    `quota_bytes=None` means unmetered. `0` means metered at zero, which is a
    real state -- a way to stop an account transferring anything without
    revoking its devices -- and deliberately not the same thing.

    The address is normalized the same way registration normalizes it, so an
    operator typing the address as they received it finds the account rather
    than reporting it missing.
    """

    normalized = normalize_email(email)
    async with session_factory() as session:
        user_id = await session.scalar(select(User.id).where(User.email_normalized == normalized))
    if user_id is None:
        raise UserNotFound(normalized)
    return await grant_traffic_quota(
        session_factory, usage, user_id=user_id, quota_bytes=quota_bytes
    )


async def grant_traffic_quota(
    session_factory: SessionFactory,
    usage: UsageService,
    *,
    user_id: UUID,
    quota_bytes: int | None,
) -> QuotaChange:
    """Grant an allowance to an account already identified.

    The same operation as [set_traffic_quota] without the address lookup --
    what the admin API calls, since it already holds the account.
    """

    # Read outside the write transaction: attribution decrypts credentials and
    # touches several tables, and holding a row lock across it would serialise
    # grants against the usage poll.
    before = await usage.usage_for_user(user_id)

    async with session_factory() as session:
        user = await session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise UserNotFound(str(user_id))

        previous = user.traffic_quota_bytes
        was_exhausted = user.quota_exhausted_at is not None

        user.traffic_quota_bytes = quota_bytes
        user.traffic_baseline_bytes = before.lifetime_bytes
        # The account is no longer cut off for having spent an allowance it no
        # longer has. Credentials it lost are not restored here -- they were
        # revoked on the servers -- but nothing now refuses a new one, so the
        # app re-provisions on the next connect.
        user.quota_exhausted_at = None
        await session.commit()

        return QuotaChange(
            user_id=user.id,
            email=user.email,
            previous_bytes=previous,
            quota_bytes=quota_bytes,
            previous_used_bytes=before.total_bytes,
            restored_access=was_exhausted,
        )
