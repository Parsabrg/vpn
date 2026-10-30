"""Strict, bounded HTTP contracts for admin user management."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from nebula_api.auth.schemas import AuthModel
from nebula_api.dns_profiles import DnsProfile


class UserListItem(AuthModel):
    id: UUID
    email: str
    username: str | None
    state: str
    device_limit: int
    dns_profile: str = "default"
    expires_at: datetime | None
    activated_at: datetime | None
    disabled_at: datetime | None
    created_at: datetime


class UserListResponse(AuthModel):
    items: list[UserListItem]
    total: int
    limit: int
    offset: int


class DeviceListItem(AuthModel):
    id: UUID
    name: str
    platform: str
    client_version: str
    state: str
    revoked_at: datetime | None
    # Null follows the account's profile.
    dns_profile: str | None = None
    # Online status, from evidence rather than a guess. "active": tunnel
    # traffic moved within the last couple of counter reads; "quiet": the
    # counters were read lately and nothing moved; "unknown": no recent read,
    # so nothing honest can be said. The timestamps are the evidence.
    activity: Literal["active", "quiet", "unknown"] = "unknown"
    tunnel_active_at: datetime | None = None
    tunnel_checked_at: datetime | None = None
    app_seen_at: datetime | None = None


class UserSessionListItem(AuthModel):
    id: UUID
    device_id: UUID
    state: str
    expires_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None


class TrafficAllowanceItem(AuthModel):
    """What the account has spent on its current allowance, and what is left."""

    used_bytes: int
    # Null means unmetered -- not "a very large allowance". The panel renders
    # the two differently and a sentinel would eventually be shown as a number.
    quota_bytes: int | None
    remaining_bytes: int | None
    # Set when the allowance was found spent and the credentials taken away.
    # Null means the account is not cut off, which is not the same as having
    # traffic left: a grant clears this, and the sweep sets it again.
    exhausted_at: datetime | None
    # Everything the account has ever transferred, across every allowance it
    # has held. Shown beside the current figure so a top-up does not look like
    # the history vanished.
    lifetime_bytes: int


class GrantTrafficQuotaRequest(AuthModel):
    """A new allowance, replacing whatever the account had.

    `quota_bytes` is required and nullable rather than optional: absent and
    null would otherwise both have to mean something, and the two candidate
    meanings -- unmetered, and leave it alone -- are far apart.
    """

    quota_bytes: int | None = Field(ge=0, le=2**63 - 1)


class SetDnsProfileRequest(AuthModel):
    """Which resolver the account's tunnels are given."""

    dns_profile: DnsProfile


class SetDeviceDnsProfileRequest(AuthModel):
    """A device's own profile; null follows the account's."""

    dns_profile: DnsProfile | None


class SetDeviceLimitRequest(AuthModel):
    """How many devices the account may have active at once."""

    device_limit: int = Field(ge=1, le=100)


class SetExpiryRequest(AuthModel):
    """When the account's access ends. Required and nullable, so "never"
    is said out loud rather than read from a missing field."""

    expires_at: AwareDatetime | None


class UserDetailResponse(AuthModel):
    user: UserListItem
    devices: list[DeviceListItem]
    sessions: list[UserSessionListItem]
    traffic: TrafficAllowanceItem
