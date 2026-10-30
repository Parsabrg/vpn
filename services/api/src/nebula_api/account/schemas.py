"""Response bodies for the caller's own account and devices."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AccountResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    username: str | None
    state: str
    device_limit: int
    devices_in_use: int
    # Null means no expiry was set, which is different from an expiry that has
    # passed. The client must not render "expired" for an absent value.
    expires_at: datetime | None

    # Traffic this account has transferred on its current allowance, both
    # directions, across every credential its devices hold. Starts again from
    # zero when an allowance is granted, which is what "left" is measured
    # against.
    used_bytes: int
    # Everything this account has ever transferred, on every device it has
    # had, revoked ones included. Never starts again.
    lifetime_bytes: int
    # Null means unmetered -- not "a very large allowance". The client renders
    # the two differently and a sentinel would eventually be shown to somebody.
    quota_bytes: int | None
    # Never negative: an over-quota account has nothing left rather than a
    # negative allowance, which is what a bar and a "GB left" label both need.
    remaining_bytes: int | None


class DeviceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    platform: str
    state: str
    client_version: str
    registered_at: datetime
    is_current: bool
    # Servers this device holds a live credential on. An empty list means
    # registered but provisioned nothing -- a real state, not missing data.
    server_codes: list[str]


class DeviceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DeviceItem]
