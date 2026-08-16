"""Strict, bounded HTTP contracts for admin user management."""

from datetime import datetime
from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class UserListItem(AuthModel):
    id: UUID
    email: str
    username: str | None
    state: str
    device_limit: int
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


class UserSessionListItem(AuthModel):
    id: UUID
    device_id: UUID
    state: str
    expires_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None


class UserDetailResponse(AuthModel):
    user: UserListItem
    devices: list[DeviceListItem]
    sessions: list[UserSessionListItem]
