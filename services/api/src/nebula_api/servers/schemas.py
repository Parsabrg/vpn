"""Strict, bounded HTTP contracts for user-facing server discovery."""

from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class AvailableProfileItem(AuthModel):
    code: str
    display_name: str
    protocol_id: UUID


class AvailableServerItem(AuthModel):
    code: str
    display_name: str
    public_host: str
    profiles: list[AvailableProfileItem]


class AvailableServerListResponse(AuthModel):
    items: list[AvailableServerItem]
