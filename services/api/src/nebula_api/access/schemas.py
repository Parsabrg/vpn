"""Strict, bounded HTTP contracts for admin protocol-permission and
server-assignment grants."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from nebula_api.auth.schemas import AuthModel


class UserPermissionListItem(AuthModel):
    id: UUID
    protocol_profile_id: UUID
    profile_code: str
    profile_display_name: str
    state: str
    granted_by_admin_id: UUID | None
    granted_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class UserPermissionListResponse(AuthModel):
    items: list[UserPermissionListItem]


class GrantPermissionsRequest(AuthModel):
    # Bounded: one change against the admin limit must not be a way to write
    # without one. A deployment offers a handful of profiles.
    protocol_profile_ids: list[UUID] = Field(min_length=1, max_length=50)


class UserAssignmentListItem(AuthModel):
    id: UUID
    vpn_server_id: UUID
    server_code: str
    server_display_name: str
    state: str
    assigned_by_admin_id: UUID | None
    assigned_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class UserAssignmentListResponse(AuthModel):
    items: list[UserAssignmentListItem]


class PermissionListItem(UserPermissionListItem):
    user_id: UUID
    user_email: str


class PermissionListResponse(AuthModel):
    items: list[PermissionListItem]
    total: int
    limit: int
    offset: int


class AssignmentListItem(UserAssignmentListItem):
    user_id: UUID
    user_email: str


class AssignmentListResponse(AuthModel):
    items: list[AssignmentListItem]
    total: int
    limit: int
    offset: int
