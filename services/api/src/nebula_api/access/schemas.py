"""Strict, bounded HTTP contracts for admin protocol-permission and
server-assignment grants."""

from datetime import datetime
from uuid import UUID

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
