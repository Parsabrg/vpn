"""Strict, bounded HTTP contracts for the read-only audit log view."""

from datetime import datetime
from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class AuditLogListItem(AuthModel):
    id: UUID
    actor_kind: str
    actor_id: UUID | None
    target_kind: str
    target_id: UUID
    event_code: str
    outcome: str
    reason_code: str | None
    request_id: UUID | None
    recorded_at: datetime


class AuditLogListResponse(AuthModel):
    items: list[AuditLogListItem]
    total: int
    limit: int
    offset: int
