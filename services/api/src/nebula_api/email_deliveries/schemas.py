"""Strict, bounded HTTP contracts for the read-only email delivery status view."""

from datetime import datetime
from uuid import UUID

from nebula_api.auth.schemas import AuthModel


class EmailDeliveryListItem(AuthModel):
    id: UUID
    template_code: str
    recipient_address: str
    subject_kind: str
    subject_id: UUID
    state: str
    attempt_count: int
    available_at: datetime
    sent_at: datetime | None
    provider_message_id: str | None
    result_code: str | None


class EmailDeliveryListResponse(AuthModel):
    items: list[EmailDeliveryListItem]
    total: int
    limit: int
    offset: int
