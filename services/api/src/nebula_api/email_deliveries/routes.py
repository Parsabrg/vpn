"""Read-only administrator email delivery status routes."""

from typing import cast

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from nebula_api.auth.admin_authorization import require_admin_session
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.email_deliveries.schemas import EmailDeliveryListItem, EmailDeliveryListResponse
from nebula_api.email_deliveries.service import (
    EmailDeliveryEntry,
    EmailDeliveryFilters,
    EmailDeliveryService,
)

router = APIRouter(prefix="/v1/admin/email-deliveries", tags=["admin-email-deliveries"])


def _service(request: Request) -> EmailDeliveryService:
    service = getattr(request.app.state, "email_delivery_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email delivery status is temporarily unavailable",
        )
    return cast(EmailDeliveryService, service)


@router.get("/", response_model=EmailDeliveryListResponse)
async def list_email_deliveries(
    request: Request,
    response: Response,
    state: str | None = None,
    template_code: str | None = None,
    subject_kind: str | None = None,
    recipient_address: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> EmailDeliveryListResponse:
    await require_admin_session(request)
    page = await _service(request).list_events(
        filters=EmailDeliveryFilters(
            state=state,
            template_code=template_code,
            subject_kind=subject_kind,
            recipient_address=recipient_address,
        ),
        limit=limit,
        offset=offset,
    )
    apply_auth_response_headers(response)
    return EmailDeliveryListResponse(
        items=[_to_item(entry) for entry in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


def _to_item(entry: EmailDeliveryEntry) -> EmailDeliveryListItem:
    return EmailDeliveryListItem(
        id=entry.id,
        template_code=entry.template_code,
        recipient_address=entry.recipient_address,
        subject_kind=entry.subject_kind,
        subject_id=entry.subject_id,
        state=entry.state,
        attempt_count=entry.attempt_count,
        available_at=entry.available_at,
        sent_at=entry.sent_at,
        provider_message_id=entry.provider_message_id,
        result_code=entry.result_code,
    )
