"""Read-only administrator audit log routes."""

from datetime import datetime
from typing import cast
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from nebula_api.audit.schemas import AuditLogListItem, AuditLogListResponse
from nebula_api.audit.service import AuditLogEntry, AuditLogFilters, AuditLogService
from nebula_api.auth.admin_authorization import require_admin_session
from nebula_api.auth.http import apply_auth_response_headers

router = APIRouter(prefix="/v1/admin/audit-log", tags=["admin-audit-log"])


def _service(request: Request) -> AuditLogService:
    service = getattr(request.app.state, "audit_log_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit log is temporarily unavailable",
        )
    return cast(AuditLogService, service)


@router.get("/", response_model=AuditLogListResponse)
async def list_audit_log(
    request: Request,
    response: Response,
    actor_kind: str | None = None,
    target_kind: str | None = None,
    event_code: str | None = None,
    outcome: str | None = None,
    actor_id: UUID | None = None,
    target_id: UUID | None = None,
    recorded_after: datetime | None = None,
    recorded_before: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditLogListResponse:
    await require_admin_session(request)
    page = await _service(request).list_events(
        filters=AuditLogFilters(
            actor_kind=actor_kind,
            target_kind=target_kind,
            event_code=event_code,
            outcome=outcome,
            actor_id=actor_id,
            target_id=target_id,
            recorded_after=recorded_after,
            recorded_before=recorded_before,
        ),
        limit=limit,
        offset=offset,
    )
    apply_auth_response_headers(response)
    return AuditLogListResponse(
        items=[_to_item(entry) for entry in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


def _to_item(entry: AuditLogEntry) -> AuditLogListItem:
    return AuditLogListItem(
        id=entry.id,
        actor_kind=entry.actor_kind,
        actor_id=entry.actor_id,
        target_kind=entry.target_kind,
        target_id=entry.target_id,
        event_code=entry.event_code,
        outcome=entry.outcome,
        reason_code=entry.reason_code,
        request_id=entry.request_id,
        recorded_at=entry.recorded_at,
    )
