"""User-facing, session-gated routes for the caller's own account."""

import logging
from typing import Annotated, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from nebula_api.account.schemas import AccountResponse, DeviceItem, DeviceListResponse
from nebula_api.account.service import (
    AccountEntry,
    AccountService,
    DeviceEntry,
    DeviceRevocationRefused,
)
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.auth.user_authorization import require_user_session
from nebula_api.auth.user_service import AuthenticatedUser

router = APIRouter(prefix="/v1/account", tags=["account"])
_LOGGER = logging.getLogger(__name__)


def _service(request: Request) -> AccountService:
    service = getattr(request.app.state, "account_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Account information is temporarily unavailable",
        )
    return cast(AccountService, service)


@router.get("", response_model=AccountResponse)
async def get_account(
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> AccountResponse:
    entry: AccountEntry | None = await _service(request).get_account(principal.user_id)
    if entry is None:
        # The session authenticated, so the user existed a moment ago. Treat a
        # miss as gone rather than as a server fault.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    apply_auth_response_headers(response)
    return AccountResponse(
        email=entry.email,
        username=entry.username,
        state=entry.state,
        device_limit=entry.device_limit,
        devices_in_use=entry.devices_in_use,
        expires_at=entry.expires_at,
        used_bytes=entry.used_bytes,
        lifetime_bytes=entry.lifetime_bytes,
        quota_bytes=entry.quota_bytes,
        remaining_bytes=entry.remaining_bytes,
    )


@router.get("/devices", response_model=DeviceListResponse)
async def list_devices(
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> DeviceListResponse:
    entries: list[DeviceEntry] = await _service(request).list_devices(
        principal.user_id, principal.device_id
    )
    apply_auth_response_headers(response)
    return DeviceListResponse(
        items=[
            DeviceItem(
                id=entry.id,
                name=entry.name,
                platform=entry.platform,
                state=entry.state,
                client_version=entry.client_version,
                registered_at=entry.registered_at,
                is_current=entry.is_current,
                server_codes=entry.server_codes,
            )
            for entry in entries
        ]
    )


@router.post("/devices/{device_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(
    device_id: UUID,
    request: Request,
    response: Response,
    principal: Annotated[AuthenticatedUser, Depends(require_user_session)],
) -> Response:
    try:
        await _service(request).revoke_device(
            user_id=principal.user_id,
            device_id=device_id,
            current_device_id=principal.device_id,
            request_id=uuid4(),
        )
    except DeviceRevocationRefused as refusal:
        # 404 for a device that is not the caller's, so the response cannot be
        # used to probe for device ids on other accounts. 409 for the two
        # cases that are about this account's own state and are worth telling
        # the user apart, since the client can word them.
        if refusal.reason_code == "not_found":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
            ) from refusal
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=refusal.reason_code
        ) from refusal

    apply_auth_response_headers(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers=dict(response.headers))
