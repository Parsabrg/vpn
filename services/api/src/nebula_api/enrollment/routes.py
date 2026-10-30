"""The route a node with no identity uses to obtain one.

Public, and it has to be: a VPS being enrolled holds an enrollment token and
nothing else, so requiring authentication would make enrolment impossible.
The token in the body is the credential, exactly as the activation and
password-reset routes work.

What keeps that safe is the service behind it, not this layer. Every refusal
there is indistinguishable, tokens are single-use and short-lived, and the
certificate's contents come from the token rather than from the request.
"""

import logging
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from nebula_api.auth.admin_authorization import authorize_admin_mutation
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.enrollment.schemas import (
    EnrollNodeRequest,
    EnrollNodeResponse,
    MintEnrollmentTokenRequest,
    MintEnrollmentTokenResponse,
)
from nebula_api.enrollment.service import EnrollmentRejected, EnrollmentService
from nebula_api.models.types import AdminRole
from nebula_api.pki import PkiError, load_certificate_authority
from nebula_api.settings import Settings

router = APIRouter(prefix="/v1/nodes", tags=["nodes"])
admin_router = APIRouter(prefix="/v1/admin/nodes", tags=["admin-nodes"])
_LOGGER = logging.getLogger(__name__)

_GENERIC_DETAIL = "Enrollment was not accepted"


def get_service(request: Request) -> EnrollmentService:
    service = getattr(request.app.state, "enrollment_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Node enrollment is temporarily unavailable",
        )
    return cast(EnrollmentService, service)


@router.post("/enroll", response_model=EnrollNodeResponse)
async def enroll_node(
    payload: EnrollNodeRequest,
    request: Request,
    service: Annotated[EnrollmentService, Depends(get_service)],
) -> EnrollNodeResponse:
    """Exchange an enrollment token for a signed node certificate."""

    settings = cast(Settings, request.app.state.settings)
    try:
        authority = load_certificate_authority(
            settings.resolved_node_ca_certificate_file, settings.resolved_node_ca_key_file
        )
    except PkiError:
        # The deployment cannot issue certificates at all. That is an
        # operator problem rather than a bad request, and saying so is more
        # useful than refusing this particular token.
        _LOGGER.exception("the node certificate authority could not be loaded")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Node enrollment is temporarily unavailable",
        ) from None

    try:
        enrolled = await service.redeem(
            token=payload.token,
            csr_pem=payload.certificate_request.encode("ascii", errors="strict"),
            authority=authority,
            public_host=payload.public_host,
            agent_host=payload.agent_host,
            agent_port=payload.agent_port,
            protocol_profiles=payload.protocol_profiles,
        )
    except UnicodeEncodeError:
        # A certificate request is PEM, which is ASCII. Refused the same way
        # as every other bad token so the response says nothing new.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL
        ) from None
    except EnrollmentRejected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_GENERIC_DETAIL
        ) from None

    return EnrollNodeResponse(
        server_id=enrolled.server_id,
        label=enrolled.label,
        certificate=enrolled.certificate_pem,
        ca_certificate=enrolled.ca_certificate_pem,
    )


@admin_router.post("/enrollment-tokens", response_model=MintEnrollmentTokenResponse)
async def mint_enrollment_token(
    payload: MintEnrollmentTokenRequest,
    request: Request,
    response: Response,
    service: Annotated[EnrollmentService, Depends(get_service)],
) -> MintEnrollmentTokenResponse:
    """A one-time token to add a server, for the panel's "Add server"."""

    principal = await authorize_admin_mutation(
        request,
        allowed_roles=frozenset({AdminRole.OWNER, AdminRole.OPERATOR}),
        require_step_up=True,
    )
    minted = await service.mint(label=payload.label, admin_id=principal.admin_id)
    apply_auth_response_headers(response)
    settings = cast(Settings, request.app.state.settings)
    return MintEnrollmentTokenResponse(
        token=minted.token,
        label=minted.label,
        expires_at=minted.expires_at,
        api_url=settings.api_public_url.rstrip("/"),
    )
