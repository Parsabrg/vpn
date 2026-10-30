"""Pairing: how a generic client learns which deployment it belongs to.

One app build serves every installation, so nothing about a deployment can
be compiled into it. Instead the operator hands a person a pairing link --
as a QR code in the admin panel, or as text -- and the app keeps what it
learns from it:

    https://vpn.example.org/pair#v=1&d=<deployment id>&ca=<sha256 of CA>

The link is the trust anchor. It names the deployment's identity and, for
an installation whose certificate no client trusts on its own (one reached
by IP address, with the installer's internal CA), the SHA-256 of the CA
certificate. The app then fetches the record below from the link's origin,
accepts the CA only if its hash matches the link, re-fetches over a
connection verified against that CA, and accepts the record only if its
deployment id matches the link. A link that is tampered with in transit
changes one of those and pairs with nothing; a server that is not the one
the link names cannot produce a matching record.

What the record deliberately leaves out: the VPN servers, their addresses
and ports, and the other addresses the API answers on. Those are a censor's
shopping list (see api_routes.py) and are served only to a signed-in
account, by /v1/servers and /v1/routes, as before. The record carries only
what the holder of the link already has, plus the name and trust needed to
check it.
"""

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote, urlencode
from uuid import UUID

import segno
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from nebula_api.auth.admin_authorization import require_admin_session
from nebula_api.auth.http import apply_auth_response_headers
from nebula_api.auth.schemas import AuthModel
from nebula_api.db.engine import SessionFactory
from nebula_api.models.deployment import Deployment
from nebula_api.models.topology import ProtocolProfile, ServerProtocolCapability, VPNServer
from nebula_api.models.types import CapabilityState, ServerState
from nebula_api.settings import Settings

PAIRING_VERSION = 1

router = APIRouter(tags=["pairing"])


class PairingError(RuntimeError):
    pass


@dataclass(frozen=True)
class TrustAnchor:
    certificate_pem: str
    sha256: str


def load_trust_anchor(path: Path | None) -> TrustAnchor | None:
    """The configured CA, checked to be one certificate, and its hash.

    The hash is over the DER encoding, which is what a client computes from
    the PEM it is given; hashing the PEM text would make the result depend on
    line endings.
    """

    if path is None:
        return None
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        # Configured but not placed: the installer writes this file only for
        # an install whose certificate needs pinning, and removes it otherwise.
        return None
    except OSError as error:
        raise PairingError(f"the pairing CA at {path} cannot be read: {error}") from None
    try:
        certificate = x509.load_pem_x509_certificate(content)
    except ValueError as error:
        raise PairingError(f"the pairing CA at {path} cannot be read: {error}") from None
    der = certificate.public_bytes(serialization.Encoding.DER)
    return TrustAnchor(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        sha256=hashlib.sha256(der).hexdigest(),
    )


@dataclass(frozen=True)
class PairingRecord:
    deployment_id: UUID
    deployment_name: str
    api_url: str
    trust: TrustAnchor | None
    profiles: tuple[str, ...]

    def link(self) -> str:
        fragment = {"v": str(PAIRING_VERSION), "d": str(self.deployment_id)}
        if self.trust is not None:
            fragment["ca"] = self.trust.sha256
        # A fragment, not a query: browsers never send it, so opening the link
        # by mistake does not put the pairing values in a server log.
        return f"{self.api_url}/pair#{urlencode(fragment)}"

    def app_link(self) -> str:
        """The same values under the app's own scheme, for opening it directly."""

        query = {"u": self.api_url, "d": str(self.deployment_id)}
        if self.trust is not None:
            query["ca"] = self.trust.sha256
        return f"nebula://pair?{urlencode(query, quote_via=quote)}"


class PairingService:
    def __init__(self, session_factory: SessionFactory, settings: Settings) -> None:
        self._session_factory = session_factory
        self._settings = settings

    async def record(self) -> PairingRecord:
        async with self._session_factory() as session:
            deployment = await session.scalar(select(Deployment))
            # Offered means enabled on at least one active server: a profile
            # that exists but that nothing serves is not something to promise.
            profiles = (
                await session.scalars(
                    select(ProtocolProfile.code)
                    .join(
                        ServerProtocolCapability,
                        ServerProtocolCapability.protocol_profile_id == ProtocolProfile.id,
                    )
                    .join(VPNServer, VPNServer.id == ServerProtocolCapability.vpn_server_id)
                    .where(
                        ServerProtocolCapability.state == CapabilityState.ENABLED,
                        VPNServer.state == ServerState.ACTIVE,
                    )
                    .distinct()
                    .order_by(ProtocolProfile.code)
                )
            ).all()
        if deployment is None:
            raise PairingError("this installation has not been initialized")
        return PairingRecord(
            deployment_id=deployment.id,
            deployment_name=deployment.name,
            api_url=self._settings.api_public_url.rstrip("/"),
            # Read each time rather than at start-up: the installer places it
            # after the proxy has made its CA, while the API is already up.
            trust=load_trust_anchor(self._settings.pairing_ca_file),
            profiles=tuple(profiles),
        )


class PairingRecordResponse(AuthModel):
    version: int
    deployment_id: UUID
    deployment_name: str
    api_url: str
    # PEM, present only when clients must pin a CA of this installation's own.
    ca_certificate: str | None
    ca_sha256: str | None
    # Profile codes this deployment offers. Where they are served, and on
    # which ports, is told to signed-in clients only.
    profiles: list[str]


class AdminPairingResponse(AuthModel):
    link: str
    app_link: str
    qr_svg: str
    deployment_id: UUID
    ca_sha256: str | None


def _service(request: Request) -> PairingService:
    service = getattr(request.app.state, "pairing_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pairing is temporarily unavailable",
        )
    return cast(PairingService, service)


async def _record(request: Request) -> PairingRecord:
    try:
        return await _service(request).record()
    except PairingError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pairing is temporarily unavailable",
        ) from None


@router.get("/v1/pairing", response_model=PairingRecordResponse)
async def pairing_record(request: Request, response: Response) -> PairingRecordResponse:
    record = await _record(request)
    apply_auth_response_headers(response)
    return PairingRecordResponse(
        version=PAIRING_VERSION,
        deployment_id=record.deployment_id,
        deployment_name=record.deployment_name,
        api_url=record.api_url,
        ca_certificate=record.trust.certificate_pem if record.trust else None,
        ca_sha256=record.trust.sha256 if record.trust else None,
        profiles=list(record.profiles),
    )


@router.get("/v1/admin/pairing", response_model=AdminPairingResponse)
async def admin_pairing(request: Request, response: Response) -> AdminPairingResponse:
    await require_admin_session(request)
    record = await _record(request)
    link = record.link()
    # A whole SVG document, namespace included: the panel shows it as an
    # image, and an SVG without its namespace does not render as one. Black
    # on white whatever the panel's theme, which is what cameras read.
    image = io.BytesIO()
    segno.make(link, error="m").save(
        image, kind="svg", scale=6, border=4, dark="black", light="white", xmldecl=False
    )
    qr_svg = image.getvalue().decode("utf-8")
    apply_auth_response_headers(response)
    return AdminPairingResponse(
        link=link,
        app_link=record.app_link(),
        qr_svg=qr_svg,
        deployment_id=record.deployment_id,
        ca_sha256=record.trust.sha256 if record.trust else None,
    )
