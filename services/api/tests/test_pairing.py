"""The pairing record and link a generic client pairs from."""

import asyncio
import hashlib
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.admin_service import AdminAuthService, AdminPrincipal
from nebula_api.auth.http import install_auth_http_safeguards
from nebula_api.bootstrap import ensure_node_authority
from nebula_api.models.types import AdminRole
from nebula_api.pairing import (
    PairingError,
    PairingRecord,
    PairingService,
    TrustAnchor,
    load_trust_anchor,
    router,
)
from nebula_api.settings import Settings

DEPLOYMENT = UUID("7d3c1f2e-0b5a-4c9d-8e61-2f4a9b0c1d2e")


def _authority(tmp_path: Path) -> Path:
    ensure_node_authority(tmp_path / "ca.pem", tmp_path / "ca.key", deployment_name="Test")
    return tmp_path / "ca.pem"


def _record(trust: TrustAnchor | None) -> PairingRecord:
    return PairingRecord(
        deployment_id=DEPLOYMENT,
        deployment_name="Home",
        api_url="https://203.0.113.7:8443",
        trust=trust,
        profiles=("wireguard-native",),
    )


def test_the_anchor_is_the_hash_of_the_certificate_der(tmp_path: Path) -> None:
    path = _authority(tmp_path)

    anchor = load_trust_anchor(path)

    assert anchor is not None
    der = x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(Encoding.DER)
    assert anchor.sha256 == hashlib.sha256(der).hexdigest()
    assert load_trust_anchor(None) is None
    assert load_trust_anchor(tmp_path / "absent.pem") is None


def test_an_unreadable_anchor_is_an_error_not_a_silent_public_ca(tmp_path: Path) -> None:
    (tmp_path / "ca.pem").write_text("not a certificate")

    with pytest.raises(PairingError, match="cannot be read"):
        load_trust_anchor(tmp_path / "ca.pem")


def test_the_link_carries_identity_and_pin_in_the_fragment(tmp_path: Path) -> None:
    anchor = load_trust_anchor(_authority(tmp_path))

    link = urlsplit(_record(anchor).link())

    assert f"{link.scheme}://{link.netloc}{link.path}" == "https://203.0.113.7:8443/pair"
    # In the fragment, so a browser opening it never sends the values anywhere.
    assert link.query == ""
    values = parse_qs(link.fragment)
    assert values == {"v": ["1"], "d": [str(DEPLOYMENT)], "ca": [anchor.sha256]}  # type: ignore[union-attr]


def test_a_publicly_trusted_install_has_no_pin() -> None:
    assert "ca=" not in _record(None).link()
    assert "ca=" not in _record(None).app_link()


def test_the_app_link_names_the_api_url(tmp_path: Path) -> None:
    anchor = load_trust_anchor(_authority(tmp_path))

    link = urlsplit(_record(anchor).app_link())

    assert (link.scheme, link.netloc) == ("nebula", "pair")
    assert parse_qs(link.query)["u"] == ["https://203.0.113.7:8443"]


class _Service:
    def __init__(self, record: PairingRecord | None) -> None:
        self._record = record

    async def record(self) -> PairingRecord:
        if self._record is None:
            raise PairingError("not initialized")
        return self._record


class _Admins:
    async def principal(self, _token: str) -> AdminPrincipal:
        return AdminPrincipal(DEPLOYMENT, DEPLOYMENT, AdminRole.OWNER, False, "totp")


def _client(record: PairingRecord | None) -> TestClient:
    settings = Settings(env="test")
    app = FastAPI()
    app.state.settings = settings
    app.state.pairing_service = cast(PairingService, _Service(record))
    app.state.admin_auth_service = cast(AdminAuthService, _Admins())
    install_auth_http_safeguards(app, settings)
    app.include_router(router)
    return TestClient(app)


def test_the_record_is_public_and_carries_the_ca(tmp_path: Path) -> None:
    anchor = load_trust_anchor(_authority(tmp_path))

    with _client(_record(anchor)) as client:
        body = client.get("/v1/pairing").json()

    assert body["deployment_id"] == str(DEPLOYMENT)
    assert body["ca_sha256"] == anchor.sha256  # type: ignore[union-attr]
    assert body["ca_certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["profiles"] == ["wireguard-native"]
    # Where VPN servers are, and the API's other addresses, cost a sign-in.
    assert not {"servers", "routes", "endpoints"} & set(body)


def test_an_uninitialized_install_says_so() -> None:
    with _client(None) as client:
        assert client.get("/v1/pairing").status_code == 503


def test_the_admin_pairing_view_needs_a_session_and_draws_a_qr_code() -> None:
    with _client(_record(None)) as client:
        assert client.get("/v1/admin/pairing").status_code == 401
        client.cookies.set(Settings(env="test").admin_cookie_name, "v1.session")
        body = client.get("/v1/admin/pairing").json()

    assert body["link"].startswith("https://203.0.113.7:8443/pair#")
    assert body["qr_svg"].startswith("<svg")
    # Rendered as an <img>, which needs the SVG namespace to draw at all.
    assert 'xmlns="http://www.w3.org/2000/svg"' in body["qr_svg"]


class _Rows:
    def __init__(self, rows: list[str]) -> None:
        self._rows = rows

    def all(self) -> list[str]:
        return self._rows


class _Session:
    def __init__(self, deployment: object | None, profiles: list[str]) -> None:
        self._deployment = deployment
        self._profiles = profiles

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def scalar(self, _statement: object) -> object | None:
        return self._deployment

    async def scalars(self, _statement: object) -> _Rows:
        return _Rows(self._profiles)


def test_the_service_reads_the_deployment_and_what_it_offers() -> None:
    from types import SimpleNamespace

    from nebula_api.db.engine import SessionFactory
    from nebula_api.pairing import PairingError, PairingService

    settings = Settings(env="test", api_public_url="https://api.example.org:8444/")
    deployment = SimpleNamespace(id=DEPLOYMENT, name="Example")
    offered = PairingService(
        cast(SessionFactory, lambda: _Session(deployment, ["vless-ws-tls"])), settings
    )

    record = asyncio.run(offered.record())

    assert record.deployment_id == DEPLOYMENT
    assert record.api_url == "https://api.example.org:8444"
    assert record.profiles == ("vless-ws-tls",)
    assert record.trust is None
    uninitialized = PairingService(cast(SessionFactory, lambda: _Session(None, [])), settings)
    with pytest.raises(PairingError):
        asyncio.run(uninitialized.record())
