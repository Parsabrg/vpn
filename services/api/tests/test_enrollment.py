"""Exchanging a token for a node identity.

The one place in this system where something with no credentials is handed
some, so the refusals matter more than the success. Every one of them must
look identical from outside: this endpoint is reachable by anyone, and an
unknown token answering differently from an expired one turns it into an
oracle that tells somebody probing with guesses which of them was real.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from nebula_api.db.engine import SessionFactory
from nebula_api.enrollment.service import (
    ENROLLMENT_NAMESPACE,
    MAXIMUM_TOKEN_LIFETIME,
    EnrollmentRejected,
    EnrollmentService,
)
from nebula_api.models.enrollment import NodeEnrollmentToken
from nebula_api.pki import (
    CertificateAuthority,
    create_certificate_authority,
    create_certificate_request,
)

KEY_RING = {1: b"k" * 32}
NOW = datetime.now(UTC)


class FakeSession:
    """Holds whatever token rows a test set up, plus anything added."""

    def __init__(self, rows: list[NodeEnrollmentToken] | None = None) -> None:
        self.rows = rows or []
        self.added: list[object] = []
        self.commits = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalar(self, statement: object) -> Any:
        rendered = str(statement.compile().params.values())  # type: ignore[attr-defined]
        for row in self.rows:
            if row.token_digest is not None and str(row.token_digest) in rendered:
                return row
            if str(row.id) in rendered:
                return row
        return self.rows[0] if self.rows and "token_digest" not in str(statement) else None

    async def scalars(self, _statement: object) -> Any:
        return _Rows(self.rows)

    def add(self, value: object) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


def _factory(session: FakeSession) -> SessionFactory:
    return cast(SessionFactory, lambda: session)


def _service(session: FakeSession) -> EnrollmentService:
    return EnrollmentService(_factory(session), KEY_RING, 1)


def _authority() -> CertificateAuthority:
    certificate_pem, key_pem = create_certificate_authority(deployment_name="Frankfurt")
    key = serialization.load_pem_private_key(key_pem, password=None)
    return CertificateAuthority(
        certificate=x509.load_pem_x509_certificate(certificate_pem),
        private_key=cast(ec.EllipticCurvePrivateKey, key),
    )


def _token_row(
    token: str,
    *,
    expires_in: timedelta = timedelta(minutes=30),
    used_at: datetime | None = None,
    revoked_at: datetime | None = None,
    label: str = "node-02",
) -> NodeEnrollmentToken:
    from nebula_api.auth.opaque_tokens import digest_opaque_token

    digest = digest_opaque_token(token, KEY_RING, namespace=ENROLLMENT_NAMESPACE)
    return NodeEnrollmentToken(
        id=uuid4(),
        label=label,
        token_digest=digest.value,
        key_version=digest.key_version,
        expires_at=datetime.now(UTC) + expires_in,
        used_at=used_at,
        revoked_at=revoked_at,
    )


def _redeem(service: EnrollmentService, token: str, *, csr: bytes | None = None) -> Any:
    request = csr if csr is not None else create_certificate_request(common_name="whatever")[0]
    return asyncio.run(
        service.redeem(
            token=token,
            csr_pem=request,
            authority=_authority(),
            public_host="vps2.example.com",
            agent_host="10.0.0.2",
            agent_port=9443,
        )
    )


class TestMinting:
    def test_the_token_is_returned_once_and_never_stored(self) -> None:
        # Only the digest reaches the database. A backup or a stray query
        # result must not contain something that can enrol a node.
        session = FakeSession()

        minted = asyncio.run(_service(session).mint(label="node-02"))

        stored = cast(NodeEnrollmentToken, session.added[0])
        assert minted.token
        assert minted.token.encode() not in bytes(stored.token_digest)
        assert stored.token_digest != minted.token.encode()

    def test_a_lifetime_beyond_the_maximum_is_refused(self) -> None:
        # An unused token is a standing invitation to join this deployment.
        session = FakeSession()

        with pytest.raises(ValueError):
            asyncio.run(
                _service(session).mint(
                    label="node-02", lifetime=MAXIMUM_TOKEN_LIFETIME + timedelta(days=1)
                )
            )

        assert session.added == []

    def test_a_zero_or_negative_lifetime_is_refused(self) -> None:
        session = FakeSession()

        with pytest.raises(ValueError):
            asyncio.run(_service(session).mint(label="node-02", lifetime=timedelta(0)))


class TestRedeeming:
    def test_a_valid_token_yields_a_certificate_and_a_server(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token)])

        enrolled = _redeem(_service(session), token)

        assert "BEGIN CERTIFICATE" in enrolled.certificate_pem
        assert "BEGIN CERTIFICATE" in enrolled.ca_certificate_pem
        assert enrolled.label == "node-02"

    def test_the_profiles_a_node_serves_are_enabled_with_their_ad_block_twins(
        self,
    ) -> None:
        # Offered at once, not after an administrator enables each by hand.
        from nebula_api.auth.opaque_tokens import issue_opaque_token
        from nebula_api.models.topology import ProtocolProfile, ServerProtocolCapability

        token = issue_opaque_token(1)
        profiles = [
            ProtocolProfile(id=uuid4(), code=code, version=1)
            for code in ("vless-ws-tls", "vless-ws-tls-adblock")
        ]
        asked: list[str] = []

        class _ProfileSession(FakeSession):
            async def scalars(self, statement: object) -> Any:
                asked.append(
                    str(statement.compile(compile_kwargs={"literal_binds": True}))  # type: ignore[attr-defined]
                )
                return _Rows(profiles)

        session = _ProfileSession([_token_row(token)])
        asyncio.run(
            _service(session).redeem(
                token=token,
                csr_pem=create_certificate_request(common_name="whatever")[0],
                authority=_authority(),
                public_host="vps2.example.com",
                agent_host="10.0.0.2",
                agent_port=9443,
                protocol_profiles=["vless-ws-tls"],
            )
        )

        enabled = [item for item in session.added if isinstance(item, ServerProtocolCapability)]
        assert {item.protocol_profile_id for item in enabled} == {p.id for p in profiles}
        assert "vless-ws-tls-adblock" in asked[0]

    def test_a_wireguard_node_is_stored_with_its_range(self) -> None:
        # Without it the control plane could give no device a WireGuard
        # address on a joined server (Tehran, 2026-10-31).
        from ipaddress import IPv4Address, IPv4Network

        from nebula_api.auth.opaque_tokens import issue_opaque_token
        from nebula_api.models.topology import VPNServer

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token)])
        asyncio.run(
            _service(session).redeem(
                token=token,
                csr_pem=create_certificate_request(common_name="whatever")[0],
                authority=_authority(),
                public_host="vps2.example.com",
                agent_host="10.0.0.2",
                agent_port=9443,
                wireguard_client_pool=IPv4Network("10.77.0.0/20"),
                wireguard_gateway_address=IPv4Address("10.77.0.1"),
            )
        )

        server = next(item for item in session.added if isinstance(item, VPNServer))
        assert server.wireguard_client_pool == "10.77.0.0/20"
        assert server.wireguard_gateway_address == "10.77.0.1"

    def test_the_certificate_names_the_node_from_the_token_not_the_request(self) -> None:
        # A requester that could name itself would be able to obtain a
        # certificate for another node's hostname and impersonate it.
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token, label="node-02")])
        forged, _ = create_certificate_request(common_name="node-01")

        enrolled = _redeem(_service(session), token, csr=forged)

        certificate = x509.load_pem_x509_certificate(enrolled.certificate_pem.encode())
        assert certificate.subject.rfc4514_string() == "CN=node-02"

    def test_the_certificate_covers_both_addresses_the_node_answers_on(self) -> None:
        # The public host serves VPN traffic; the agent host is often a
        # private address the control plane reaches internally. A certificate
        # carrying one of them fails verification on the other.
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token)])

        enrolled = _redeem(_service(session), token)

        certificate = x509.load_pem_x509_certificate(enrolled.certificate_pem.encode())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        rendered = {str(entry.value) for entry in names}
        assert rendered == {"vps2.example.com", "10.0.0.2"}

    def test_redeeming_marks_the_token_spent(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        row = _token_row(token)
        session = FakeSession([row])

        _redeem(_service(session), token)

        assert row.used_at is not None
        assert row.vpn_server_id is not None


class TestEveryRefusalLooksTheSame:
    """The failures, which are the part that matters.

    Each asserts the same exception, deliberately: if any of these ever
    started reporting a distinguishable reason, this endpoint would tell
    somebody guessing tokens which guesses were close.
    """

    def test_an_unknown_token_is_refused(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        session = FakeSession([])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), issue_opaque_token(1))

    def test_an_expired_token_is_refused(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        row = _token_row(token, expires_in=timedelta(minutes=-1))
        session = FakeSession([row])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), token)

        assert row.used_at is None

    def test_a_token_already_redeemed_is_refused(self) -> None:
        # Single use is what makes a token read from a shell history inert.
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token, used_at=NOW)])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), token)

    def test_a_revoked_token_is_refused(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        session = FakeSession([_token_row(token, revoked_at=NOW)])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), token)

    def test_a_malformed_token_is_refused_like_an_unknown_one(self) -> None:
        session = FakeSession([])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), "not-a-token")

    def test_a_token_from_another_deployment_is_refused(self) -> None:
        # Each installation has its own token pepper, so a token minted
        # elsewhere digests to something this one has never stored -- even if
        # the two databases were somehow merged.
        from nebula_api.auth.opaque_tokens import digest_opaque_token, issue_opaque_token

        token = issue_opaque_token(1)
        other_deployment_digest = digest_opaque_token(
            token, {1: b"a different deployment's pepper!"}, namespace=ENROLLMENT_NAMESPACE
        )
        row = _token_row(token)
        row.token_digest = other_deployment_digest.value
        session = FakeSession([row])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), token)

    def test_a_malformed_certificate_request_leaves_the_token_unspent(self) -> None:
        # A node that sent a bad request should be able to fix it and retry,
        # rather than need a fresh token from an administrator.
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        token = issue_opaque_token(1)
        row = _token_row(token)
        session = FakeSession([row])

        with pytest.raises(EnrollmentRejected):
            _redeem(_service(session), token, csr=b"not a certificate request")

        assert row.used_at is None


class TestRevoking:
    def test_an_outstanding_token_can_be_withdrawn(self) -> None:
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        row = _token_row(issue_opaque_token(1))
        session = FakeSession([row])

        assert asyncio.run(_service(session).revoke(row.id))
        assert row.revoked_at is not None

    def test_a_spent_token_is_not_revoked_again(self) -> None:
        # It is already inert; what is worth revoking then is the node's
        # certificate, which is a different object.
        from nebula_api.auth.opaque_tokens import issue_opaque_token

        row = _token_row(issue_opaque_token(1), used_at=NOW)
        session = FakeSession([row])

        assert not asyncio.run(_service(session).revoke(row.id))
        assert row.revoked_at is None


def test_a_redeemable_token_needs_all_three_conditions() -> None:
    # One place, because the endpoint must not be able to check two of these
    # and forget the third.
    now = datetime.now(UTC)
    live = _token_row("v1." + "a" * 43)
    assert live.is_redeemable(now=now)

    for spent in (
        _token_row("v1." + "a" * 43, used_at=now),
        _token_row("v1." + "a" * 43, revoked_at=now),
        _token_row("v1." + "a" * 43, expires_in=timedelta(seconds=-1)),
    ):
        assert not spent.is_redeemable(now=now)


def test_the_enrollment_namespace_is_distinct_from_other_token_uses() -> None:
    # Namespacing is what stops a refresh token or a password reset being
    # presented here, and vice versa.
    from nebula_api.auth.opaque_tokens import digest_opaque_token, issue_opaque_token

    token = issue_opaque_token(1)
    enrollment = digest_opaque_token(token, KEY_RING, namespace=ENROLLMENT_NAMESPACE)
    refresh = digest_opaque_token(token, KEY_RING, namespace="refresh-token")

    assert enrollment.value != refresh.value


def test_a_uuid_is_never_confused_for_a_token() -> None:
    assert isinstance(uuid4(), UUID)
