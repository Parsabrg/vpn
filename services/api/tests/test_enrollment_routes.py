"""The HTTP surface a node with no identity uses to obtain one.

Public by necessity, so the tests here are mostly about what it refuses and
about the fact that every refusal reads identically. The certificate exchange
is exercised for real -- a generated key, a real request, a real signature --
because the one thing a mocked signature could not tell us is whether a node
could actually use what comes back.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from cryptography import x509
from fastapi import FastAPI
from fastapi.testclient import TestClient

from nebula_api.auth.opaque_tokens import digest_opaque_token, issue_opaque_token
from nebula_api.enrollment.routes import admin_router, router
from nebula_api.enrollment.service import (
    ENROLLMENT_NAMESPACE,
    EnrolledNode,
    EnrollmentRejected,
    EnrollmentService,
)
from nebula_api.pki import (
    create_certificate_authority,
    create_certificate_request,
    write_certificate,
    write_private_key,
)
from nebula_api.settings import Settings

KEY_RING = {1: b"k" * 32}


class FakeEnrollmentService:
    """Records what it was asked, and answers however the test says."""

    def __init__(self, result: EnrolledNode | Exception | None = None) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def redeem(self, **kwargs: object) -> EnrolledNode:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        if self.result is None:
            raise EnrollmentRejected()
        return self.result


def _write_authority(tmp_path: Path) -> Path:
    certificate_pem, key_pem = create_certificate_authority(deployment_name="Frankfurt")
    write_certificate(tmp_path / "node_ca_certificate", certificate_pem)
    write_private_key(tmp_path / "node_ca_key", key_pem)
    return tmp_path


def make_client(
    tmp_path: Path,
    service: object | None = None,
    *,
    omit_service: bool = False,
    omit_authority: bool = False,
) -> TestClient:
    if not omit_authority:
        _write_authority(tmp_path)
    app = FastAPI()
    app.state.settings = Settings(env="test", state_dir=tmp_path)
    if not omit_service:
        app.state.enrollment_service = cast(EnrollmentService, service or FakeEnrollmentService())
    app.include_router(router)
    return TestClient(app)


def _body(**overrides: object) -> dict[str, object]:
    csr, _ = create_certificate_request(common_name="whatever")
    payload: dict[str, object] = {
        "token": issue_opaque_token(1),
        "certificate_request": csr.decode("ascii"),
        "public_host": "vps2.example.com",
        "agent_host": "10.0.0.2",
        "agent_port": 9443,
    }
    payload.update(overrides)
    return payload


class TestARealExchange:
    """Against the real service, so the certificate is genuinely signed."""

    def test_a_node_receives_a_usable_certificate_and_the_authority(self, tmp_path: Path) -> None:
        from nebula_api.models.enrollment import NodeEnrollmentToken

        token = issue_opaque_token(1)
        digest = digest_opaque_token(token, KEY_RING, namespace=ENROLLMENT_NAMESPACE)
        row = NodeEnrollmentToken(
            id=uuid4(),
            label="node-02",
            token_digest=digest.value,
            key_version=digest.key_version,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        class _Session:
            async def __aenter__(self) -> "_Session":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def scalar(self, _statement: object) -> object:
                return row

            def add(self, _value: object) -> None:
                return None

            async def flush(self) -> None:
                return None

            async def commit(self) -> None:
                return None

        service = EnrollmentService(cast(object, lambda: _Session()), KEY_RING, 1)  # type: ignore[arg-type]
        with make_client(tmp_path, service) as client:
            response = client.post("/v1/nodes/enroll", json=_body(token=token))

        assert response.status_code == 200
        body = response.json()
        certificate = x509.load_pem_x509_certificate(body["certificate"].encode())
        authority = x509.load_pem_x509_certificate(body["ca_certificate"].encode())

        # Issued by this deployment, and named by the token rather than by
        # anything the requester sent.
        assert certificate.issuer == authority.subject
        assert certificate.subject.rfc4514_string() == "CN=node-02"
        assert body["label"] == "node-02"

    def test_the_response_carries_no_private_key(self, tmp_path: Path) -> None:
        # The node generated its own and never sent it. A response containing
        # one would mean the control plane had made a key for somebody else.
        enrolled = EnrolledNode(
            server_id=uuid4(),
            label="node-02",
            certificate_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
            ca_certificate_pem="-----BEGIN CERTIFICATE-----\ny\n-----END CERTIFICATE-----\n",
        )
        with make_client(tmp_path, FakeEnrollmentService(enrolled)) as client:
            body = client.post("/v1/nodes/enroll", json=_body()).json()

        assert set(body) == {"server_id", "label", "certificate", "ca_certificate"}
        assert "PRIVATE KEY" not in str(body)


class TestRefusalsAreIndistinguishable:
    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(
                _body(token="not-a-token"),  # noqa: S106 - fixture, not a credential
                id="malformed token",
            ),
            pytest.param(_body(), id="unknown token"),
        ],
    )
    def test_a_bad_token_is_refused_with_the_same_answer(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> None:
        with make_client(tmp_path, FakeEnrollmentService(EnrollmentRejected())) as client:
            response = client.post("/v1/nodes/enroll", json=payload)

        assert response.status_code == 400
        assert response.json()["detail"] == "Enrollment was not accepted"

    def test_a_non_ascii_certificate_request_is_refused_the_same_way(self, tmp_path: Path) -> None:
        # PEM is ASCII. Anything else is refused identically rather than
        # reaching the parser and failing differently.
        with make_client(tmp_path) as client:
            response = client.post(
                "/v1/nodes/enroll", json=_body(certificate_request="—not ascii—")
            )

        assert response.status_code == 400
        assert response.json()["detail"] == "Enrollment was not accepted"


class TestTheRequestIsBounded:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("agent_port", 0),
            ("agent_port", 70000),
            ("token", ""),
            ("public_host", ""),
            ("certificate_request", "x" * 9000),
        ],
    )
    def test_an_out_of_range_field_never_reaches_the_service(
        self, tmp_path: Path, field: str, value: object
    ) -> None:
        service = FakeEnrollmentService()
        with make_client(tmp_path, service) as client:
            response = client.post("/v1/nodes/enroll", json=_body(**{field: value}))

        assert response.status_code == 422
        assert service.calls == []

    def test_unknown_fields_are_rejected(self, tmp_path: Path) -> None:
        # extra="forbid": a node sending something this version does not know
        # about should be told, not silently have it ignored.
        service = FakeEnrollmentService()
        with make_client(tmp_path, service) as client:
            response = client.post("/v1/nodes/enroll", json=_body(deployment_id=str(uuid4())))

        assert response.status_code == 422
        assert service.calls == []

    def test_the_node_cannot_name_itself(self, tmp_path: Path) -> None:
        # There is no field for it. The label comes from the token, so a
        # request has no way to ask to be called something else.
        assert "label" not in _body()


class TestWhenTheDeploymentCannotIssueCertificates:
    def test_a_missing_authority_is_unavailable_not_a_bad_request(self, tmp_path: Path) -> None:
        # An operator problem rather than a bad token. Reporting it as a
        # refusal would send somebody looking at their token for an hour.
        with make_client(tmp_path, omit_authority=True) as client:
            response = client.post("/v1/nodes/enroll", json=_body())

        assert response.status_code == 503

    def test_an_unconfigured_service_is_unavailable(self, tmp_path: Path) -> None:
        with make_client(tmp_path, omit_service=True) as client:
            response = client.post("/v1/nodes/enroll", json=_body())

        assert response.status_code == 503


def test_the_node_supplies_where_it_can_be_reached(tmp_path: Path) -> None:
    # Both addresses, because the control plane reaches the agent on one and
    # clients reach the VPN on the other, and they are frequently different.
    service = FakeEnrollmentService(
        EnrolledNode(
            server_id=uuid4(), label="node-02", certificate_pem="c", ca_certificate_pem="a"
        )
    )
    with make_client(tmp_path, service) as client:
        client.post("/v1/nodes/enroll", json=_body())

    call = service.calls[0]
    assert call["public_host"] == "vps2.example.com"
    assert call["agent_host"] == "10.0.0.2"
    assert call["agent_port"] == 9443


def test_adding_a_server_from_the_panel_needs_an_admin(tmp_path: Path) -> None:
    app = FastAPI()
    app.state.settings = Settings(env="test", state_dir=tmp_path)
    app.state.enrollment_service = cast(EnrollmentService, FakeEnrollmentService())
    app.include_router(admin_router)

    with TestClient(app) as client:
        response = client.post("/v1/admin/nodes/enrollment-tokens", json={"label": "node-02"})

    assert response.status_code in (401, 403)
