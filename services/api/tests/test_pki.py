"""The deployment's certificate authority.

A CA that signs whatever it is handed is worse than no CA, because it looks
like authentication. Most of what follows is about what this one refuses, and
about the two places where a certificate can be subtly wrong in a way that
reads as correct in every text dump of it.
"""

import ipaddress
import os
from pathlib import Path
from typing import Literal

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nebula_api.pki import (
    CA_VALID_DAYS,
    LEAF_VALID_DAYS,
    CertificateAuthority,
    PkiError,
    create_certificate_authority,
    create_certificate_request,
    issuing_authority_pem,
    load_certificate_authority,
    sign_node_certificate,
    write_certificate,
    write_private_key,
)


def _authority(tmp_path: Path, name: str = "Frankfurt") -> CertificateAuthority:
    certificate_pem, key_pem = create_certificate_authority(deployment_name=name)
    write_certificate(tmp_path / "ca", certificate_pem)
    write_private_key(tmp_path / "ca.key", key_pem)
    return load_certificate_authority(tmp_path / "ca", tmp_path / "ca.key")


class TestTheAuthority:
    def test_is_a_certificate_authority(self, tmp_path: Path) -> None:
        authority = _authority(tmp_path)

        constraints = authority.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        assert constraints.ca
        # Depth zero: it signs leaves and cannot mint another CA beneath
        # itself, which is the only shape this deployment needs.
        assert constraints.path_length == 0

    def test_cannot_itself_be_used_as_a_tls_identity(self, tmp_path: Path) -> None:
        # Without this the CA key would also be usable as a server or client
        # certificate -- a second, unintended identity with the authority's
        # own key behind it.
        usage = (
            _authority(tmp_path).certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        )

        assert usage.key_cert_sign
        assert not usage.digital_signature
        assert not usage.key_agreement

    def test_is_named_after_the_deployment(self, tmp_path: Path) -> None:
        # So somebody holding certificates from two installations can tell
        # which issued which.
        authority = _authority(tmp_path, name="Helsinki")

        assert "Helsinki" in authority.certificate.subject.rfc4514_string()

    def test_outlives_the_certificates_it_signs(self, tmp_path: Path) -> None:
        # A leaf outliving its issuer verifies as expired anyway, which reads
        # as the node being at fault rather than the authority.
        assert CA_VALID_DAYS > LEAF_VALID_DAYS

    def test_two_deployments_never_share_an_authority(self, tmp_path: Path) -> None:
        first = _authority(tmp_path / "a")
        second = _authority(tmp_path / "b")

        assert first.certificate.fingerprint(hashes.SHA256()) != second.certificate.fingerprint(
            hashes.SHA256()
        )


class TestLoadingRefusesRatherThanHalfLoads:
    def test_a_missing_authority_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(PkiError):
            load_certificate_authority(tmp_path / "absent", tmp_path / "absent.key")

    def test_an_unreadable_certificate_is_an_error(self, tmp_path: Path) -> None:
        (tmp_path / "ca").write_bytes(b"not a certificate")
        (tmp_path / "ca.key").write_bytes(b"not a key")

        with pytest.raises(PkiError):
            load_certificate_authority(tmp_path / "ca", tmp_path / "ca.key")

    def test_a_key_of_the_wrong_type_is_an_error(self, tmp_path: Path) -> None:
        # An Ed25519 key cannot sign the certificates this issues, and
        # discovering that at signing time would fail the first enrolment
        # rather than the start-up that loaded it.
        certificate_pem, _ = create_certificate_authority(deployment_name="Frankfurt")
        (tmp_path / "ca").write_bytes(certificate_pem)
        (tmp_path / "ca.key").write_bytes(
            ed25519.Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with pytest.raises(PkiError):
            load_certificate_authority(tmp_path / "ca", tmp_path / "ca.key")


class TestSigning:
    def test_a_valid_request_is_signed_by_the_authority(self, tmp_path: Path) -> None:
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        certificate = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )
        )

        assert certificate.issuer == authority.certificate.subject

    def test_the_subject_comes_from_the_caller_not_the_request(self, tmp_path: Path) -> None:
        # The central rule. A requester that could name itself would obtain a
        # certificate for another node and impersonate it to the control plane.
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-01-i-am-not")

        certificate = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )
        )

        assert certificate.subject.rfc4514_string() == "CN=node-02"

    def test_an_address_becomes_an_ip_san_not_a_dns_name(self, tmp_path: Path) -> None:
        # A client dialling a literal address checks the IP SANs. A
        # certificate carrying the address as a DNS name fails verification
        # while looking, in every text dump, exactly correct.
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        certificate = x509.load_pem_x509_certificate(
            sign_node_certificate(authority, csr, common_name="node-02", hostnames=["5.6.7.8"])
        )

        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert names.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("5.6.7.8")]
        assert names.get_values_for_type(x509.DNSName) == []

    def test_a_node_certificate_is_for_one_end_only(self, tmp_path: Path) -> None:
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        server = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )
        )
        client = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="control", hostnames=["control"], usage="client"
            )
        )

        assert list(server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
            ExtendedKeyUsageOID.SERVER_AUTH
        ]
        assert list(client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
            ExtendedKeyUsageOID.CLIENT_AUTH
        ]

    def test_a_signed_node_certificate_cannot_sign_others(self, tmp_path: Path) -> None:
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        certificate = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )
        )

        assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


class TestSigningRefusals:
    def test_a_malformed_request_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(PkiError):
            sign_node_certificate(
                _authority(tmp_path),
                b"not a certificate request",
                common_name="node-02",
                hostnames=["vps2.example.com"],
            )

    def test_a_request_with_no_hostname_is_refused(self, tmp_path: Path) -> None:
        # A certificate with no subject alternative name verifies against
        # nothing, so it would fail at first connection rather than here.
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        with pytest.raises(PkiError):
            sign_node_certificate(authority, csr, common_name="node-02", hostnames=[])

    def test_blank_hostnames_do_not_count_as_hostnames(self, tmp_path: Path) -> None:
        authority = _authority(tmp_path)
        csr, _ = create_certificate_request(common_name="node-02")

        with pytest.raises(PkiError):
            sign_node_certificate(authority, csr, common_name="node-02", hostnames=["", "  "])

    def test_a_request_carrying_the_wrong_key_type_is_refused(self, tmp_path: Path) -> None:
        # RSA works in TLS, but accepting it here would mean node
        # certificates silently varying in type depending on what the node
        # happened to generate.
        authority = _authority(tmp_path)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node-02")]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
        )

        with pytest.raises(PkiError):
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )


class TestWriting:
    @pytest.mark.skipif(
        os.name != "posix",
        reason="Windows does not implement POSIX permission bits; the mode is "
        "still requested and applies wherever this actually runs",
    )
    def test_a_key_is_not_readable_by_anyone_else(self, tmp_path: Path) -> None:
        _, key_pem = create_certificate_authority(deployment_name="Frankfurt")
        path = tmp_path / "ca.key"

        write_private_key(path, key_pem)

        assert path.stat().st_mode & 0o077 == 0

    def test_writing_never_overwrites_existing_material(self, tmp_path: Path) -> None:
        # Silently replacing a CA would invalidate every certificate it ever
        # issued, with nothing reporting that anything had changed.
        path = tmp_path / "ca"
        write_certificate(path, b"first")

        with pytest.raises(FileExistsError):
            write_certificate(path, b"second")

        assert path.read_bytes() == b"first"

    def test_the_directory_is_created_when_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "ca"

        write_certificate(path, b"pem")

        assert path.read_bytes() == b"pem"


def test_a_request_proves_the_requester_holds_the_key(tmp_path: Path) -> None:
    # The signature on a CSR is the only thing tying the public key in it to
    # whoever sent it. A tampered request must not be signed.
    authority = _authority(tmp_path)
    csr, _ = create_certificate_request(common_name="node-02")
    tampered = bytearray(csr)
    # Corrupt the body without breaking the PEM framing.
    middle = len(tampered) // 2
    tampered[middle] = ord("A") if tampered[middle] != ord("A") else ord("B")

    with pytest.raises(PkiError):
        sign_node_certificate(
            authority, bytes(tampered), common_name="node-02", hostnames=["vps2.example.com"]
        )


def test_a_generated_request_carries_an_ec_key() -> None:
    csr_pem, key_pem = create_certificate_request(common_name="node-02")

    request = x509.load_pem_x509_csr(csr_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(request.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert request.is_signature_valid


def _handshake(
    tmp_path: Path,
    authority: CertificateAuthority,
    client_usage: Literal["server", "client"],
    *,
    caller_authority: CertificateAuthority | None = None,
    agent_trusts: list[CertificateAuthority] | None = None,
) -> bool:
    """A TLS handshake the way the agent runs it (serve.py: CERT_REQUIRED
    against the node CA), with the caller presenting a certificate of
    [client_usage]. True when the agent accepts it."""

    import socket
    import ssl
    import threading

    def issue(
        name: str, usage: Literal["server", "client"], signer: CertificateAuthority
    ) -> tuple[Path, Path]:
        csr, key = create_certificate_request(common_name=name)
        cert = sign_node_certificate(
            signer, csr, common_name=name, hostnames=["127.0.0.1"], usage=usage
        )
        write_certificate(tmp_path / f"{name}.crt", cert)
        write_private_key(tmp_path / f"{name}.key", key)
        return tmp_path / f"{name}.crt", tmp_path / f"{name}.key"

    write_certificate(tmp_path / "ca.crt", authority.certificate_pem())
    # The agent's client-CA file, one PEM or several (the switch-over bundle).
    trusted = b"".join(a.certificate_pem() for a in (agent_trusts or [authority]))
    write_certificate(tmp_path / "trusted.crt", trusted)
    agent_cert, agent_key = issue("agent", "server", authority)
    caller_cert, caller_key = issue("caller", client_usage, caller_authority or authority)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(agent_cert, agent_key)
    server_context.load_verify_locations(tmp_path / "trusted.crt")
    server_context.verify_mode = ssl.CERT_REQUIRED
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(tmp_path / "ca.crt")
    client_context.load_cert_chain(caller_cert, caller_key)

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    accepted: list[bool] = []

    def serve() -> None:
        connection, _ = listener.accept()
        try:
            with server_context.wrap_socket(connection, server_side=True) as tls:
                tls.recv(1)
                tls.sendall(b"y")
                accepted.append(True)
        except (ssl.SSLError, OSError):
            accepted.append(False)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with (
            socket.create_connection(("127.0.0.1", port)) as raw,
            client_context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
        ):
            tls.sendall(b"x")
            tls.recv(1)
    except (ssl.SSLError, OSError):
        pass
    thread.join(timeout=10)
    listener.close()
    return accepted == [True]


def test_the_agent_refuses_a_server_certificate_as_its_caller(tmp_path: Path) -> None:
    # A taken-over server's own certificate must not let it act as the
    # control plane toward the others.
    authority = _authority(tmp_path)
    assert not _handshake(tmp_path, authority, "server")


def test_the_agent_accepts_the_control_planes_client_certificate(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    assert _handshake(tmp_path, authority, "client")


def _control_plane_authority(tmp_path: Path) -> CertificateAuthority:
    directory = tmp_path / "control-plane"
    directory.mkdir()
    certificate_pem, key_pem = create_certificate_authority(
        deployment_name="Frankfurt", role="control-plane CA"
    )
    write_certificate(directory / "ca", certificate_pem)
    write_private_key(directory / "ca.key", key_pem)
    return load_certificate_authority(directory / "ca", directory / "ca.key")


def test_an_agent_trusting_the_control_plane_ca_refuses_every_node_certificate(
    tmp_path: Path,
) -> None:
    # Even one from before the usage split, good as a client: no revocation
    # list is needed for old copies to stop working.
    nodes, control_plane = _authority(tmp_path), _control_plane_authority(tmp_path)
    assert not _handshake(tmp_path, nodes, "client", agent_trusts=[control_plane])


def test_an_agent_trusting_the_control_plane_ca_accepts_the_control_plane(
    tmp_path: Path,
) -> None:
    nodes, control_plane = _authority(tmp_path), _control_plane_authority(tmp_path)
    assert _handshake(
        tmp_path, nodes, "client", caller_authority=control_plane, agent_trusts=[control_plane]
    )


def test_during_the_switch_an_agent_accepts_the_old_and_new_control_plane(
    tmp_path: Path,
) -> None:
    nodes, control_plane = _authority(tmp_path), _control_plane_authority(tmp_path)
    both = [nodes, control_plane]
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    assert _handshake(tmp_path / "old", nodes, "client", agent_trusts=both)
    assert _handshake(
        tmp_path / "new", nodes, "client", caller_authority=control_plane, agent_trusts=both
    )


def test_the_control_plane_ca_is_named_for_its_role(tmp_path: Path) -> None:
    common_name = (
        _control_plane_authority(tmp_path)
        .certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        .value
    )
    assert common_name == "Frankfurt control-plane CA"


def test_the_issuing_authority_is_found_among_several(tmp_path: Path) -> None:
    nodes, control_plane = _authority(tmp_path), _control_plane_authority(tmp_path)
    csr, _ = create_certificate_request(common_name="nebula-control-plane")
    write_certificate(
        tmp_path / "client.crt",
        sign_node_certificate(
            control_plane, csr, common_name="cp", hostnames=["cp"], usage="client"
        ),
    )
    authorities = [tmp_path / "missing", tmp_path / "ca", tmp_path / "control-plane" / "ca"]
    assert issuing_authority_pem(tmp_path / "client.crt", authorities) == (
        control_plane.certificate_pem()
    )
    assert issuing_authority_pem(tmp_path / "client.crt", [tmp_path / "ca"]) is None
    assert nodes.certificate_pem() != control_plane.certificate_pem()


def test_no_issuing_authority_for_a_missing_certificate(tmp_path: Path) -> None:
    _authority(tmp_path)
    assert issuing_authority_pem(tmp_path / "absent.crt", [tmp_path / "ca"]) is None
