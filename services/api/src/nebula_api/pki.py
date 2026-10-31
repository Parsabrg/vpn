"""The deployment's own certificate authority.

Until now every certificate in this system was made by hand and copied into
place: the agent's server certificate, the CA it trusts, the API's client
certificate. That works for one server somebody set up personally. It does
not survive "add a second VPS", which is the whole point of enrollment -- a
new node has to be able to obtain an identity the control plane will accept,
over the network, without an operator generating anything.

So the deployment becomes a CA -- two of them, one per direction:

    API (client cert) -------mTLS-------> agent (server cert)
      signed by the control-plane CA        signed by the node CA
      trusts the node CA                    trusts the control-plane CA

Two, because one was not enough: with a single CA every node holds a
certificate from the authority the agents trust for clients, so a server
taken over could call every other server's agent as the control plane. The
control-plane CA signs exactly one certificate, and an agent that trusts only
it refuses every node certificate, old copies included (there is no
revocation list to rely on).

The CA key never leaves the control plane. A node proves it holds a valid
enrollment token, sends a certificate request, and receives a signed
certificate back -- it never sees the key that signed it, and cannot issue
anything to anyone else.

Elliptic curve rather than RSA: P-256 keys and signatures are small, fast on
the small VPSs this runs on, and universally supported by the TLS stacks at
both ends. Nothing here needs RSA's compatibility with old clients, because
both ends of this connection ship together.
"""

import datetime as dt
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Ten years. This is a private CA for one deployment's internal links, and
# rotating it means re-enrolling every node -- an operation worth doing
# deliberately rather than because a certificate quietly expired on a
# Tuesday. Leaf certificates below are short by comparison, which is where
# the actual churn belongs.
CA_VALID_DAYS = 3650

# Node and client certificates. Long enough not to be a routine chore, short
# enough that a leaked key is not useful forever. Renewal re-enrolls.
LEAF_VALID_DAYS = 825

# Clocks on freshly provisioned VPSs are often wrong for the first few
# seconds, and a certificate that is not yet valid fails in exactly the same
# way as one that is invalid. Backdating slightly costs nothing.
_CLOCK_SKEW = dt.timedelta(minutes=5)

_CA_FILE_MODE = 0o640
_KEY_FILE_MODE = 0o600


class PkiError(RuntimeError):
    """Raised without reflecting key material or file contents."""


@dataclass(frozen=True, slots=True)
class CertificateAuthority:
    """The signing identity, loaded into memory only to sign."""

    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey

    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def create_certificate_authority(
    *, deployment_name: str, role: str = "node CA"
) -> tuple[bytes, bytes]:
    """A new self-signed CA, returned as (certificate PEM, private key PEM).

    Named after the deployment so an operator looking at a certificate on a
    node can tell which installation issued it -- useful precisely when
    somebody is holding certificates from two of them.
    """

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"{deployment_name} {role}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nebula"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            # A CA that can only sign certificates and CRLs. Without this it
            # could also be used as a TLS server or client identity itself,
            # which is not a capability anything here needs.
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def load_certificate_authority(certificate_path: Path, key_path: Path) -> CertificateAuthority:
    """Read the CA, failing clearly rather than half-loaded."""

    try:
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError) as error:
        raise PkiError("the deployment certificate authority could not be read") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PkiError("the deployment certificate authority key is not an EC key")
    return CertificateAuthority(certificate=certificate, private_key=key)


def issuing_authority_pem(certificate_path: Path, authorities: list[Path]) -> bytes | None:
    """The PEM of whichever of [authorities] signed the certificate at
    [certificate_path], or None if none did (or a file is missing).

    Enrolment hands a node the authority that issued the control plane's
    client certificate, so a node enrolled before or after the control plane
    moved to its own authority trusts what the control plane presents.
    """

    try:
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    except (OSError, ValueError):
        return None
    for path in authorities:
        try:
            authority = x509.load_pem_x509_certificate(path.read_bytes())
            certificate.verify_directly_issued_by(authority)
        except (OSError, ValueError, TypeError, InvalidSignature):
            continue
        return authority.public_bytes(serialization.Encoding.PEM)
    return None


def sign_node_certificate(
    authority: CertificateAuthority,
    csr_pem: bytes,
    *,
    common_name: str,
    hostnames: list[str],
    usage: Literal["server", "client"] = "server",
) -> bytes:
    """Sign a node's request, returning the certificate PEM.

    [usage] is the one end of the agent link the certificate may act as: an
    agent's is a server certificate, the control plane's a client one. A
    certificate good for both let any server, if taken over, call every
    other server's agent as the control plane.

    The subject is rebuilt here rather than taken from the request. A CSR's
    subject and its SAN list are whatever the requester wrote, and a node that
    could name itself would be able to obtain a certificate for another node's
    hostname and then impersonate it to the control plane. What the requester
    actually supplies is a public key; everything the certificate asserts
    comes from what the control plane already knows about this enrolment.

    The signature on the request is still checked, because it proves the
    requester holds the private key for the public key being certified.
    """

    try:
        request = x509.load_pem_x509_csr(csr_pem)
        # Inside the same guard as parsing: a request that parses but carries
        # a corrupted key raises from *here* rather than returning False, and
        # letting that escape would answer an enrolment attempt with a crash
        # instead of a refusal.
        signature_valid = request.is_signature_valid
    except ValueError as error:
        raise PkiError("the certificate request could not be read") from error
    if not signature_valid:
        raise PkiError("the certificate request is not correctly signed")

    public_key = request.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise PkiError("the certificate request must carry an EC public key")

    alternative_names = _subject_alternative_names(hostnames)
    if not alternative_names:
        raise PkiError("a node certificate needs at least one hostname or address")

    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(authority.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + dt.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if usage == "server"
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            critical=False,
        )
        .sign(authority.private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def create_certificate_request(*, common_name: str) -> tuple[bytes, bytes]:
    """A key and a request for it, returned as (CSR PEM, private key PEM).

    Lives here rather than in the agent so both ends agree on the key type
    without the agent depending on this package -- the agent calls the
    equivalent in its own tree, and this one is what the tests and the
    control plane's own client certificate use.
    """

    key = ec.generate_private_key(ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return (
        request.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def write_certificate(path: Path, pem: bytes) -> None:
    """Write a certificate, which is public and group-readable."""

    _write_exclusive(path, pem, _CA_FILE_MODE)


def write_private_key(path: Path, pem: bytes) -> None:
    """Write a key, readable only by the service that owns it."""

    _write_exclusive(path, pem, _KEY_FILE_MODE)


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive: two processes racing here must not both believe they wrote
    # the CA, because only one of them did and the other would go on signing
    # with a key nothing stored.
    # O_BINARY: the bytes as given, not newline-translated, on Windows too.
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode
    )
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def _subject_alternative_names(hostnames: list[str]) -> list[x509.GeneralName]:
    """Turn hostnames and addresses into SAN entries.

    An address has to be an IPAddress entry rather than a DNSName: a TLS
    client connecting to a literal address checks the IP SANs, and a
    certificate carrying the address only as a DNS name fails verification
    while looking, in every text dump, exactly correct.
    """

    names: list[x509.GeneralName] = []
    for hostname in hostnames:
        candidate = hostname.strip()
        if not candidate:
            continue
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            names.append(x509.DNSName(candidate))
    return names
