"""Turning an enrollment token into this node's TLS identity.

A fresh VPS has no way to talk to the control plane. The agent serves under
mutual TLS, so it needs a certificate before it can answer anything -- and it
cannot ask for one over a channel that does not exist yet. An enrollment
token is the way out: an administrator mints one, it travels here by whatever
means the operator already trusts, and this command exchanges it for a
certificate signed by the deployment's own authority.

It runs once, as root, before the service starts, and deliberately not from
inside the service:

  - the unit mounts the secrets directory read-only, so the running agent
    could not write there even if it wanted to
  - a service that can replace its own identity while running is a service
    that can be pointed at another control plane by anyone who can restart it

The private key is generated here and never leaves this host. What crosses
the network is a certificate request -- a public key and a signature proving
this host holds the matching private one -- and the token. Nothing that comes
back is secret.

    nebula-agent-enroll --control-plane https://api.example.com --token-file /root/token

Running it again on an enrolled node changes nothing and exits successfully,
so an installer that reruns is not a problem.
"""

import argparse
import json
import os
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nebula_agent.settings import get_settings

ENROLL_PATH = "/v1/nodes/enroll"

# The group the systemd unit runs the agent as (deploy/nebula-vpn-agent.service).
DEFAULT_SERVICE_GROUP = "nebula-agent"

# Long enough to cross a real network to a control plane that may be busy,
# short enough that a wrong address does not look like a hang.
_TIMEOUT_SECONDS = 30.0

# What the repository ships as a default. A node that enrolled with one of
# these would be recorded by the control plane at an address nothing answers
# on, and every client handed that server would simply fail to connect --
# with the enrollment itself having reported success.
_PLACEHOLDER_HOSTS = frozenset({"vpn.example.com", "vpn.example.org", "example.com"})

# Wildcard binds. Meaningful to a listening socket, meaningless as somewhere
# to dial, which is what both of these fields are for.
_UNROUTABLE_HOSTS = frozenset({"0.0.0.0", "::", "*"})  # noqa: S104 - refused, never bound


class EnrollmentError(Exception):
    """Anything that stops this node obtaining an identity."""


def _require_persistent(paths: list[Path]) -> None:
    """Refuse to write an identity somewhere that does not survive a reboot.

    /run is tmpfs. A certificate written there is gone at the next boot and
    the node comes back unable to serve, which reads as the agent being
    broken rather than as its identity having evaporated. The service unit
    already points these at /etc/nebula/secrets for exactly this reason; a
    host still on the development defaults has not been configured yet.
    """

    if any(path.as_posix().startswith("/run/") for path in paths):
        raise EnrollmentError(
            "the agent's certificate paths are under /run, which is wiped on every "
            "reboot; point NEBULA_AGENT_TLS_CERT_FILE, NEBULA_AGENT_TLS_KEY_FILE and "
            "NEBULA_AGENT_TRUSTED_CLIENT_CA_FILE at persistent storage before enrolling"
        )


def _already_enrolled(paths: list[Path]) -> bool:
    """Whether this node has an identity, refusing a half-written one.

    A certificate without its key cannot be presented and a key without its
    certificate cannot be verified. Either alone means a previous attempt
    stopped partway, and writing the missing piece now would produce a pair
    that does not match -- a failure that surfaces later, at the first
    connection, as something that looks nothing like this.
    """

    present = [path for path in paths if path.exists()]
    if not present:
        return False
    if len(present) == len(paths):
        return True
    raise EnrollmentError(
        "this node is partly enrolled: "
        + ", ".join(str(path) for path in present)
        + " exist but the rest do not; remove them and enroll again"
    )


def _read_token(token_file: str | None) -> str:
    """The token, from a file or standard input -- never from the argv.

    Arguments to a running process are readable by every other user on the
    host through /proc, and land in the operator's shell history besides.
    """

    if token_file is None or token_file == "-":  # noqa: S105 - a path, not a secret
        token = sys.stdin.read()
    else:
        token = Path(token_file).read_text(encoding="utf-8")
    token = token.strip()
    if not token:
        raise EnrollmentError("no enrollment token was supplied")
    return token


def build_certificate_request(common_name: str) -> tuple[bytes, bytes]:
    """A key for this node and a request over it.

    The common name here is a formality: the control plane rebuilds the
    subject from the token it was minted against and ignores whatever this
    says, because a node able to name itself could ask for another node's
    name. It is filled in so the request is well formed and so an operator
    reading it sees something recognisable.
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


def _tls_context(control_plane: str, ca_file: str | None) -> ssl.SSLContext:
    """Verification, always.

    There is no option to turn this off and there should not be. The token is
    a bearer credential that enrols a node into this deployment; handing it to
    an unverified endpoint hands it to whoever answered. A deployment whose
    control plane uses a private authority passes that authority here instead.
    """

    if urlsplit(control_plane).scheme != "https":
        raise EnrollmentError("the control plane address must be https")
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _post(url: str, payload: dict[str, object], context: ssl.SSLContext) -> dict[str, str]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - scheme checked in _tls_context
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - scheme checked in _tls_context
            request, timeout=_TIMEOUT_SECONDS, context=context
        ) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        # The control plane answers every bad token with one sentence, on
        # purpose. Passing it through unchanged keeps this end from inventing
        # a more specific reason than the other end was willing to give.
        raise EnrollmentError(_rejection(error)) from None
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as error:
        raise EnrollmentError(f"the control plane could not be reached: {error}") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EnrollmentError("the control plane sent something that was not a response") from None
    if not isinstance(decoded, dict):
        raise EnrollmentError("the control plane sent something that was not a response")
    return decoded


def _rejection(error: urllib.error.HTTPError) -> str:
    try:
        detail = json.loads(error.read().decode("utf-8")).get("detail")
    except (ValueError, OSError, AttributeError):
        detail = None
    if error.code == 503:
        return (
            "the control plane cannot issue certificates yet; ask its operator "
            "to run `nebula-api initialize`"
        )
    return f"enrollment was refused ({error.code}): {detail or 'no reason given'}"


def _write(path: Path, content: str, *, mode: int) -> None:
    """Create the file, never replace one.

    Silently overwriting an identity would strand whichever half was not
    replaced, and the exclusive create is what makes the partial-enrollment
    check above meaningful rather than advisory.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def _grant_service_access(path: Path, group: str) -> str | None:
    """Let the agent read the key this command just wrote.

    Enrollment runs as root and the service does not, so a key left at 0600
    root-owned is a key the agent cannot read -- and the failure surfaces at
    start-up as a permission error on a file that looks perfectly correct.
    The mode matches what the deployment README already specifies for
    everything else in that directory.

    Reported rather than raised: the certificate is valid and the node is
    enrolled, so failing here would leave the operator holding a spent token
    and a command that now refuses to run again. What they need is the one
    line that fixes it.
    """

    if os.name != "posix":
        return None
    try:
        shutil.chown(path, group=group)
        path.chmod(0o640)
    except (LookupError, OSError) as error:
        return (
            f"the key is readable only by root ({error}); the agent runs as another "
            f"user, so give it access with: chown root:{group} {path} && chmod 0640 {path}"
        )
    return None


def enroll(
    *,
    certificate_path: Path,
    key_path: Path,
    ca_path: Path,
    control_plane: str,
    token: str,
    public_host: str,
    agent_host: str,
    agent_port: int,
    control_plane_ca_file: str | None = None,
    service_group: str | None = None,
    protocol_profiles: list[str] | None = None,
) -> tuple[str, str | None] | None:
    """Obtain and install this node's identity.

    Returns the name it was enrolled under and anything the operator still
    needs to do by hand, or None if this node already had an identity.
    """

    for field, host in (("public host", public_host), ("agent host", agent_host)):
        if host in _PLACEHOLDER_HOSTS:
            raise EnrollmentError(
                f"the {field} is still the example value {host!r}; set the real address"
            )
        if host in _UNROUTABLE_HOSTS:
            raise EnrollmentError(
                f"the {field} is {host!r}, which is somewhere to listen rather than "
                "somewhere to dial; give the address this node is reached at"
            )

    _require_persistent([certificate_path, key_path, ca_path])
    if _already_enrolled([certificate_path, key_path, ca_path]):
        return None

    # Before generating anything: a refusal here is about how this command
    # was invoked, and finding that out after minting a key would mean the
    # first thing a mistyped address produces is a discarded private key.
    context = _tls_context(control_plane, control_plane_ca_file)
    csr_pem, key_pem = build_certificate_request(public_host)
    answer = _post(
        control_plane.rstrip("/") + ENROLL_PATH,
        {
            "token": token,
            "certificate_request": csr_pem.decode("ascii"),
            "public_host": public_host,
            "agent_host": agent_host,
            "agent_port": agent_port,
            "protocol_profiles": list(protocol_profiles or []),
        },
        context,
    )
    for field in ("certificate", "ca_certificate", "label"):
        value = answer.get(field)
        if not isinstance(value, str) or not value:
            raise EnrollmentError(f"the control plane's response had no {field}")

    # The key first and at 0600: it is the only part of this that is secret,
    # and the mode is set by the open rather than afterwards so there is no
    # instant where it exists world-readable.
    _write(key_path, key_pem.decode("ascii"), mode=0o600)
    _write(certificate_path, answer["certificate"], mode=0o644)
    _write(ca_path, answer["ca_certificate"], mode=0o644)
    warning = _grant_service_access(key_path, service_group) if service_group else None
    return answer["label"], warning


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nebula-agent-enroll",
        description="Exchange an enrollment token for this node's TLS identity.",
    )
    parser.add_argument(
        "--control-plane", required=True, help="https address of the deployment's API"
    )
    parser.add_argument(
        "--token-file", help="file holding the enrollment token; standard input when omitted"
    )
    parser.add_argument(
        "--public-host", help="where clients reach this node (default: NEBULA_XRAY_PUBLIC_HOST)"
    )
    parser.add_argument(
        "--agent-host", help="where the control plane reaches this agent (default: the public host)"
    )
    parser.add_argument(
        "--agent-port", type=int, help="port this agent serves on (default: NEBULA_AGENT_BIND_PORT)"
    )
    parser.add_argument(
        "--service-group",
        default=DEFAULT_SERVICE_GROUP,
        help="group the agent runs as, given read access to the key it was issued "
        f"(default: {DEFAULT_SERVICE_GROUP}; pass an empty value to leave it root-only)",
    )
    parser.add_argument(
        "--control-plane-ca",
        help="certificate authority to verify the control plane against, for a "
        "deployment not using a publicly trusted certificate",
    )
    return parser


def _served_profiles(settings: object) -> list[str]:
    """What this node will serve, so the control plane offers it at once."""

    from nebula_agent.driver_factory import build_xray_driver

    codes: list[str] = []
    if getattr(settings, "wg_driver", "fake") == "native":
        codes.append("wireguard-native")
    if getattr(settings, "xray_enabled", False):
        driver = build_xray_driver(settings)  # type: ignore[arg-type]
        advertised = getattr(driver, "advertised_endpoints", None)
        if advertised is not None:
            codes.extend(code for code, *_ in advertised())
    return codes


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    settings = get_settings()
    # Defaulted from settings rather than recomputed, so what this node
    # enrols as is the same thing it goes on to advertise. The bind host is
    # deliberately not a default for --agent-host: it is frequently 0.0.0.0,
    # which is not an address anything can dial.
    public_host = arguments.public_host or settings.xray_public_host
    try:
        enrolled = enroll(
            certificate_path=Path(settings.agent_tls_cert_file),
            key_path=Path(settings.agent_tls_key_file),
            ca_path=Path(settings.agent_trusted_client_ca_file),
            control_plane=arguments.control_plane,
            token=_read_token(arguments.token_file),
            public_host=public_host,
            agent_host=arguments.agent_host or public_host,
            agent_port=arguments.agent_port or settings.agent_bind_port,
            control_plane_ca_file=arguments.control_plane_ca,
            service_group=arguments.service_group or None,
            protocol_profiles=_served_profiles(settings),
        )
    except (EnrollmentError, OSError) as error:
        print(f"enrollment failed: {error}", file=sys.stderr)
        return 1
    if enrolled is None:
        print("this node is already enrolled; nothing to do")
        return 0
    label, warning = enrolled
    print(f"enrolled as {label}")
    if warning is not None:
        print(f"warning: {warning}", file=sys.stderr)
    print("start the agent with: systemctl restart nebula-vpn-agent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
