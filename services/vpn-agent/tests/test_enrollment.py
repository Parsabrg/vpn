"""A node obtaining the identity it needs before it can serve anything.

The exchange is exercised against a stand-in control plane that really signs
what it is sent, because the failure this command exists to avoid is not
"the request was refused" -- it is a node that enrolls successfully and then
cannot complete a single TLS handshake, because the certificate on disk does
not go with the key beside it. Only real material can show that.

The rest is refusals. This runs once, as root, on a host nobody is watching,
and each of these is a way for it to appear to succeed while leaving the node
unusable.
"""

import json
import os
import ssl
import sys
import types
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nebula_agent import enrollment
from nebula_agent.enrollment import EnrollmentError, enroll
from nebula_agent.settings import Settings

CONTROL_PLANE = "https://api.example.com:8444"


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        # HTTPError treats what it is handed as a file and closes it.
        return None


def _authority() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test deployment")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _stub_control_plane(
    monkeypatch: pytest.MonkeyPatch,
    *,
    label: str = "node-02",
    omit: str | None = None,
) -> list[dict[str, Any]]:
    """A control plane that signs for real. Returns the requests it received."""

    key, ca_certificate = _authority()
    received: list[dict[str, Any]] = []

    def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
        payload = json.loads(request.data)
        received.append(payload)
        csr = x509.load_pem_x509_csr(payload["certificate_request"].encode())
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .sign(key, hashes.SHA256())
        )
        body = {
            "server_id": str(uuid4()),
            "label": label,
            "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode(),
            "ca_certificate": ca_certificate.public_bytes(serialization.Encoding.PEM).decode(),
        }
        if omit is not None:
            body.pop(omit)
        return _Response(json.dumps(body).encode())

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return received


def _refusing_control_plane(monkeypatch: pytest.MonkeyPatch, status: int, detail: str) -> None:
    def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
        raise urllib.error.HTTPError(
            CONTROL_PLANE,
            status,
            "refused",
            {},  # type: ignore[arg-type]
            _Response(json.dumps({"detail": detail}).encode()),  # type: ignore[arg-type]
        )

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)


def _unreachable_control_plane(monkeypatch: pytest.MonkeyPatch) -> None:
    def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)


def _record(into: list[tuple[Path, str]], path: Path, group: str) -> None:
    into.append((path, group))


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "certificate_path": tmp_path / "agent_tls_cert",
        "key_path": tmp_path / "agent_tls_key",
        "ca_path": tmp_path / "agent_trusted_client_ca",
    }


def _enroll(tmp_path: Path, **overrides: Any) -> tuple[str, str | None] | None:
    arguments: dict[str, Any] = {
        **_paths(tmp_path),
        "control_plane": CONTROL_PLANE,
        "token": "v1.aaaa",
        "public_host": "vps2.example.com",
        "agent_host": "10.0.0.2",
        "agent_port": 9443,
    }
    arguments.update(overrides)
    return enroll(**arguments)


class TestAFreshNode:
    def test_the_certificate_it_receives_goes_with_the_key_it_kept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The whole point. A mismatched pair passes every check this command
        # makes and then fails at the first handshake, where it reads as the
        # control plane not trusting this node rather than as this node
        # holding the wrong key.
        _stub_control_plane(monkeypatch)
        paths = _paths(tmp_path)

        _enroll(tmp_path)

        key = serialization.load_pem_private_key(paths["key_path"].read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(paths["certificate_path"].read_bytes())
        assert certificate.public_key().public_numbers() == key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_the_certificate_was_issued_by_the_authority_it_also_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The agent verifies the control plane's client certificate against
        # this file. One that did not issue the node's own certificate would
        # mean the two ends trust different authorities and never connect.
        _stub_control_plane(monkeypatch)
        paths = _paths(tmp_path)

        _enroll(tmp_path)

        certificate = x509.load_pem_x509_certificate(paths["certificate_path"].read_bytes())
        authority = x509.load_pem_x509_certificate(paths["ca_path"].read_bytes())
        assert certificate.issuer == authority.subject

    def test_the_private_key_never_crosses_the_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        received = _stub_control_plane(monkeypatch)

        _enroll(tmp_path)

        assert "PRIVATE KEY" not in json.dumps(received[0])

    def test_the_request_proves_this_host_holds_the_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Without a valid signature the request is just a public key, and
        # anyone relaying it could obtain a certificate over a key they hold.
        received = _stub_control_plane(monkeypatch)

        _enroll(tmp_path)

        request = x509.load_pem_x509_csr(received[0]["certificate_request"].encode())
        assert request.is_signature_valid

    def test_the_node_does_not_ask_to_be_called_anything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The name comes from the token. A node that could choose its own
        # would be able to ask for one already enrolled.
        received = _stub_control_plane(monkeypatch)

        enrolled = _enroll(tmp_path)

        assert enrolled is not None
        assert enrolled[0] == "node-02"
        assert "label" not in received[0]

    def test_it_says_where_it_can_be_reached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        received = _stub_control_plane(monkeypatch)

        _enroll(tmp_path)

        assert received[0]["public_host"] == "vps2.example.com"
        assert received[0]["agent_host"] == "10.0.0.2"
        assert received[0]["agent_port"] == 9443

    @pytest.mark.skipif(
        os.name != "posix",
        reason="Windows does not implement POSIX permission bits; the mode is "
        "still requested and applies wherever this actually runs",
    )
    def test_the_key_is_not_readable_by_anyone_else(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_control_plane(monkeypatch)

        _enroll(tmp_path)

        assert _paths(tmp_path)["key_path"].stat().st_mode & 0o077 == 0
        # The certificate and the authority are public by construction, and
        # the agent process reads them as a different user than enrolled.
        assert _paths(tmp_path)["certificate_path"].stat().st_mode & 0o044 != 0

    def test_the_agent_is_given_access_to_the_key_it_was_issued(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # This runs as root and the service does not. A key left root-only is
        # a key the agent cannot read, and that surfaces at start-up as a
        # permission error on a file that looks entirely correct.
        _stub_control_plane(monkeypatch)
        granted: list[tuple[Path, str]] = []
        monkeypatch.setattr(
            enrollment,
            "_grant_service_access",
            lambda path, group: _record(granted, path, group),
        )

        _enroll(tmp_path, service_group="nebula-agent")

        assert granted == [(_paths(tmp_path)["key_path"], "nebula-agent")]

    def test_a_failure_to_grant_access_is_reported_rather_than_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The node is enrolled and the token is spent by this point. Raising
        # would leave an operator holding a working certificate and a command
        # that now refuses to run again, with no idea what to do next.
        _stub_control_plane(monkeypatch)
        monkeypatch.setattr(
            enrollment, "_grant_service_access", lambda path, group: "no such group"
        )

        enrolled = _enroll(tmp_path, service_group="nebula-agent")

        assert enrolled == ("node-02", "no such group")
        assert _paths(tmp_path)["certificate_path"].exists()

    def test_nothing_is_chowned_when_no_group_was_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _stub_control_plane(monkeypatch)
        monkeypatch.setattr(
            enrollment,
            "_grant_service_access",
            lambda path, group: pytest.fail("should not have been called"),
        )

        assert _enroll(tmp_path) == ("node-02", None)

    @pytest.mark.skipif(os.name != "posix", reason="POSIX ownership only")
    def test_an_unknown_group_produces_the_command_that_fixes_it(self, tmp_path: Path) -> None:
        key = tmp_path / "agent_tls_key"
        key.write_text("a key")

        warning = enrollment._grant_service_access(key, "a-group-that-does-not-exist")

        assert warning is not None
        assert "chown root:a-group-that-does-not-exist" in warning


class TestItRefusesBeforeMintingAnything:
    """Each of these leaves the node exactly as it was found."""

    def test_a_plaintext_control_plane_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The token is a bearer credential that enrols a node into this
        # deployment. Sending it unverified sends it to whoever answered.
        received = _stub_control_plane(monkeypatch)

        with pytest.raises(EnrollmentError, match="https"):
            _enroll(tmp_path, control_plane="http://api.example.com:8444")

        assert received == []
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize("host", ["vpn.example.com", "example.com"])
    def test_an_example_address_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        # A node enrolled at the shipped default is recorded by the control
        # plane at an address nothing answers on, and every client handed
        # that server fails to connect -- after enrollment reported success.
        received = _stub_control_plane(monkeypatch)

        with pytest.raises(EnrollmentError, match="example value"):
            _enroll(tmp_path, public_host=host)

        assert received == []

    @pytest.mark.parametrize("host", ["0.0.0.0", "::"])  # noqa: S104 - refused, never bound
    def test_a_wildcard_bind_is_not_an_address_to_dial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
    ) -> None:
        received = _stub_control_plane(monkeypatch)

        with pytest.raises(EnrollmentError, match="listen"):
            _enroll(tmp_path, agent_host=host)

        assert received == []

    def test_an_identity_is_never_written_to_tmpfs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # /run is wiped on every boot. A node enrolled there comes back after
        # a reboot unable to serve, looking like a broken agent rather than
        # like an identity that evaporated.
        received = _stub_control_plane(monkeypatch)

        with pytest.raises(EnrollmentError, match="/run"):
            _enroll(
                tmp_path,
                certificate_path=Path("/run/nebula-secrets/agent_tls_cert"),
                key_path=Path("/run/nebula-secrets/agent_tls_key"),
                ca_path=Path("/run/nebula-secrets/agent_trusted_client_ca"),
            )

        assert received == []

    def test_the_shipped_default_paths_are_the_ones_refused(self) -> None:
        # Pins the check above to the actual defaults rather than to a string
        # a test invented, so moving the defaults cannot quietly defeat it.
        settings = Settings(env="test")

        assert str(settings.agent_tls_cert_file).startswith("/run/")
        assert str(settings.agent_tls_key_file).startswith("/run/")
        assert str(settings.agent_trusted_client_ca_file).startswith("/run/")

    def test_a_half_written_identity_is_refused_rather_than_completed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Filling in the missing piece now would pair a fresh key with an old
        # certificate, which fails later and somewhere else.
        received = _stub_control_plane(monkeypatch)
        paths = _paths(tmp_path)
        paths["certificate_path"].write_text("a certificate from a previous attempt")

        with pytest.raises(EnrollmentError, match="partly enrolled"):
            _enroll(tmp_path)

        assert received == []
        assert paths["certificate_path"].read_text() == "a certificate from a previous attempt"


class TestANodeThatAlreadyHasAnIdentity:
    def test_enrolling_again_changes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An installer that reruns must not spend a second token, and must
        # certainly not replace a working certificate with a new one.
        received = _stub_control_plane(monkeypatch)
        paths = _paths(tmp_path)
        for path in paths.values():
            path.write_text("existing")

        assert _enroll(tmp_path) is None
        assert received == []
        assert all(path.read_text() == "existing" for path in paths.values())


class TestWhenTheControlPlaneWillNotIssue:
    def test_a_refusal_is_reported_as_the_control_plane_worded_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # That end answers every bad token with one sentence on purpose.
        # Inventing a more specific reason here would be guessing.
        _refusing_control_plane(monkeypatch, 400, "Enrollment was not accepted")

        with pytest.raises(EnrollmentError, match="Enrollment was not accepted"):
            _enroll(tmp_path)

        assert list(tmp_path.iterdir()) == []

    def test_an_uninitialised_control_plane_says_what_to_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 503 is an operator problem at the other end, not a bad token.
        # Reporting it as a refusal sends somebody to inspect their token.
        _refusing_control_plane(monkeypatch, 503, "unavailable")

        with pytest.raises(EnrollmentError, match="nebula-api initialize"):
            _enroll(tmp_path)

    def test_an_unreachable_control_plane_is_reported_as_such(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unreachable_control_plane(monkeypatch)

        with pytest.raises(EnrollmentError, match="could not be reached"):
            _enroll(tmp_path)

        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize("missing", ["certificate", "ca_certificate", "label"])
    def test_an_incomplete_answer_leaves_nothing_behind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
    ) -> None:
        # Writing the parts that did arrive would produce exactly the
        # half-enrolled state the check above exists to catch.
        _stub_control_plane(monkeypatch, omit=missing)

        with pytest.raises(EnrollmentError, match=missing):
            _enroll(tmp_path)

        assert list(tmp_path.iterdir()) == []

    def test_a_refusal_with_no_readable_body_still_reports_something(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A reverse proxy in front of the control plane answers with HTML,
        # not JSON. Failing to parse it must not turn a refusal into a
        # traceback on an operator's terminal.
        def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
            raise urllib.error.HTTPError(
                CONTROL_PLANE,
                502,
                "bad gateway",
                {},  # type: ignore[arg-type]
                _Response(b"<html>502 Bad Gateway</html>"),  # type: ignore[arg-type]
            )

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)

        with pytest.raises(EnrollmentError, match="502"):
            _enroll(tmp_path)

    def test_json_that_is_not_an_object_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
            return _Response(b"[]")

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)

        with pytest.raises(EnrollmentError, match="not a response"):
            _enroll(tmp_path)

    def test_a_response_that_is_not_a_response_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def urlopen(request: Any, timeout: float | None = None, context: Any = None) -> _Response:
            return _Response(b"<html>a proxy got in the way</html>")

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)

        with pytest.raises(EnrollmentError, match="not a response"):
            _enroll(tmp_path)


class TestTheToken:
    def test_it_is_read_from_a_file_rather_than_the_command_line(self, tmp_path: Path) -> None:
        # Arguments to a running process are readable by every other user on
        # the host through /proc, and land in shell history besides.
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa\n")

        assert enrollment._read_token(str(token_file)) == "v1.aaaa"

    def test_it_can_come_from_standard_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(read=lambda: "  v1.aaaa  \n"))

        assert enrollment._read_token(None) == "v1.aaaa"

    def test_an_empty_token_is_refused_before_anything_is_generated(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token"
        token_file.write_text("\n\n")

        with pytest.raises(EnrollmentError, match="no enrollment token"):
            enrollment._read_token(str(token_file))


class TestTheCommand:
    def _settings(self, tmp_path: Path) -> Any:
        paths = _paths(tmp_path)
        return types.SimpleNamespace(
            agent_tls_cert_file=paths["certificate_path"],
            agent_tls_key_file=paths["key_path"],
            agent_trusted_client_ca_file=paths["ca_path"],
            xray_public_host="vps2.example.com",
            agent_bind_port=9443,
        )

    def test_a_successful_enrollment_names_the_node_and_succeeds(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _stub_control_plane(monkeypatch)
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa")

        code = enrollment.main(["--control-plane", CONTROL_PLANE, "--token-file", str(token_file)])

        assert code == 0
        assert "enrolled as node-02" in capsys.readouterr().out

    def test_the_agent_host_defaults_to_the_public_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A single-VPS deployment reaches the agent at the same address
        # clients reach the VPN at, which is the common case and should not
        # need saying twice.
        received = _stub_control_plane(monkeypatch)
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa")

        enrollment.main(["--control-plane", CONTROL_PLANE, "--token-file", str(token_file)])

        assert received[0]["agent_host"] == received[0]["public_host"] == "vps2.example.com"

    def test_a_failure_reports_on_standard_error_and_does_not_succeed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The exit code is what an installer branches on; printing the
        # problem and returning zero would let a broken node look installed.
        _refusing_control_plane(monkeypatch, 400, "Enrollment was not accepted")
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa")

        code = enrollment.main(["--control-plane", CONTROL_PLANE, "--token-file", str(token_file)])

        assert code == 1
        assert "enrollment failed" in capsys.readouterr().err

    def test_an_already_enrolled_node_succeeds_quietly(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))
        for path in _paths(tmp_path).values():
            path.write_text("existing")
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa")

        code = enrollment.main(["--control-plane", CONTROL_PLANE, "--token-file", str(token_file)])

        assert code == 0
        assert "already enrolled" in capsys.readouterr().out

    def test_a_key_the_agent_cannot_read_is_called_out(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Enrollment succeeded, so the exit code stays zero -- but an agent
        # that cannot read its own key will not start, and the operator has
        # to be told while they are still looking at the terminal.
        _stub_control_plane(monkeypatch)
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))
        monkeypatch.setattr(
            enrollment, "_grant_service_access", lambda path, group: "chown root:nebula-agent ..."
        )
        token_file = tmp_path / "token"
        token_file.write_text("v1.aaaa")

        code = enrollment.main(["--control-plane", CONTROL_PLANE, "--token-file", str(token_file)])

        assert code == 0
        assert "chown root:nebula-agent" in capsys.readouterr().err

    def test_a_missing_token_file_is_an_ordinary_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An OSError escaping here would print a traceback at an operator
        # who mistyped a path.
        monkeypatch.setattr(enrollment, "get_settings", lambda: self._settings(tmp_path))

        code = enrollment.main(
            ["--control-plane", CONTROL_PLANE, "--token-file", str(tmp_path / "absent")]
        )

        assert code == 1


def test_the_context_requires_a_modern_tls_version() -> None:
    context = enrollment._tls_context(CONTROL_PLANE, None)

    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_a_private_authority_can_be_supplied_for_the_control_plane(tmp_path: Path) -> None:
    # A self-hosted deployment whose control plane does not have a publicly
    # trusted certificate still has to be verified against something. This is
    # that something; there is deliberately no way to verify against nothing.
    _, certificate = _authority()
    ca_file = tmp_path / "control_plane_ca"
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    context = enrollment._tls_context(CONTROL_PLANE, str(ca_file))

    assert context.get_ca_certs()
