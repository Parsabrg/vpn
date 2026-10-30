"""Initialization that runs on every start.

The entrypoint runs this again on every restart, redeploy and crash loop, so
"safe to rerun" is not a nicety here -- it is the only mode it ever runs in.
Every failure it can have is silent: a second identity orphans every enrolled
node while looking like a clean install, and a replaced secret invalidates
outstanding enrolments with no error anywhere.
"""

import asyncio
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import Table

from nebula_api.bootstrap import (
    DEPLOYMENT_SECRET_BYTES,
    ensure_control_plane_identity,
    ensure_deployment,
    ensure_deployment_secret,
    ensure_node_authority,
    read_deployment_secret,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.models.deployment import Deployment
from nebula_api.pki import (
    PkiError,
    create_certificate_request,
    load_certificate_authority,
    sign_node_certificate,
)


class FakeSession:
    """One in-memory deployment row, shared across calls like a real table."""

    def __init__(self) -> None:
        self.row: Deployment | None = None
        self.added: list[object] = []
        self.commits = 0
        self.locks = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, statement: object) -> Any:
        if "pg_advisory_xact_lock" in str(statement):
            self.locks += 1
        return None

    async def scalar(self, _statement: object) -> Any:
        return self.row

    def add(self, value: object) -> None:
        self.added.append(value)
        self.row = cast(Deployment, value)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        return None


def _factory(session: FakeSession) -> SessionFactory:
    return cast(SessionFactory, lambda: session)


class TestTheIdentityIsGeneratedOnce:
    def test_a_fresh_installation_gets_an_identity(self) -> None:
        session = FakeSession()

        deployment, created = asyncio.run(ensure_deployment(_factory(session), name="Home"))

        assert created
        assert deployment.name == "Home"
        assert deployment.id is not None

    def test_running_again_keeps_the_same_identity(self) -> None:
        # The whole point. A second identity would orphan every node enrolled
        # against the first while looking like a successful clean install.
        session = FakeSession()

        first, created_first = asyncio.run(ensure_deployment(_factory(session), name="Home"))
        second, created_second = asyncio.run(ensure_deployment(_factory(session), name="Home"))

        assert created_first
        assert not created_second
        assert first.id == second.id
        assert len(session.added) == 1

    def test_the_identity_is_not_derived_from_anything_guessable(self) -> None:
        # Not the hostname, not the admin address, not a counter. Two installs
        # configured identically must not end up with the same identity, or
        # "which deployment answered" stops being a question with an answer.
        first = asyncio.run(
            ensure_deployment(_factory(FakeSession()), name="Home", admin_email="a@example.org")
        )[0]
        second = asyncio.run(
            ensure_deployment(_factory(FakeSession()), name="Home", admin_email="a@example.org")
        )[0]

        assert first.id != second.id

    def test_the_lock_is_taken_before_looking(self) -> None:
        # Two containers starting together behind one compose file is the
        # expected case, not a rare race.
        session = FakeSession()

        asyncio.run(ensure_deployment(_factory(session), name="Home"))

        assert session.locks == 1


class TestConfigurationCanChange:
    def test_a_renamed_deployment_keeps_its_identity(self) -> None:
        # The name is configuration and an operator may edit it; the identity
        # is not, and must survive them doing so.
        session = FakeSession()

        first, _ = asyncio.run(ensure_deployment(_factory(session), name="Home"))
        original_id = first.id
        second, created = asyncio.run(ensure_deployment(_factory(session), name="Frankfurt"))

        assert not created
        assert second.id == original_id
        assert second.name == "Frankfurt"

    def test_the_admin_email_is_recorded_as_configuration(self) -> None:
        session = FakeSession()

        deployment, _ = asyncio.run(
            ensure_deployment(_factory(session), name="Home", admin_email="ops@example.org")
        )

        assert deployment.admin_email == "ops@example.org"

    def test_omitting_the_admin_email_does_not_erase_the_stored_one(self) -> None:
        # A restart without the environment variable set must not silently
        # unconfigure the deployment.
        session = FakeSession()
        asyncio.run(
            ensure_deployment(_factory(session), name="Home", admin_email="ops@example.org")
        )

        deployment, _ = asyncio.run(ensure_deployment(_factory(session), name="Home"))

        assert deployment.admin_email == "ops@example.org"


class TestTheSecret:
    def test_a_fresh_installation_gets_one(self, tmp_path: Path) -> None:
        path = tmp_path / "deployment_secret"

        created = ensure_deployment_secret(path)

        assert created
        assert len(path.read_bytes()) == DEPLOYMENT_SECRET_BYTES

    def test_it_is_stored_byte_for_byte(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Opened in text mode on Windows, every 0x0A byte was written as CRLF:
        # one random secret in eight came out too long and was refused.
        secret = bytes([0x0A]) * DEPLOYMENT_SECRET_BYTES
        monkeypatch.setattr("nebula_api.bootstrap.secrets.token_bytes", lambda _n: secret)
        path = tmp_path / "deployment_secret"

        ensure_deployment_secret(path)

        assert path.read_bytes() == secret

    def test_running_again_never_replaces_it(self, tmp_path: Path) -> None:
        # It signs enrollment tokens. Replacing it invalidates every
        # outstanding enrolment, and nothing anywhere reports that.
        path = tmp_path / "deployment_secret"
        ensure_deployment_secret(path)
        original = path.read_bytes()

        created_again = ensure_deployment_secret(path)

        assert not created_again
        assert path.read_bytes() == original

    def test_two_installations_do_not_share_a_secret(self, tmp_path: Path) -> None:
        first = tmp_path / "a" / "deployment_secret"
        second = tmp_path / "b" / "deployment_secret"

        ensure_deployment_secret(first)
        ensure_deployment_secret(second)

        assert first.read_bytes() != second.read_bytes()

    def test_a_truncated_secret_is_refused_rather_than_used(self, tmp_path: Path) -> None:
        # Half a key verifies nothing reliably. Failing loudly beats signing
        # tokens with whatever happened to survive a bad write.
        path = tmp_path / "deployment_secret"
        path.write_bytes(b"too short")

        with pytest.raises(ValueError):
            read_deployment_secret(path)

    def test_the_directory_is_created_when_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "not" / "there" / "deployment_secret"

        assert ensure_deployment_secret(path)
        assert path.exists()


def test_a_deployment_carries_no_secret_of_its_own() -> None:
    # The identity is public and the secret is not, so they live in different
    # places. A secret column would end up in a backup, a log line, or an API
    # response the first time somebody serialised the row.
    columns = set(cast(Table, Deployment.__table__).columns.keys())

    assert "secret" not in columns
    assert not any("secret" in name for name in columns)
    assert {"id", "name", "admin_email", "initialized_at"} <= columns


def test_the_table_admits_exactly_one_row() -> None:
    # Enforced in the schema rather than by the code that writes it, because
    # "do not regenerate the identity" is the requirement and code paths are
    # easier to add than constraints are to notice missing.
    table = cast(Table, Deployment.__table__)
    indexes = {index.name for index in table.indexes}

    assert "uq_deployments_singleton" in indexes
    singleton = next(index for index in table.indexes if index.name == "uq_deployments_singleton")
    assert singleton.unique


def test_an_identity_is_a_uuid_not_an_address_or_an_email() -> None:
    deployment, _ = asyncio.run(
        ensure_deployment(_factory(FakeSession()), name="Home", admin_email="ops@example.org")
    )

    rendered = str(deployment.id)
    assert "ops@example.org" not in rendered
    assert "Home" not in rendered
    assert len(rendered) == 36
    assert uuid4() != deployment.id


class TestTheNodeAuthority:
    def test_a_fresh_installation_gets_one(self, tmp_path: Path) -> None:
        created = ensure_node_authority(
            tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt"
        )

        assert created
        assert load_certificate_authority(tmp_path / "ca", tmp_path / "ca.key")

    def test_running_again_never_replaces_it(self, tmp_path: Path) -> None:
        # Every certificate this deployment ever issued to a node chains to
        # it. A new CA silently stops the control plane trusting every node it
        # already enrolled, and each failure looks like the node being
        # misconfigured rather than the authority having changed.
        ensure_node_authority(tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt")
        original = (tmp_path / "ca").read_bytes()

        created_again = ensure_node_authority(
            tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt"
        )

        assert not created_again
        assert (tmp_path / "ca").read_bytes() == original

    def test_a_half_written_authority_is_refused_rather_than_completed(
        self, tmp_path: Path
    ) -> None:
        # A certificate without its key cannot sign, and a key without its
        # certificate cannot be presented. Generating the missing partner
        # would produce a pair that does not match, which fails later and
        # somewhere else.
        (tmp_path / "ca").write_bytes(b"a certificate with no key")

        with pytest.raises(RuntimeError):
            ensure_node_authority(tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt")

    def test_a_key_without_its_certificate_is_refused_too(self, tmp_path: Path) -> None:
        (tmp_path / "ca.key").write_bytes(b"a key with no certificate")

        with pytest.raises(RuntimeError):
            ensure_node_authority(tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt")

    def test_two_installations_never_share_an_authority(self, tmp_path: Path) -> None:
        ensure_node_authority(
            tmp_path / "a" / "ca", tmp_path / "a" / "ca.key", deployment_name="Frankfurt"
        )
        ensure_node_authority(
            tmp_path / "b" / "ca", tmp_path / "b" / "ca.key", deployment_name="Frankfurt"
        )

        assert (tmp_path / "a" / "ca").read_bytes() != (tmp_path / "b" / "ca").read_bytes()


class TestTheControlPlanesOwnCertificate:
    def _authority(self, tmp_path: Path) -> tuple[Path, Path]:
        ensure_node_authority(tmp_path / "ca", tmp_path / "ca.key", deployment_name="Frankfurt")
        return tmp_path / "ca", tmp_path / "ca.key"

    def _issue(self, tmp_path: Path) -> bool:
        certificate, key = self._authority(tmp_path)
        return ensure_control_plane_identity(
            tmp_path / "client",
            tmp_path / "client.key",
            authority_certificate_path=certificate,
            authority_key_path=key,
        )

    def test_a_node_and_the_control_plane_end_up_trusting_each_other(self, tmp_path: Path) -> None:
        # The point of issuing this at all. The node trusts the authority it
        # was enrolled by; a control plane presenting anything else is
        # refused at the handshake, with neither end saying which
        # certificate was wrong.
        authority_path, authority_key = self._authority(tmp_path)
        ensure_control_plane_identity(
            tmp_path / "client",
            tmp_path / "client.key",
            authority_certificate_path=authority_path,
            authority_key_path=authority_key,
        )
        authority = load_certificate_authority(authority_path, authority_key)
        csr, _ = create_certificate_request(common_name="node-02")
        node_certificate = x509.load_pem_x509_certificate(
            sign_node_certificate(
                authority, csr, common_name="node-02", hostnames=["vps2.example.com"]
            )
        )
        client_certificate = x509.load_pem_x509_certificate((tmp_path / "client").read_bytes())

        assert client_certificate.issuer == authority.certificate.subject
        assert node_certificate.issuer == client_certificate.issuer

    def test_the_certificate_goes_with_the_key_beside_it(self, tmp_path: Path) -> None:
        self._issue(tmp_path)

        key = serialization.load_pem_private_key(
            (tmp_path / "client.key").read_bytes(), password=None
        )
        certificate = x509.load_pem_x509_certificate((tmp_path / "client").read_bytes())
        assert certificate.public_key().public_numbers() == key.public_key().public_numbers()  # type: ignore[union-attr]

    def test_it_can_be_presented_as_a_client(self, tmp_path: Path) -> None:
        self._issue(tmp_path)

        certificate = x509.load_pem_x509_certificate((tmp_path / "client").read_bytes())
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in usage

    def test_running_again_never_replaces_it(self, tmp_path: Path) -> None:
        assert self._issue(tmp_path)
        original = (tmp_path / "client").read_bytes()

        assert not self._issue(tmp_path)
        assert (tmp_path / "client").read_bytes() == original

    @pytest.mark.parametrize("existing", ["client", "client.key"])
    def test_a_half_written_identity_is_refused_rather_than_completed(
        self, tmp_path: Path, existing: str
    ) -> None:
        self._authority(tmp_path)
        (tmp_path / existing).write_bytes(b"half of a previous attempt")

        with pytest.raises(RuntimeError):
            ensure_control_plane_identity(
                tmp_path / "client",
                tmp_path / "client.key",
                authority_certificate_path=tmp_path / "ca",
                authority_key_path=tmp_path / "ca.key",
            )

    def test_it_cannot_be_issued_without_an_authority(self, tmp_path: Path) -> None:
        with pytest.raises(PkiError):
            ensure_control_plane_identity(
                tmp_path / "client",
                tmp_path / "client.key",
                authority_certificate_path=tmp_path / "absent",
                authority_key_path=tmp_path / "absent.key",
            )

        assert not (tmp_path / "client").exists()
        assert not (tmp_path / "client.key").exists()
