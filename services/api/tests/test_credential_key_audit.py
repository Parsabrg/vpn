"""Detecting a key that was replaced without its version changing.

This is a reconstruction of a real incident. The Xray encryption key file was
regenerated seventeen minutes after the first credentials were written,
reusing version 1, with no previous-keys directory configured. Fourteen
credentials became permanently undecryptable, nothing recorded that anything
had happened, and establishing why took a byte-level audit and a file birth
timestamp weeks later.

Every test here is about making that situation say its own name.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.provisioning.key_audit import audit_credential_keys
from nebula_api.provisioning.xray_credentials import (
    encrypt_xray_credential,
    key_fingerprint,
)

ORIGINAL_KEY = b"the-key-that-was-replaced-in-aug"
REPLACEMENT_KEY = b"the-key-generated-17-minutes-on!"
DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")


class FakeCredential:
    def __init__(
        self,
        *,
        key: bytes | None,
        key_version: int = 1,
        lost_at: datetime | None = None,
        fingerprint: str | None = None,
    ) -> None:
        self.id = uuid4()
        self.device_id = DEVICE_ID
        self.state = "active"
        self.key_material_lost_at = lost_at
        self.key_fingerprint = fingerprint
        if key is None:
            self.ciphertext = None
            self.nonce = None
            self.key_version = None
            return
        envelope = encrypt_xray_credential(
            uuid4(),
            device_id=DEVICE_ID,
            credential_id=self.id,
            key_version=key_version,
            key_ring={key_version: key},
        )
        self.ciphertext = envelope.ciphertext
        self.nonce = envelope.nonce
        self.key_version = str(key_version)


class FakeClient:
    def __init__(self, credential: FakeCredential) -> None:
        self.credential_id = credential.id


class FakeSession:
    def __init__(self, credentials: list[FakeCredential]) -> None:
        self.credentials = {c.id: c for c in credentials}
        self.commits = 0

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalars(self, _statement: object) -> Any:
        return _Rows([FakeClient(c) for c in self.credentials.values()])

    async def scalar(self, statement: object) -> Any:
        # The audit looks a credential up by the id its client names; the
        # fake resolves that from the statement's bound parameter.
        for value in statement.compile().params.values():  # type: ignore[attr-defined]
            if value in self.credentials:
                return self.credentials[value]
        return None

    async def commit(self) -> None:
        self.commits += 1


class _Rows:
    def __init__(self, rows: list[FakeClient]) -> None:
        self._rows = rows

    def all(self) -> list[FakeClient]:
        return self._rows


def _factory(session: FakeSession) -> SessionFactory:
    return cast(SessionFactory, lambda: session)


def _keys(*keys: bytes) -> AuthKeyMaterial:
    ring = {index + 1: key for index, key in enumerate(keys)}
    return cast(AuthKeyMaterial, type("K", (), {"xray_encryption_keys": ring})())


def _run(session: FakeSession, keys: AuthKeyMaterial, *, mark_lost: bool = False) -> Any:
    return asyncio.run(audit_credential_keys(_factory(session), keys, mark_lost=mark_lost))


def test_a_credential_written_under_the_current_key_is_readable() -> None:
    session = FakeSession([FakeCredential(key=REPLACEMENT_KEY)])

    audit = _run(session, _keys(REPLACEMENT_KEY))

    assert audit.readable == 1
    assert audit.unreadable == 0
    assert not audit.has_losses


def test_a_credential_written_under_a_replaced_key_is_unreadable() -> None:
    # The incident itself: same version, different key, no copy of the old one.
    session = FakeSession([FakeCredential(key=ORIGINAL_KEY)])

    audit = _run(session, _keys(REPLACEMENT_KEY))

    assert audit.unreadable == 1
    assert audit.readable == 0
    assert audit.has_losses


def test_one_version_naming_two_keys_is_reported_as_such() -> None:
    # The signal that makes the cause visible instead of leaving an operator
    # to compare file timestamps against row creation times.
    session = FakeSession(
        [
            FakeCredential(key=ORIGINAL_KEY),
            FakeCredential(key=REPLACEMENT_KEY),
        ]
    )

    audit = _run(session, _keys(REPLACEMENT_KEY, ORIGINAL_KEY))

    assert audit.readable == 2
    assert audit.versions_with_several_keys == ["1"]


def test_a_single_key_per_version_is_not_reported_as_a_swap() -> None:
    session = FakeSession(
        [FakeCredential(key=REPLACEMENT_KEY), FakeCredential(key=REPLACEMENT_KEY)]
    )

    audit = _run(session, _keys(REPLACEMENT_KEY))

    assert audit.versions_with_several_keys == []


def test_an_old_key_kept_in_the_ring_still_opens_its_credentials() -> None:
    # What the previous-keys directory is for. Had it been configured, the
    # fourteen would never have been lost.
    session = FakeSession([FakeCredential(key=ORIGINAL_KEY)])

    audit = _run(session, _keys(REPLACEMENT_KEY, ORIGINAL_KEY))

    assert audit.readable == 1
    assert audit.unreadable == 0


def test_the_recorded_version_is_used_even_while_searching_other_keys() -> None:
    # The AAD binds the version number, so a credential written under version
    # 2 must be tried as version 2 whichever key is being attempted. Varying
    # the version instead of the key material would fail on every candidate
    # and report a healthy credential as lost.
    session = FakeSession([FakeCredential(key=ORIGINAL_KEY, key_version=2)])

    audit = _run(session, _keys(REPLACEMENT_KEY, ORIGINAL_KEY))

    assert audit.readable == 1
    assert audit.fingerprints_by_version == {"2": {key_fingerprint(ORIGINAL_KEY)}}


class TestMarking:
    def test_marking_records_the_loss_rather_than_repairing_it(self) -> None:
        credential = FakeCredential(key=ORIGINAL_KEY)
        session = FakeSession([credential])

        audit = _run(session, _keys(REPLACEMENT_KEY), mark_lost=True)

        assert audit.marked_now == 1
        assert credential.key_material_lost_at is not None
        # The plaintext is gone either way; nothing was recovered.
        assert credential.ciphertext is not None

    def test_reporting_does_not_write_by_default(self) -> None:
        credential = FakeCredential(key=ORIGINAL_KEY)
        session = FakeSession([credential])

        _run(session, _keys(REPLACEMENT_KEY))

        assert credential.key_material_lost_at is None

    def test_an_already_marked_credential_is_not_retried(self) -> None:
        # The point of marking: a permanent, understood condition stops being
        # re-reported on every read, so a new failure is visible.
        credential = FakeCredential(key=ORIGINAL_KEY, lost_at=datetime.now(UTC))
        session = FakeSession([credential])

        audit = _run(session, _keys(REPLACEMENT_KEY))

        assert audit.already_marked == 1
        assert audit.unreadable == 0

    def test_a_readable_credential_is_never_marked_lost(self) -> None:
        credential = FakeCredential(key=REPLACEMENT_KEY)
        session = FakeSession([credential])

        _run(session, _keys(REPLACEMENT_KEY), mark_lost=True)

        assert credential.key_material_lost_at is None


class TestFingerprintBackfill:
    def test_a_readable_credential_gains_the_fingerprint_it_lacked(self) -> None:
        credential = FakeCredential(key=REPLACEMENT_KEY)
        session = FakeSession([credential])

        _run(session, _keys(REPLACEMENT_KEY))

        assert credential.key_fingerprint == key_fingerprint(REPLACEMENT_KEY)

    def test_an_existing_fingerprint_is_left_alone(self) -> None:
        credential = FakeCredential(key=REPLACEMENT_KEY, fingerprint="written-at-encryption")
        session = FakeSession([credential])

        _run(session, _keys(REPLACEMENT_KEY))

        assert credential.key_fingerprint == "written-at-encryption"


def test_a_credential_with_no_encrypted_material_is_not_a_loss() -> None:
    # A WireGuard credential legitimately has none, and counting it as lost
    # would report a problem on a healthy system.
    session = FakeSession([FakeCredential(key=None)])

    audit = _run(session, _keys(REPLACEMENT_KEY))

    assert audit.no_material == 1
    assert audit.unreadable == 0
    assert not audit.has_losses


def test_a_fingerprint_names_the_key_without_revealing_it() -> None:
    printed = key_fingerprint(ORIGINAL_KEY)

    assert printed != key_fingerprint(REPLACEMENT_KEY)
    assert printed == key_fingerprint(ORIGINAL_KEY)
    assert ORIGINAL_KEY.decode() not in printed
    assert len(printed) == 32
