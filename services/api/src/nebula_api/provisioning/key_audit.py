"""Check that every encrypted credential can still be decrypted.

The failure this exists for is silent by construction. An Xray credential is
encrypted under a key identified only by a version number, so replacing the
key file without changing that number leaves every earlier credential
undecryptable with nothing recording that anything happened. The symptom
arrives much later, as decryption failures nobody can connect to a file
written weeks earlier.

This turns that into something checkable on demand: read every credential,
try it, and report what could not be opened and which key wrote the ones that
could. Reporting by default; it only writes when asked to.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select

from nebula_api.auth.key_material import AuthKeyMaterial
from nebula_api.db.engine import SessionFactory
from nebula_api.models.provisioning import DeviceProtocolCredential, XrayClient
from nebula_api.provisioning.xray_credentials import (
    EncryptedXrayCredential,
    decrypt_xray_credential,
    key_fingerprint,
)


@dataclass(frozen=True, slots=True)
class CredentialKeyAudit:
    readable: int = 0
    unreadable: int = 0
    already_marked: int = 0
    no_material: int = 0
    marked_now: int = 0
    # Which keys actually wrote the credentials that opened, by fingerprint.
    # More than one entry for a single key version is the signature of a key
    # replaced without its version changing.
    fingerprints_by_version: dict[str, set[str]] = field(default_factory=dict)

    @property
    def has_losses(self) -> bool:
        return bool(self.unreadable or self.already_marked)

    @property
    def versions_with_several_keys(self) -> list[str]:
        return sorted(
            version for version, prints in self.fingerprints_by_version.items() if len(prints) > 1
        )


async def audit_credential_keys(
    session_factory: SessionFactory,
    key_material: AuthKeyMaterial,
    *,
    mark_lost: bool = False,
) -> CredentialKeyAudit:
    """Try every Xray credential, and optionally record the hopeless ones.

    `mark_lost` stamps `key_material_lost_at` on credentials that cannot be
    opened with any key currently held. That is a conclusion, not a repair:
    the plaintext is gone either way. Recording it stops a permanent,
    understood condition from being re-reported on every read, which is what
    would otherwise hide the next failure that is genuinely new.
    """

    readable = 0
    unreadable = 0
    already_marked = 0
    no_material = 0
    marked_now = 0
    fingerprints: dict[str, set[str]] = {}

    async with session_factory() as session:
        clients = (await session.scalars(select(XrayClient))).all()
        for client in clients:
            credential = await session.scalar(
                select(DeviceProtocolCredential).where(
                    DeviceProtocolCredential.id == client.credential_id
                )
            )
            if credential is None:
                continue
            if credential.key_material_lost_at is not None:
                already_marked += 1
                continue
            if credential.ciphertext is None or credential.key_version is None:
                # A credential with no encrypted material is not a loss; a
                # WireGuard credential legitimately has none.
                no_material += 1
                continue

            opened_by = _try_every_key(credential, key_material)
            if opened_by is None:
                unreadable += 1
                if mark_lost:
                    credential.key_material_lost_at = datetime.now(UTC)
                    marked_now += 1
                continue

            readable += 1
            fingerprints.setdefault(str(credential.key_version), set()).add(opened_by)
            if credential.key_fingerprint is None:
                # Backfill what the row could not previously record, so a
                # later swap is visible without re-deriving all of this.
                credential.key_fingerprint = opened_by

        if mark_lost or fingerprints:
            await session.commit()

    return CredentialKeyAudit(
        readable=readable,
        unreadable=unreadable,
        already_marked=already_marked,
        no_material=no_material,
        marked_now=marked_now,
        fingerprints_by_version=fingerprints,
    )


def _try_every_key(
    credential: DeviceProtocolCredential, key_material: AuthKeyMaterial
) -> str | None:
    """The fingerprint of the key that opened this, or None if none did.

    Every held key's bytes are tried, not just the one the row names, because
    the row names a *version* and the whole problem is that one version can
    mean more than one key over time.

    The version in the AAD stays the one the row recorded, though. The AAD
    binds the version number, so encrypting under version 1 and trying to
    open it as version 2 fails even with exactly the right key -- searching
    the ring means varying the key material, never the recorded version.
    """

    try:
        recorded_version = int(credential.key_version or "")
    except ValueError:
        return None

    for key in key_material.xray_encryption_keys.values():
        try:
            decrypt_xray_credential(
                EncryptedXrayCredential(
                    key_version=recorded_version,
                    nonce=credential.nonce or b"",
                    ciphertext=credential.ciphertext or b"",
                ),
                device_id=credential.device_id,
                credential_id=credential.id,
                key_ring={recorded_version: key},
            )
        except Exception:  # noqa: S112 - a wrong key is the expected
            # outcome of searching a ring, not an error worth logging once
            # per key per credential.
            continue
        return key_fingerprint(key)
    return None
