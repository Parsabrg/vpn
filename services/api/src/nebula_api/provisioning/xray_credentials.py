"""Envelope encryption for Xray VLESS client credentials.

Mirrors auth/mfa.py's EncryptedMfaSeed/encrypt_mfa_seed/decrypt_mfa_seed
exactly, with two differences: the plaintext is a 16-byte VLESS client UUID
rather than a TOTP seed, and the AAD binds to (device_id, credential_id,
key_version) instead of (admin_id, credential_id, key_version) -- this
provisions a per-device VPN client credential, not an admin MFA seed. The
XHTTP path is intentionally not part of this envelope: it is a single value
shared by the whole server inbound, not a per-client secret.
"""

import hashlib
import secrets
from collections.abc import Mapping
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nebula_api.auth.opaque_tokens import RandomBytes

XRAY_CLIENT_UUID_BYTES = 16
XRAY_NONCE_BYTES = 12
XRAY_ENCRYPTION_KEY_BYTES = 32
_AES_GCM_TAG_BYTES = 16
_XRAY_AAD_PREFIX = b"nebula:xray-client-credential:v1\x00"
_MAXIMUM_KEY_VERSION = 2_147_483_647

XrayEncryptionKeyRing = Mapping[int, bytes]


_KEY_FINGERPRINT_PREFIX = b"nebula:xray-encryption-key-fingerprint:v1:"
KEY_FINGERPRINT_LENGTH = 32


def key_fingerprint(key: bytes) -> str:
    """A short, non-secret name for a key, safe to store and to log.

    Exists because a key can be replaced without its version changing, and
    nothing about the ciphertext records which key wrote it. That happened
    here: the key was regenerated seventeen minutes after the first
    credentials were written, reusing version 1, and the only evidence was
    credentials that silently stopped decrypting. Storing this alongside each
    credential makes the swap something the system can state rather than
    something an operator has to deduce from file timestamps.

    A SHA-256 digest of a 32-byte random key, domain-separated and truncated.
    Preimage resistance is what makes it safe to keep in a database column
    and print in a report; the truncation keeps it readable, and 128 bits is
    far more than enough to tell two keys apart.
    """

    digest = hashlib.sha256(_KEY_FINGERPRINT_PREFIX + key).hexdigest()
    return digest[:KEY_FINGERPRINT_LENGTH]


class XrayCredentialEncryptionError(ValueError):
    """Raised without distinguishing missing keys, bad context, or tampering."""


class EncryptedXrayCredential:
    """Versioned AES-GCM envelope whose representation never includes ciphertext."""

    __slots__ = ("ciphertext", "key_version", "nonce")

    def __init__(self, *, key_version: int, nonce: bytes, ciphertext: bytes) -> None:
        if not _valid_key_version(key_version):
            raise ValueError("Xray credential envelope is invalid")
        if type(nonce) is not bytes or len(nonce) != XRAY_NONCE_BYTES:
            raise ValueError("Xray credential envelope is invalid")
        if (
            type(ciphertext) is not bytes
            or len(ciphertext) < XRAY_CLIENT_UUID_BYTES + _AES_GCM_TAG_BYTES
        ):
            raise ValueError("Xray credential envelope is invalid")
        self.key_version = key_version
        self.nonce = nonce
        self.ciphertext = ciphertext

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_version={self.key_version}, "
            "nonce=<redacted>, ciphertext=<redacted>)"
        )


def encrypt_xray_credential(
    client_uuid: UUID,
    *,
    device_id: UUID,
    credential_id: UUID,
    key_version: int,
    key_ring: XrayEncryptionKeyRing,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> EncryptedXrayCredential:
    """Encrypt a VLESS client UUID with AES-256-GCM bound to its device and key version."""

    _validate_client_uuid(client_uuid)
    key = _xray_encryption_key(key_ring, key_version, decrypting=False)
    _validate_context_id(device_id)
    _validate_context_id(credential_id)
    nonce = random_bytes(XRAY_NONCE_BYTES)
    if type(nonce) is not bytes or len(nonce) != XRAY_NONCE_BYTES:
        raise RuntimeError("Xray credential nonce random source returned invalid data")
    ciphertext = AESGCM(key).encrypt(
        nonce,
        client_uuid.bytes,
        _xray_aad(device_id, credential_id, key_version),
    )
    return EncryptedXrayCredential(key_version=key_version, nonce=nonce, ciphertext=ciphertext)


def decrypt_xray_credential(
    envelope: EncryptedXrayCredential,
    *,
    device_id: UUID,
    credential_id: UUID,
    key_ring: XrayEncryptionKeyRing,
) -> UUID:
    """Decrypt a VLESS client UUID, returning the same generic error for every rejection."""

    try:
        if not isinstance(envelope, EncryptedXrayCredential):
            raise XrayCredentialEncryptionError("Xray credential could not be decrypted")
        _validate_context_id(device_id)
        _validate_context_id(credential_id)
        key = _xray_encryption_key(key_ring, envelope.key_version, decrypting=True)
        plaintext = AESGCM(key).decrypt(
            envelope.nonce,
            envelope.ciphertext,
            _xray_aad(device_id, credential_id, envelope.key_version),
        )
        if type(plaintext) is not bytes or len(plaintext) != XRAY_CLIENT_UUID_BYTES:
            raise XrayCredentialEncryptionError("Xray credential could not be decrypted")
        return UUID(bytes=plaintext)
    except XrayCredentialEncryptionError:
        raise
    except (InvalidTag, TypeError, ValueError):
        raise XrayCredentialEncryptionError("Xray credential could not be decrypted") from None


def _validate_client_uuid(client_uuid: UUID) -> None:
    if not isinstance(client_uuid, UUID):
        raise ValueError("Xray client UUID is invalid")


def _validate_context_id(value: UUID) -> None:
    if not isinstance(value, UUID):
        raise ValueError("Xray credential context is invalid")


def _xray_encryption_key(
    key_ring: XrayEncryptionKeyRing,
    key_version: int,
    *,
    decrypting: bool,
) -> bytes:
    if not _valid_key_version(key_version):
        if decrypting:
            raise XrayCredentialEncryptionError("Xray credential could not be decrypted")
        raise ValueError("Xray encryption key version is invalid")
    try:
        key = key_ring[key_version]
    except (KeyError, TypeError):
        if decrypting:
            raise XrayCredentialEncryptionError("Xray credential could not be decrypted") from None
        raise ValueError("Xray encryption key ring is invalid") from None
    if type(key) is not bytes or len(key) != XRAY_ENCRYPTION_KEY_BYTES:
        if decrypting:
            raise XrayCredentialEncryptionError("Xray credential could not be decrypted")
        raise ValueError("Xray encryption key ring is invalid")
    return key


def _xray_aad(device_id: UUID, credential_id: UUID, key_version: int) -> bytes:
    return _XRAY_AAD_PREFIX + key_version.to_bytes(4, "big") + device_id.bytes + credential_id.bytes


def _valid_key_version(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAXIMUM_KEY_VERSION
