"""Load production authentication keys or create isolated development material."""

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from nebula_api.settings import Settings

_SYMMETRIC_KEY_BYTES = 32
_MAXIMUM_KEY_FILE_BYTES = 16_384


class AuthKeyMaterialError(RuntimeError):
    """Stable startup error that never includes secret data or file contents."""


@dataclass(frozen=True, slots=True, repr=False)
class AuthKeyMaterial:
    """Process-local key rings consumed by authentication codecs and stores."""

    jwt_signer: Ed25519PrivateKey
    verification_keys: dict[str, Ed25519PublicKey]
    token_peppers: dict[int, bytes]
    mfa_encryption_keys: dict[int, bytes]

    def __repr__(self) -> str:
        return "AuthKeyMaterial(<redacted>)"


def load_auth_key_material(settings: Settings) -> AuthKeyMaterial:
    """Load configured keys, allowing ephemeral keys only in development and tests."""

    configured_paths = (
        settings.jwt_private_key_file,
        settings.jwt_public_key_file,
        settings.token_pepper_file,
        settings.mfa_encryption_key_file,
    )
    if all(path is None for path in configured_paths):
        if settings.env not in {"development", "test"}:
            raise AuthKeyMaterialError("authentication key files are required")
        signer = Ed25519PrivateKey.generate()
        return AuthKeyMaterial(
            jwt_signer=signer,
            verification_keys={settings.jwt_key_id: signer.public_key()},
            token_peppers={settings.token_key_version: __import__("secrets").token_bytes(32)},
            mfa_encryption_keys={settings.mfa_key_version: __import__("secrets").token_bytes(32)},
        )
    if any(path is None for path in configured_paths):
        raise AuthKeyMaterialError("all authentication key files must be configured together")

    try:
        private_bytes = _read_bounded(settings.jwt_private_key_file)
        public_bytes = _read_bounded(settings.jwt_public_key_file)
        pepper = _read_symmetric_key(settings.token_pepper_file)
        mfa_key = _read_symmetric_key(settings.mfa_encryption_key_file)
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        public_key = serialization.load_pem_public_key(public_bytes)
    except (OSError, TypeError, ValueError):
        raise AuthKeyMaterialError("authentication key material is invalid") from None
    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(
        public_key, Ed25519PublicKey
    ):
        raise AuthKeyMaterialError("authentication signing keys must be Ed25519")
    derived_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    configured_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if derived_public != configured_public:
        raise AuthKeyMaterialError("authentication signing key pair does not match")
    return AuthKeyMaterial(
        jwt_signer=private_key,
        verification_keys={settings.jwt_key_id: public_key},
        token_peppers={settings.token_key_version: pepper},
        mfa_encryption_keys={settings.mfa_key_version: mfa_key},
    )


def _read_bounded(path: Path | None) -> bytes:
    if path is None:
        raise AuthKeyMaterialError("authentication key file is missing")
    data = path.read_bytes()
    if not data or len(data) > _MAXIMUM_KEY_FILE_BYTES:
        raise AuthKeyMaterialError("authentication key file is invalid")
    return data


def _read_symmetric_key(path: Path | None) -> bytes:
    value = _read_bounded(path)
    if len(value) != _SYMMETRIC_KEY_BYTES:
        raise AuthKeyMaterialError("authentication symmetric key must contain exactly 32 bytes")
    return value
