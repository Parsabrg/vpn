"""Load production authentication keys or create isolated development material."""

import re
import secrets
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
# Matches Settings.jwt_key_id's pattern exactly -- a retired key's filename is its kid.
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
# Matches Settings.token_key_version/mfa_key_version's upper bound exactly.
_MAXIMUM_KEY_VERSION = 2_147_483_647


class AuthKeyMaterialError(RuntimeError):
    """Stable startup error that never includes secret data or file contents."""


@dataclass(frozen=True, slots=True, repr=False)
class AuthKeyMaterial:
    """Process-local key rings consumed by authentication codecs and stores."""

    jwt_signer: Ed25519PrivateKey
    verification_keys: dict[str, Ed25519PublicKey]
    token_peppers: dict[int, bytes]
    mfa_encryption_keys: dict[int, bytes]
    xray_encryption_keys: dict[int, bytes]

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
            token_peppers={settings.token_key_version: secrets.token_bytes(32)},
            mfa_encryption_keys={settings.mfa_key_version: secrets.token_bytes(32)},
            xray_encryption_keys=_load_xray_encryption_keys(settings),
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
        previous_verification_keys = _load_previous_verification_keys(
            settings.jwt_previous_public_keys_dir, current_key_id=settings.jwt_key_id
        )
        previous_peppers = _load_previous_symmetric_ring(
            settings.token_previous_peppers_dir, current_version=settings.token_key_version
        )
        previous_mfa_keys = _load_previous_symmetric_ring(
            settings.mfa_previous_encryption_keys_dir, current_version=settings.mfa_key_version
        )
        xray_encryption_keys = _load_xray_encryption_keys(settings)
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
        verification_keys={**previous_verification_keys, settings.jwt_key_id: public_key},
        token_peppers={**previous_peppers, settings.token_key_version: pepper},
        mfa_encryption_keys={**previous_mfa_keys, settings.mfa_key_version: mfa_key},
        xray_encryption_keys=xray_encryption_keys,
    )


def _load_xray_encryption_keys(settings: Settings) -> dict[int, bytes]:
    """Configured independently of the JWT/token/MFA bundle above, so that a
    deployment predating Xray support still starts without it.

    The ephemeral fallback below is a development convenience and nothing more.
    Xray credentials are now genuinely encrypted with this key
    (provisioning/service.py), and an ephemeral one does not survive a restart:
    every active client would afterwards be unable to reconnect *and* unable to
    be revoked (both paths decrypt first and reject on failure), stranding rows
    that still hold capacity. Several workers would each mint a different key
    and fail against each other's rows. Settings.validate_runtime_boundaries
    therefore requires the file outright in production -- this fallback should
    only ever be reachable in development and tests.
    """

    if settings.xray_encryption_key_file is None:
        return {settings.xray_key_version: secrets.token_bytes(32)}
    xray_key = _read_symmetric_key(settings.xray_encryption_key_file)
    previous_xray_keys = _load_previous_symmetric_ring(
        settings.xray_previous_encryption_keys_dir, current_version=settings.xray_key_version
    )
    return {**previous_xray_keys, settings.xray_key_version: xray_key}


def _load_previous_verification_keys(
    directory: Path | None, *, current_key_id: str
) -> dict[str, Ed25519PublicKey]:
    """Retired JWT verification keys, one PEM file per key, filename == its old `kid`."""

    keys: dict[str, Ed25519PublicKey] = {}
    for entry in _listed_previous_key_files(directory):
        key_id = entry.name
        if not _KEY_ID_PATTERN.fullmatch(key_id) or key_id == current_key_id or key_id in keys:
            raise AuthKeyMaterialError("authentication key material is invalid")
        public_key = serialization.load_pem_public_key(_read_bounded(entry))
        if not isinstance(public_key, Ed25519PublicKey):
            raise AuthKeyMaterialError("authentication signing keys must be Ed25519")
        keys[key_id] = public_key
    return keys


def _load_previous_symmetric_ring(
    directory: Path | None, *, current_version: int
) -> dict[int, bytes]:
    """Retired token peppers or MFA keys, one 32-byte file per key, filename == its old version."""

    ring: dict[int, bytes] = {}
    for entry in _listed_previous_key_files(directory):
        version = _parse_key_version(entry.name)
        if version is None or version == current_version or version in ring:
            raise AuthKeyMaterialError("authentication key material is invalid")
        ring[version] = _read_symmetric_key(entry)
    return ring


def _listed_previous_key_files(directory: Path | None) -> list[Path]:
    if directory is None:
        return []
    if not directory.is_dir():
        raise AuthKeyMaterialError("authentication key material is invalid")
    entries = sorted(directory.iterdir())
    for entry in entries:
        if not entry.is_file():
            raise AuthKeyMaterialError("authentication key material is invalid")
    return entries


def _parse_key_version(name: str) -> int | None:
    if not name.isdecimal():
        return None
    value = int(name)
    return value if 1 <= value <= _MAXIMUM_KEY_VERSION else None


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
