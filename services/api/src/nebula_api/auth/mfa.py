"""TOTP, encrypted MFA seeds, and one-time recovery-code primitives."""

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nebula_api.auth.opaque_tokens import (
    KeyRing,
    OpaqueTokenDigest,
    RandomBytes,
    digest_opaque_token,
    issue_opaque_token,
    verify_opaque_token,
)

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
MFA_SEED_BYTES = 20
MFA_NONCE_BYTES = 12
MFA_ENCRYPTION_KEY_BYTES = 32
DEFAULT_RECOVERY_CODE_COUNT = 10
_AES_GCM_TAG_BYTES = 16
_MAXIMUM_MFA_SEED_BYTES = 64
_MAXIMUM_RECOVERY_CODE_COUNT = 20
_TOTP_PATTERN = re.compile(r"[0-9]{6}\Z")
_MFA_AAD_PREFIX = b"nebula:admin-mfa-seed:v1\x00"
_RECOVERY_CODE_NAMESPACE = "mfa-recovery"

Clock = Callable[[], datetime]
MfaEncryptionKeyRing = Mapping[int, bytes]


class MfaEncryptionError(ValueError):
    """Raised without distinguishing missing keys, bad context, or tampering."""


class EncryptedMfaSeed:
    """Versioned AES-GCM envelope whose representation never includes ciphertext."""

    __slots__ = ("ciphertext", "key_version", "nonce")

    def __init__(self, *, key_version: int, nonce: bytes, ciphertext: bytes) -> None:
        if not _valid_key_version(key_version):
            raise ValueError("MFA seed envelope is invalid")
        if type(nonce) is not bytes or len(nonce) != MFA_NONCE_BYTES:
            raise ValueError("MFA seed envelope is invalid")
        if type(ciphertext) is not bytes or len(ciphertext) < MFA_SEED_BYTES + _AES_GCM_TAG_BYTES:
            raise ValueError("MFA seed envelope is invalid")
        self.key_version = key_version
        self.nonce = nonce
        self.ciphertext = ciphertext

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_version={self.key_version}, "
            "nonce=<redacted>, ciphertext=<redacted>)"
        )


class RecoveryCodeBatch:
    """Generated recovery digests with plaintext codes retrievable exactly once."""

    __slots__ = ("_digests", "_plaintext_codes")

    def __init__(
        self,
        *,
        plaintext_codes: tuple[str, ...],
        digests: tuple[OpaqueTokenDigest, ...],
    ) -> None:
        if not plaintext_codes or len(plaintext_codes) != len(digests):
            raise ValueError("recovery code batch is invalid")
        self._plaintext_codes: tuple[str, ...] | None = plaintext_codes
        self._digests = digests

    @property
    def digests(self) -> tuple[OpaqueTokenDigest, ...]:
        """Return only the persistence-safe keyed digests."""

        return self._digests

    @property
    def count(self) -> int:
        return len(self._digests)

    def take_plaintext_codes(self) -> tuple[str, ...]:
        """Return generated codes once, then erase this object's references to them."""

        if self._plaintext_codes is None:
            raise RuntimeError("recovery codes have already been retrieved")
        plaintext_codes = self._plaintext_codes
        self._plaintext_codes = None
        return plaintext_codes

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(count={self.count}, "
            "plaintext_codes=<redacted>, digests=<redacted>)"
        )


def generate_mfa_seed(*, random_bytes: RandomBytes = secrets.token_bytes) -> bytes:
    """Generate the RFC 4226-recommended 160-bit shared secret."""

    seed = random_bytes(MFA_SEED_BYTES)
    if type(seed) is not bytes or len(seed) != MFA_SEED_BYTES:
        raise RuntimeError("MFA seed random source returned invalid data")
    return seed


def totp_at_counter(seed: bytes, counter: int) -> str:
    """Calculate a six-digit HMAC-SHA1 HOTP value for one TOTP counter."""

    _validate_mfa_seed(seed)
    if type(counter) is not int or not 0 <= counter < 2**64:
        raise ValueError("TOTP counter is invalid")
    digest = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFF_FFFF
    return f"{binary % (10**TOTP_DIGITS):0{TOTP_DIGITS}d}"


def verify_totp(
    seed: bytes,
    code: str,
    *,
    clock: Clock = lambda: datetime.now(UTC),
    skew: int = 1,
) -> int | None:
    """Return the accepted counter so a service can durably reject replay."""

    _validate_mfa_seed(seed)
    if type(skew) is not int or not 0 <= skew <= 10:
        raise ValueError("TOTP skew is invalid")
    if type(code) is not str or _TOTP_PATTERN.fullmatch(code) is None:
        return None

    current_counter = _totp_counter(clock())
    minimum_counter = max(0, current_counter - skew)
    maximum_counter = current_counter + skew
    # Prefer the greatest matching counter so persisted replay state moves forward.
    for counter in range(maximum_counter, minimum_counter - 1, -1):
        if hmac.compare_digest(totp_at_counter(seed, counter), code):
            return counter
    return None


def encrypt_mfa_seed(
    seed: bytes,
    *,
    admin_id: UUID,
    credential_id: UUID,
    key_version: int,
    key_ring: MfaEncryptionKeyRing,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> EncryptedMfaSeed:
    """Encrypt a seed with AES-256-GCM bound to its administrator and key version."""

    _validate_mfa_seed(seed)
    key = _mfa_encryption_key(key_ring, key_version, decrypting=False)
    _validate_admin_id(admin_id)
    _validate_admin_id(credential_id)
    nonce = random_bytes(MFA_NONCE_BYTES)
    if type(nonce) is not bytes or len(nonce) != MFA_NONCE_BYTES:
        raise RuntimeError("MFA nonce random source returned invalid data")
    ciphertext = AESGCM(key).encrypt(
        nonce,
        seed,
        _mfa_aad(admin_id, credential_id, key_version),
    )
    return EncryptedMfaSeed(key_version=key_version, nonce=nonce, ciphertext=ciphertext)


def decrypt_mfa_seed(
    envelope: EncryptedMfaSeed,
    *,
    admin_id: UUID,
    credential_id: UUID,
    key_ring: MfaEncryptionKeyRing,
) -> bytes:
    """Decrypt an MFA seed, returning the same generic error for every rejection."""

    try:
        if not isinstance(envelope, EncryptedMfaSeed):
            raise MfaEncryptionError("MFA seed could not be decrypted")
        _validate_admin_id(admin_id)
        _validate_admin_id(credential_id)
        key = _mfa_encryption_key(key_ring, envelope.key_version, decrypting=True)
        seed = AESGCM(key).decrypt(
            envelope.nonce,
            envelope.ciphertext,
            _mfa_aad(admin_id, credential_id, envelope.key_version),
        )
        _validate_mfa_seed(seed)
        return seed
    except MfaEncryptionError:
        raise
    except (InvalidTag, TypeError, ValueError):
        raise MfaEncryptionError("MFA seed could not be decrypted") from None


def generate_recovery_codes(
    key_ring: KeyRing,
    *,
    key_version: int = 1,
    count: int = DEFAULT_RECOVERY_CODE_COUNT,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> RecoveryCodeBatch:
    """Generate independently random recovery codes and retain only keyed digests."""

    if type(count) is not int or not 1 <= count <= _MAXIMUM_RECOVERY_CODE_COUNT:
        raise ValueError("recovery code count is invalid")

    codes: list[str] = []
    digests: list[OpaqueTokenDigest] = []
    seen: set[str] = set()
    maximum_attempts = count * 10
    for _ in range(maximum_attempts):
        code = issue_opaque_token(key_version, random_bytes=random_bytes)
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
        digests.append(digest_opaque_token(code, key_ring, namespace=_RECOVERY_CODE_NAMESPACE))
        if len(codes) == count:
            return RecoveryCodeBatch(
                plaintext_codes=tuple(codes),
                digests=tuple(digests),
            )
    raise RuntimeError("recovery code random source produced repeated data")


def verify_recovery_code(
    code: str,
    expected: OpaqueTokenDigest,
    key_ring: KeyRing,
) -> bool:
    """Verify a recovery code with the MFA-specific digest namespace."""

    return verify_opaque_token(
        code,
        expected,
        key_ring,
        namespace=_RECOVERY_CODE_NAMESPACE,
    )


def _totp_counter(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authentication clock must return a timezone-aware datetime")
    timestamp = int(value.astimezone(UTC).timestamp())
    if timestamp < 0:
        raise ValueError("TOTP time is invalid")
    return timestamp // TOTP_PERIOD_SECONDS


def _validate_mfa_seed(seed: bytes) -> None:
    if type(seed) is not bytes or not MFA_SEED_BYTES <= len(seed) <= _MAXIMUM_MFA_SEED_BYTES:
        raise ValueError("MFA seed is invalid")


def _validate_admin_id(admin_id: UUID) -> None:
    if not isinstance(admin_id, UUID):
        raise ValueError("MFA administrator context is invalid")


def _mfa_encryption_key(
    key_ring: MfaEncryptionKeyRing,
    key_version: int,
    *,
    decrypting: bool,
) -> bytes:
    if not _valid_key_version(key_version):
        if decrypting:
            raise MfaEncryptionError("MFA seed could not be decrypted")
        raise ValueError("MFA encryption key version is invalid")
    try:
        key = key_ring[key_version]
    except (KeyError, TypeError):
        if decrypting:
            raise MfaEncryptionError("MFA seed could not be decrypted") from None
        raise ValueError("MFA encryption key ring is invalid") from None
    if type(key) is not bytes or len(key) != MFA_ENCRYPTION_KEY_BYTES:
        if decrypting:
            raise MfaEncryptionError("MFA seed could not be decrypted")
        raise ValueError("MFA encryption key ring is invalid")
    return key


def _mfa_aad(admin_id: UUID, credential_id: UUID, key_version: int) -> bytes:
    return _MFA_AAD_PREFIX + key_version.to_bytes(4, "big") + admin_id.bytes + credential_id.bytes


def _valid_key_version(value: object) -> bool:
    return type(value) is int and 1 <= value <= 2_147_483_647
