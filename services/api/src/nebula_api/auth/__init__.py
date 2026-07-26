"""Secret-safe authentication cryptographic primitives."""

from nebula_api.auth.access_tokens import (
    AccessTokenClaims,
    AccessTokenError,
    decode_access_token,
    issue_access_token,
)
from nebula_api.auth.mfa import (
    EncryptedMfaSeed,
    MfaEncryptionError,
    RecoveryCodeBatch,
    decrypt_mfa_seed,
    encrypt_mfa_seed,
    generate_mfa_seed,
    generate_recovery_codes,
    totp_at_counter,
    verify_recovery_code,
    verify_totp,
)
from nebula_api.auth.opaque_tokens import (
    OpaqueTokenDigest,
    OpaqueTokenError,
    digest_opaque_token,
    issue_opaque_token,
    verify_opaque_token,
)

__all__ = [
    "AccessTokenClaims",
    "AccessTokenError",
    "EncryptedMfaSeed",
    "MfaEncryptionError",
    "OpaqueTokenDigest",
    "OpaqueTokenError",
    "RecoveryCodeBatch",
    "decode_access_token",
    "decrypt_mfa_seed",
    "digest_opaque_token",
    "encrypt_mfa_seed",
    "generate_mfa_seed",
    "generate_recovery_codes",
    "issue_access_token",
    "issue_opaque_token",
    "totp_at_counter",
    "verify_opaque_token",
    "verify_recovery_code",
    "verify_totp",
]
