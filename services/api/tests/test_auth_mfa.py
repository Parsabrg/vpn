from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest

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

RFC_SECRET = b"12345678901234567890"
NOW = datetime.fromtimestamp(1_234_567_890, UTC)


@pytest.mark.parametrize(
    ("counter", "expected"),
    [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ],
)
def test_hotp_matches_rfc_4226_six_digit_vectors(counter: int, expected: str) -> None:
    assert totp_at_counter(RFC_SECRET, counter) == expected


def test_totp_accepts_configured_window_and_returns_counter_for_replay_state() -> None:
    current = int(NOW.timestamp()) // 30

    for offset in (-1, 0, 1):
        code = totp_at_counter(RFC_SECRET, current + offset)
        assert verify_totp(RFC_SECRET, code, clock=lambda: NOW, skew=1) == current + offset

    assert (
        verify_totp(
            RFC_SECRET,
            totp_at_counter(RFC_SECRET, current + 2),
            clock=lambda: NOW,
            skew=1,
        )
        is None
    )


@pytest.mark.parametrize("code", ["12345", "1234567", " 123456", "+12345", "12.345"])
def test_totp_rejects_noncanonical_codes(code: str) -> None:
    assert verify_totp(RFC_SECRET, code, clock=lambda: NOW) is None


def test_totp_preserves_leading_zero_codes() -> None:
    counter = next(
        value for value in range(100_000) if totp_at_counter(RFC_SECRET, value)[0] == "0"
    )
    code = totp_at_counter(RFC_SECRET, counter)
    instant = datetime.fromtimestamp(counter * 30, UTC)

    assert len(code) == 6 and code.startswith("0")
    assert verify_totp(RFC_SECRET, code, clock=lambda: instant, skew=0) == counter


@pytest.mark.parametrize("counter", [-1, 2**64, True])
def test_hotp_rejects_invalid_counters(counter: int) -> None:
    with pytest.raises(ValueError, match="counter"):
        totp_at_counter(RFC_SECRET, counter)


def test_totp_rejects_invalid_seed_clock_and_skew() -> None:
    with pytest.raises(ValueError, match="seed"):
        totp_at_counter(b"short", 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_totp(RFC_SECRET, "123456", clock=lambda: datetime(2026, 1, 1), skew=0)
    with pytest.raises(ValueError, match="skew"):
        verify_totp(RFC_SECRET, "123456", skew=-1)


def test_seed_generation_requires_exact_random_source_contract() -> None:
    assert generate_mfa_seed(random_bytes=lambda size: b"s" * size) == b"s" * 20
    with pytest.raises(RuntimeError, match="random source"):
        generate_mfa_seed(random_bytes=lambda _size: b"short")


def test_mfa_seed_encryption_is_bound_to_admin_and_credential() -> None:
    admin_id = uuid4()
    credential_id = uuid4()
    keys = {7: b"k" * 32}
    envelope = encrypt_mfa_seed(
        RFC_SECRET,
        admin_id=admin_id,
        credential_id=credential_id,
        key_version=7,
        key_ring=keys,
        random_bytes=lambda size: b"n" * size,
    )

    assert (
        decrypt_mfa_seed(
            envelope,
            admin_id=admin_id,
            credential_id=credential_id,
            key_ring=keys,
        )
        == RFC_SECRET
    )
    assert RFC_SECRET.hex() not in repr(envelope)
    for wrong_admin, wrong_credential in (
        (uuid4(), credential_id),
        (admin_id, uuid4()),
    ):
        with pytest.raises(MfaEncryptionError, match="could not be decrypted"):
            decrypt_mfa_seed(
                envelope,
                admin_id=wrong_admin,
                credential_id=wrong_credential,
                key_ring=keys,
            )


def test_mfa_seed_decryption_rejects_tampering_and_unknown_keys_generically() -> None:
    admin_id = uuid4()
    credential_id = uuid4()
    keys = {1: b"k" * 32}
    envelope = encrypt_mfa_seed(
        RFC_SECRET,
        admin_id=admin_id,
        credential_id=credential_id,
        key_version=1,
        key_ring=keys,
    )
    tampered = EncryptedMfaSeed(
        key_version=1,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
    )

    for candidate, key_ring in ((tampered, keys), (envelope, {2: b"q" * 32})):
        with pytest.raises(MfaEncryptionError, match="could not be decrypted"):
            decrypt_mfa_seed(
                candidate,
                admin_id=admin_id,
                credential_id=credential_id,
                key_ring=key_ring,
            )


def test_mfa_envelope_and_key_validation_rejects_wrong_shapes() -> None:
    with pytest.raises(ValueError, match="envelope"):
        EncryptedMfaSeed(key_version=0, nonce=b"n" * 12, ciphertext=b"x" * 36)
    with pytest.raises(ValueError, match="envelope"):
        EncryptedMfaSeed(key_version=1, nonce=b"short", ciphertext=b"x" * 36)
    with pytest.raises(ValueError, match="envelope"):
        EncryptedMfaSeed(key_version=1, nonce=b"n" * 12, ciphertext=b"short")
    with pytest.raises(ValueError, match="key ring"):
        encrypt_mfa_seed(
            RFC_SECRET,
            admin_id=uuid4(),
            credential_id=uuid4(),
            key_version=1,
            key_ring={1: b"short"},
        )
    with pytest.raises(RuntimeError, match="nonce"):
        encrypt_mfa_seed(
            RFC_SECRET,
            admin_id=uuid4(),
            credential_id=uuid4(),
            key_version=1,
            key_ring={1: b"k" * 32},
            random_bytes=lambda _size: b"short",
        )


def test_recovery_codes_are_independent_single_retrieval_values() -> None:
    counter = 0

    def deterministic_random(size: int) -> bytes:
        nonlocal counter
        counter += 1
        return counter.to_bytes(size, "big")

    keys = {3: b"p" * 32}
    batch = generate_recovery_codes(
        keys,
        key_version=3,
        count=4,
        random_bytes=deterministic_random,
    )
    codes = batch.take_plaintext_codes()

    assert len(set(codes)) == batch.count == 4
    assert "v3." not in repr(batch)
    assert all(
        verify_recovery_code(code, digest, keys)
        for code, digest in zip(codes, batch.digests, strict=True)
    )
    assert not verify_recovery_code(codes[0], batch.digests[1], keys)
    with pytest.raises(RuntimeError, match="already been retrieved"):
        batch.take_plaintext_codes()


def test_recovery_code_generation_rejects_policy_and_broken_randomness() -> None:
    with pytest.raises(ValueError, match="count"):
        generate_recovery_codes({1: b"k" * 32}, count=0)
    with pytest.raises(RuntimeError, match="repeated"):
        generate_recovery_codes(
            {1: b"k" * 32},
            count=2,
            random_bytes=lambda size: b"x" * size,
        )


def test_recovery_batch_and_negative_totp_time_are_rejected() -> None:
    with pytest.raises(ValueError, match="batch is invalid"):
        RecoveryCodeBatch(plaintext_codes=(), digests=())
    with pytest.raises(ValueError, match="TOTP time is invalid"):
        verify_totp(
            RFC_SECRET,
            "123456",
            clock=lambda: datetime(1969, 12, 31, 23, 59, 59, tzinfo=UTC),
            skew=0,
        )


def test_mfa_encryption_rejects_invalid_context_versions_and_key_rings() -> None:
    credential_id = uuid4()
    with pytest.raises(ValueError, match="administrator context"):
        encrypt_mfa_seed(
            RFC_SECRET,
            admin_id=cast(UUID, "invalid"),
            credential_id=credential_id,
            key_version=1,
            key_ring={1: b"k" * 32},
        )
    with pytest.raises(ValueError, match="key version"):
        encrypt_mfa_seed(
            RFC_SECRET,
            admin_id=uuid4(),
            credential_id=credential_id,
            key_version=0,
            key_ring={},
        )
    with pytest.raises(ValueError, match="key ring"):
        encrypt_mfa_seed(
            RFC_SECRET,
            admin_id=uuid4(),
            credential_id=credential_id,
            key_version=1,
            key_ring={},
        )


def test_mfa_decryption_rejects_invalid_envelope_and_invalid_key_value() -> None:
    admin_id = uuid4()
    credential_id = uuid4()
    envelope = encrypt_mfa_seed(
        RFC_SECRET,
        admin_id=admin_id,
        credential_id=credential_id,
        key_version=1,
        key_ring={1: b"k" * 32},
    )

    with pytest.raises(MfaEncryptionError, match="could not be decrypted"):
        decrypt_mfa_seed(
            cast(EncryptedMfaSeed, object()),
            admin_id=admin_id,
            credential_id=credential_id,
            key_ring={1: b"k" * 32},
        )
    with pytest.raises(MfaEncryptionError, match="could not be decrypted"):
        decrypt_mfa_seed(
            envelope,
            admin_id=admin_id,
            credential_id=credential_id,
            key_ring={1: b"short"},
        )
