from typing import cast
from uuid import UUID, uuid4

import pytest

from nebula_api.provisioning.xray_credentials import (
    EncryptedXrayCredential,
    XrayCredentialEncryptionError,
    decrypt_xray_credential,
    encrypt_xray_credential,
)

CLIENT_UUID = UUID("12345678-1234-5678-1234-567812345678")


def test_xray_credential_encryption_is_bound_to_device_and_credential() -> None:
    device_id = uuid4()
    credential_id = uuid4()
    keys = {7: b"k" * 32}
    envelope = encrypt_xray_credential(
        CLIENT_UUID,
        device_id=device_id,
        credential_id=credential_id,
        key_version=7,
        key_ring=keys,
        random_bytes=lambda size: b"n" * size,
    )

    assert (
        decrypt_xray_credential(
            envelope,
            device_id=device_id,
            credential_id=credential_id,
            key_ring=keys,
        )
        == CLIENT_UUID
    )
    assert CLIENT_UUID.hex not in repr(envelope)
    for wrong_device, wrong_credential in (
        (uuid4(), credential_id),
        (device_id, uuid4()),
    ):
        with pytest.raises(XrayCredentialEncryptionError, match="could not be decrypted"):
            decrypt_xray_credential(
                envelope,
                device_id=wrong_device,
                credential_id=wrong_credential,
                key_ring=keys,
            )


def test_xray_credential_decryption_rejects_tampering_and_unknown_keys_generically() -> None:
    device_id = uuid4()
    credential_id = uuid4()
    keys = {1: b"k" * 32}
    envelope = encrypt_xray_credential(
        CLIENT_UUID,
        device_id=device_id,
        credential_id=credential_id,
        key_version=1,
        key_ring=keys,
    )
    tampered = EncryptedXrayCredential(
        key_version=1,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
    )

    for candidate, key_ring in ((tampered, keys), (envelope, {2: b"q" * 32})):
        with pytest.raises(XrayCredentialEncryptionError, match="could not be decrypted"):
            decrypt_xray_credential(
                candidate,
                device_id=device_id,
                credential_id=credential_id,
                key_ring=key_ring,
            )


def test_xray_credential_key_rotation_keeps_the_old_key_decryptable() -> None:
    device_id = uuid4()
    credential_id = uuid4()
    old_key = b"o" * 32
    new_key = b"n" * 32
    envelope = encrypt_xray_credential(
        CLIENT_UUID,
        device_id=device_id,
        credential_id=credential_id,
        key_version=1,
        key_ring={1: old_key},
    )
    ring_after_rotation = {1: old_key, 2: new_key}

    assert (
        decrypt_xray_credential(
            envelope,
            device_id=device_id,
            credential_id=credential_id,
            key_ring=ring_after_rotation,
        )
        == CLIENT_UUID
    )

    new_envelope = encrypt_xray_credential(
        uuid4(),
        device_id=device_id,
        credential_id=credential_id,
        key_version=2,
        key_ring=ring_after_rotation,
    )
    assert new_envelope.key_version == 2


def test_xray_envelope_and_key_validation_rejects_wrong_shapes() -> None:
    with pytest.raises(ValueError, match="envelope"):
        EncryptedXrayCredential(key_version=0, nonce=b"n" * 12, ciphertext=b"x" * 32)
    with pytest.raises(ValueError, match="envelope"):
        EncryptedXrayCredential(key_version=1, nonce=b"short", ciphertext=b"x" * 32)
    with pytest.raises(ValueError, match="envelope"):
        EncryptedXrayCredential(key_version=1, nonce=b"n" * 12, ciphertext=b"short")
    with pytest.raises(ValueError, match="key ring"):
        encrypt_xray_credential(
            CLIENT_UUID,
            device_id=uuid4(),
            credential_id=uuid4(),
            key_version=1,
            key_ring={1: b"short"},
        )
    with pytest.raises(RuntimeError, match="nonce"):
        encrypt_xray_credential(
            CLIENT_UUID,
            device_id=uuid4(),
            credential_id=uuid4(),
            key_version=1,
            key_ring={1: b"k" * 32},
            random_bytes=lambda _size: b"short",
        )


def test_xray_credential_encryption_rejects_invalid_context_versions_and_key_rings() -> None:
    credential_id = uuid4()
    with pytest.raises(ValueError, match="client UUID"):
        encrypt_xray_credential(
            cast(UUID, "invalid"),
            device_id=uuid4(),
            credential_id=credential_id,
            key_version=1,
            key_ring={1: b"k" * 32},
        )
    with pytest.raises(ValueError, match="credential context"):
        encrypt_xray_credential(
            CLIENT_UUID,
            device_id=cast(UUID, "invalid"),
            credential_id=credential_id,
            key_version=1,
            key_ring={1: b"k" * 32},
        )
    with pytest.raises(ValueError, match="key version"):
        encrypt_xray_credential(
            CLIENT_UUID,
            device_id=uuid4(),
            credential_id=credential_id,
            key_version=0,
            key_ring={},
        )
    with pytest.raises(ValueError, match="key ring"):
        encrypt_xray_credential(
            CLIENT_UUID,
            device_id=uuid4(),
            credential_id=credential_id,
            key_version=1,
            key_ring={},
        )


def test_xray_credential_decryption_rejects_invalid_envelope_and_invalid_key_value() -> None:
    device_id = uuid4()
    credential_id = uuid4()
    envelope = encrypt_xray_credential(
        CLIENT_UUID,
        device_id=device_id,
        credential_id=credential_id,
        key_version=1,
        key_ring={1: b"k" * 32},
    )

    with pytest.raises(XrayCredentialEncryptionError, match="could not be decrypted"):
        decrypt_xray_credential(
            cast(EncryptedXrayCredential, object()),
            device_id=device_id,
            credential_id=credential_id,
            key_ring={1: b"k" * 32},
        )
    with pytest.raises(XrayCredentialEncryptionError, match="could not be decrypted"):
        decrypt_xray_credential(
            envelope,
            device_id=device_id,
            credential_id=credential_id,
            key_ring={1: b"short"},
        )
    with pytest.raises(XrayCredentialEncryptionError, match="could not be decrypted"):
        decrypt_xray_credential(
            envelope,
            device_id=cast(UUID, "invalid"),
            credential_id=credential_id,
            key_ring={1: b"k" * 32},
        )
