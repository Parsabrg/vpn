from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nebula_api.auth.key_material import (
    AuthKeyMaterialError,
    _read_bounded,
    load_auth_key_material,
)
from nebula_api.auth.mfa import decrypt_mfa_seed, encrypt_mfa_seed
from nebula_api.provisioning.xray_credentials import (
    decrypt_xray_credential,
    encrypt_xray_credential,
)
from nebula_api.settings import Settings

_RAW = serialization.Encoding.Raw
_RAW_PUBLIC = serialization.PublicFormat.Raw


def _public_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_key_files(directory: Path) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / "jwt-private.pem"
    public_path = directory / "jwt-public.pem"
    pepper_path = directory / "token-pepper"
    mfa_path = directory / "mfa-key"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    pepper_path.write_bytes(b"p" * 32)
    mfa_path.write_bytes(b"m" * 32)
    return {
        "jwt_private_key_file": private_path,
        "jwt_public_key_file": public_path,
        "token_pepper_file": pepper_path,
        "mfa_encryption_key_file": mfa_path,
    }


def test_development_ephemeral_keys_are_complete_and_redacted() -> None:
    material = load_auth_key_material(Settings(env="test"))

    assert set(material.verification_keys) == {"v1"}
    assert len(material.token_peppers[1]) == 32
    assert len(material.mfa_encryption_keys[1]) == 32
    assert len(material.xray_encryption_keys[1]) == 32
    assert repr(material) == "AuthKeyMaterial(<redacted>)"


def test_configured_key_pair_and_symmetric_keys_load(tmp_path: Path) -> None:
    material = load_auth_key_material(Settings(env="test", **write_key_files(tmp_path)))

    assert set(material.verification_keys) == {"v1"}
    assert material.token_peppers == {1: b"p" * 32}
    assert material.mfa_encryption_keys == {1: b"m" * 32}


def test_xray_key_is_ephemeral_when_unset_even_with_the_core_bundle_configured(
    tmp_path: Path,
) -> None:
    """Xray key material is configured independently of the JWT/token/MFA
    bundle -- an unset xray key file never blocks loading the rest."""

    material = load_auth_key_material(Settings(env="test", **write_key_files(tmp_path)))

    assert len(material.xray_encryption_keys[1]) == 32


def test_xray_key_loads_from_a_configured_file(tmp_path: Path) -> None:
    xray_key_path = tmp_path / "xray-key"
    xray_key_path.write_bytes(b"z" * 32)

    material = load_auth_key_material(
        Settings(
            env="test",
            xray_encryption_key_file=xray_key_path,
            **write_key_files(tmp_path),
        )
    )

    assert material.xray_encryption_keys == {1: b"z" * 32}


def test_previous_xray_key_still_decrypts_an_envelope_it_encrypted(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-xray"
    previous_dir.mkdir()
    retired_key = b"o" * 32
    (previous_dir / "1").write_bytes(retired_key)
    xray_key_path = tmp_path / "xray-key"
    xray_key_path.write_bytes(b"n" * 32)
    device_id, credential_id = uuid4(), uuid4()
    client_uuid = uuid4()
    envelope = encrypt_xray_credential(
        client_uuid,
        device_id=device_id,
        credential_id=credential_id,
        key_version=1,
        key_ring={1: retired_key},
    )

    material = load_auth_key_material(
        Settings(
            env="test",
            xray_encryption_key_file=xray_key_path,
            xray_previous_encryption_keys_dir=previous_dir,
            xray_key_version=2,
            **write_key_files(tmp_path),
        )
    )

    assert (
        decrypt_xray_credential(
            envelope,
            device_id=device_id,
            credential_id=credential_id,
            key_ring=material.xray_encryption_keys,
        )
        == client_uuid
    )


def test_partial_configuration_fails_without_exposing_path(tmp_path: Path) -> None:
    canary_path = tmp_path / "canary-secret-path"

    with pytest.raises(AuthKeyMaterialError) as error:
        load_auth_key_material(Settings(env="test", token_pepper_file=canary_path))

    assert str(canary_path) not in str(error.value)


def test_wrong_symmetric_key_length_fails_generically(tmp_path: Path) -> None:
    paths = write_key_files(tmp_path)
    paths["token_pepper_file"].write_bytes(b"canary-too-short")

    with pytest.raises(AuthKeyMaterialError, match="exactly 32 bytes"):
        load_auth_key_material(Settings(env="test", **paths))


def test_non_development_environment_requires_explicit_key_files() -> None:
    with pytest.raises(AuthKeyMaterialError, match="key files are required"):
        load_auth_key_material(Settings.model_construct(env="production"))


def test_missing_invalid_and_oversized_key_files_fail_generically(tmp_path: Path) -> None:
    missing = write_key_files(tmp_path)
    missing["jwt_private_key_file"] = tmp_path / "missing-private-key.pem"
    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(Settings(env="test", **missing))

    empty = write_key_files(tmp_path)
    empty["jwt_private_key_file"].write_bytes(b"")
    with pytest.raises(AuthKeyMaterialError, match="key file is invalid"):
        load_auth_key_material(Settings(env="test", **empty))

    oversized = tmp_path / "oversized-key"
    oversized.write_bytes(b"x" * 65_537)
    with pytest.raises(AuthKeyMaterialError, match="key file is invalid"):
        _read_bounded(oversized)
    with pytest.raises(AuthKeyMaterialError, match="key file is missing"):
        _read_bounded(None)


def test_signing_key_algorithm_and_pair_must_match(tmp_path: Path) -> None:
    wrong_algorithm = write_key_files(tmp_path)
    ec_private = ec.generate_private_key(ec.SECP256R1())
    wrong_algorithm["jwt_private_key_file"].write_bytes(
        ec_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    wrong_algorithm["jwt_public_key_file"].write_bytes(
        ec_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(AuthKeyMaterialError, match="must be Ed25519"):
        load_auth_key_material(Settings(env="test", **wrong_algorithm))

    mismatched = write_key_files(tmp_path)
    other_key = Ed25519PrivateKey.generate()
    mismatched["jwt_public_key_file"].write_bytes(
        other_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(AuthKeyMaterialError, match="does not match"):
        load_auth_key_material(Settings(env="test", **mismatched))


def test_absent_previous_key_directories_match_todays_single_entry_rings(tmp_path: Path) -> None:
    material = load_auth_key_material(Settings(env="test", **write_key_files(tmp_path)))

    assert len(material.verification_keys) == 1
    assert len(material.token_peppers) == 1
    assert len(material.mfa_encryption_keys) == 1


def test_previous_verification_key_loads_alongside_the_current_one(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-jwt"
    previous_dir.mkdir()
    retired_signer = Ed25519PrivateKey.generate()
    (previous_dir / "v0").write_bytes(_public_pem(retired_signer))

    material = load_auth_key_material(
        Settings(
            env="test",
            jwt_previous_public_keys_dir=previous_dir,
            **write_key_files(tmp_path),
        )
    )

    assert set(material.verification_keys) == {"v0", "v1"}
    assert material.verification_keys["v0"].public_bytes(_RAW, _RAW_PUBLIC) == (
        retired_signer.public_key().public_bytes(_RAW, _RAW_PUBLIC)
    )


def test_previous_pepper_loads_alongside_the_current_one(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "2").write_bytes(b"q" * 32)
    paths = write_key_files(tmp_path)

    material = load_auth_key_material(
        Settings(
            env="test",
            token_previous_peppers_dir=previous_dir,
            token_key_version=3,
            **paths,
        )
    )

    assert material.token_peppers == {2: b"q" * 32, 3: b"p" * 32}


def test_previous_mfa_key_still_decrypts_an_envelope_it_encrypted(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-mfa"
    previous_dir.mkdir()
    retired_key = b"o" * 32
    (previous_dir / "1").write_bytes(retired_key)
    admin_id, credential_id = uuid4(), uuid4()
    envelope = encrypt_mfa_seed(
        b"s" * 20,
        admin_id=admin_id,
        credential_id=credential_id,
        key_version=1,
        key_ring={1: retired_key},
    )

    material = load_auth_key_material(
        Settings(
            env="test",
            mfa_previous_encryption_keys_dir=previous_dir,
            mfa_key_version=2,
            **write_key_files(tmp_path),
        )
    )

    assert (
        decrypt_mfa_seed(
            envelope,
            admin_id=admin_id,
            credential_id=credential_id,
            key_ring=material.mfa_encryption_keys,
        )
        == b"s" * 20
    )


def test_previous_key_colliding_with_the_current_version_fails_generically(
    tmp_path: Path,
) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "1").write_bytes(b"r" * 32)

    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir,
                **write_key_files(tmp_path),
            )
        )


def test_duplicate_previous_key_versions_fail_generically(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "2").write_bytes(b"r" * 32)
    (previous_dir / "02").write_bytes(b"s" * 32)

    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir,
                **write_key_files(tmp_path),
            )
        )


def test_malformed_previous_key_filename_fails_generically(tmp_path: Path) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "not-a-version").write_bytes(b"r" * 32)

    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir,
                **write_key_files(tmp_path),
            )
        )


def test_malformed_previous_key_content_fails_like_a_malformed_current_key(
    tmp_path: Path,
) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "2").write_bytes(b"too-short")

    with pytest.raises(AuthKeyMaterialError, match="exactly 32 bytes"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir,
                **write_key_files(tmp_path),
            )
        )


def test_previous_key_directory_that_is_actually_a_file_fails_generically(
    tmp_path: Path,
) -> None:
    previous_dir_as_file = tmp_path / "previous-pepper-file"
    previous_dir_as_file.write_bytes(b"not a directory")

    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir_as_file,
                **write_key_files(tmp_path),
            )
        )


def test_missing_previous_key_directory_fails_generically(tmp_path: Path) -> None:
    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=tmp_path / "does-not-exist",
                **write_key_files(tmp_path),
            )
        )


def test_nested_directory_inside_a_previous_key_directory_fails_generically(
    tmp_path: Path,
) -> None:
    previous_dir = tmp_path / "previous-pepper"
    previous_dir.mkdir()
    (previous_dir / "nested").mkdir()

    with pytest.raises(AuthKeyMaterialError, match="key material is invalid"):
        load_auth_key_material(
            Settings(
                env="test",
                token_previous_peppers_dir=previous_dir,
                **write_key_files(tmp_path),
            )
        )
