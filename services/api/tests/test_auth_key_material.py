from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nebula_api.auth.key_material import (
    AuthKeyMaterialError,
    _read_bounded,
    load_auth_key_material,
)
from nebula_api.settings import Settings


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
    assert repr(material) == "AuthKeyMaterial(<redacted>)"


def test_configured_key_pair_and_symmetric_keys_load(tmp_path: Path) -> None:
    material = load_auth_key_material(Settings(env="test", **write_key_files(tmp_path)))

    assert set(material.verification_keys) == {"v1"}
    assert material.token_peppers == {1: b"p" * 32}
    assert material.mfa_encryption_keys == {1: b"m" * 32}


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
