"""Recognising a physical device across an uninstall and reinstall.

A device's server id lives in app storage, which an uninstall wipes. The
reinstalled app sends no id and used to be registered as a brand-new device,
so one phone counted twice against the account's device limit and the old row
never went away.

The fix is a stable identifier the app can reproduce after a reinstall -- the
platform's own install/hardware id -- which the app sends and the server keys
a device on. It is never stored in the clear: the server keeps only an
HMAC-SHA256 of it under the token pepper, so the stored value is useless off
this deployment and cannot be matched back to a device without the secret.
"""

import hmac
from hashlib import sha256

from nebula_api.auth.opaque_tokens import KeyRing

# Bound into the HMAC message so a hardware hash can never collide with a
# digest this deployment computes for anything else under the same key.
_NAMESPACE = b"nebula.device.hardware\x00"


def hash_hardware_id(hardware_id: str, key_ring: KeyRing, *, key_version: int) -> tuple[int, bytes]:
    """The current-key HMAC of a device's hardware id, with its key version."""

    key = key_ring.get(key_version)
    if key is None:
        raise KeyError("no pepper for the configured key version")
    digest = hmac.new(key, _NAMESPACE + hardware_id.encode("utf-8"), sha256).digest()
    return key_version, digest


def hardware_id_matches(
    hardware_id: str,
    *,
    stored_hash: bytes,
    stored_version: int,
    key_ring: KeyRing,
) -> bool:
    """Whether [hardware_id] is the one [stored_hash] was made from.

    Checked against the key version the stored hash names, so a pepper
    rotation does not strand devices enrolled under an earlier key.
    """

    key = key_ring.get(stored_version)
    if key is None:
        return False
    candidate = hmac.new(key, _NAMESPACE + hardware_id.encode("utf-8"), sha256).digest()
    return hmac.compare_digest(candidate, stored_hash)
