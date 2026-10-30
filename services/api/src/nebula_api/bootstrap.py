"""First-run initialization, safe to run on every start.

This runs from the container entrypoint, which means it runs again on every
restart, every redeploy, and every crash loop. So the question it answers is
not "set this up" but "is this already set up, and if not, what exactly is
missing" -- each step is checked and skipped independently, because a
half-finished bootstrap is the normal case after an interrupted first start.

What it must never do, and what the code is shaped to prevent:

  - generate a second deployment identity. Nodes are enrolled against the
    first one, and a new identity orphans every one of them while looking
    like a clean install. The database refuses a second row; this refuses to
    ask for one.
  - overwrite the deployment secret. It signs enrollment tokens, so replacing
    it invalidates outstanding enrolments with no error anywhere.
  - re-seed the administrator. Somebody may have changed that password.

Secrets are generated here rather than baked into an image or read from a
compose file, and they are written to the secrets directory with the rest of
the key material -- see docs/runbooks/encryption-key-rotation.md for why that
directory is the one place they live.
"""

import logging
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select, text

from nebula_api.db.engine import SessionFactory, session_scope
from nebula_api.models.deployment import Deployment
from nebula_api.models.identity import AdminUser
from nebula_api.pki import (
    create_certificate_authority,
    create_certificate_request,
    load_certificate_authority,
    sign_node_certificate,
    write_certificate,
    write_private_key,
)

_LOGGER = logging.getLogger(__name__)

DEPLOYMENT_SECRET_BYTES = 32
_SECRET_FILE_MODE = 0o640


async def ensure_deployment(
    session_factory: SessionFactory, *, name: str, admin_email: str | None = None
) -> tuple[Deployment, bool]:
    """The deployment identity, creating it only if there is none.

    Under an advisory lock, matching how the initial admin is seeded: two
    containers starting together is the expected case behind a compose file,
    and both would otherwise read "no deployment" and both insert. The unique
    index would reject the loser, but with an integrity error rather than the
    correct answer, and a crash loop at start is a bad way to learn that.
    """

    async with session_scope(session_factory) as session:
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtext('nebula.deployment'))"))
        existing = await session.scalar(select(Deployment))
        if existing is not None:
            # The name and administrator are configuration and may legitimately
            # change between starts; the identity may not. Updating them here
            # is what makes a changed environment variable take effect without
            # anything else being disturbed.
            existing.name = name
            if admin_email is not None:
                existing.admin_email = admin_email
            return existing, False

        deployment = Deployment(
            id=uuid4(),
            name=name,
            admin_email=admin_email,
            initialized_at=datetime.now(UTC),
        )
        session.add(deployment)
        await session.flush()
        return deployment, True


def ensure_deployment_secret(path: Path) -> bool:
    """Generate the deployment secret if it does not exist yet.

    Returns whether it was created. Never overwrites: this signs node
    enrollment tokens, so replacing it silently invalidates every outstanding
    enrolment, and the failure appears later as a node that cannot join for
    no visible reason.

    Written owner-read plus group-read, matching the other key material --
    the API reads its secrets through a group rather than as root, and a
    root-only file is one the service cannot open.
    """

    if path.exists():
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create: two processes racing here must not both believe they
    # wrote the secret, because only one of them did and the other would
    # carry on with bytes that were never stored.
    # O_BINARY (Windows only): without it every 0x0A byte of the secret is
    # written as CRLF, and one secret in eight came out too long to read.
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), _SECRET_FILE_MODE
    )
    try:
        os.write(descriptor, secrets.token_bytes(DEPLOYMENT_SECRET_BYTES))
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, _SECRET_FILE_MODE)
    except OSError:
        # Best effort: some filesystems refuse, and the exclusive create above
        # already applied the mode.
        pass
    # Never the value, at any level. This is the one secret that can mint
    # node credentials.
    _LOGGER.info("generated a deployment secret at %s", path)
    return True


def read_deployment_secret(path: Path) -> bytes:
    """The deployment secret, or a clear failure.

    Deliberately not generated on demand here. A caller that needs the secret
    is signing or verifying something, and quietly inventing one would make
    every previously issued token invalid while appearing to work.
    """

    data = path.read_bytes()
    if len(data) != DEPLOYMENT_SECRET_BYTES:
        raise ValueError("the deployment secret is not the expected length")
    return data


def ensure_node_authority(certificate_path: Path, key_path: Path, *, deployment_name: str) -> bool:
    """Generate the node certificate authority if there is none.

    Returns whether it was created. Never replaces an existing one: every
    certificate this deployment has ever issued to a node chains to it, so a
    new CA silently stops the control plane trusting every node it already
    enrolled -- and each of those failures looks like the node being
    misconfigured rather than like the authority having changed underneath it.

    Both files, or neither. A certificate without its key cannot sign and a
    key without its certificate cannot be presented, so finding one of the
    two is a half-written state worth refusing rather than completing with a
    freshly generated partner that does not match.
    """

    if certificate_path.exists() and key_path.exists():
        return False
    if certificate_path.exists() or key_path.exists():
        raise RuntimeError(
            "the node certificate authority is incomplete; "
            "one of its certificate and key exists without the other"
        )

    certificate_pem, key_pem = create_certificate_authority(deployment_name=deployment_name)
    write_certificate(certificate_path, certificate_pem)
    write_private_key(key_path, key_pem)
    # The path, never the key.
    _LOGGER.info("generated a node certificate authority at %s", certificate_path)
    return True


# What the control plane calls itself on the agent link. A name rather than a
# hostname because nothing dials the control plane over this connection --
# the agent only ever checks that the certificate presented to it was issued
# by the authority it trusts.
CONTROL_PLANE_COMMON_NAME = "nebula-control-plane"


def ensure_control_plane_identity(
    certificate_path: Path,
    key_path: Path,
    *,
    authority_certificate_path: Path,
    authority_key_path: Path,
) -> bool:
    """Issue the control plane its own client certificate. Returns whether
    one was created.

    The other half of enrollment. A node receives a certificate signed by
    this deployment's authority and trusts that authority in return -- so the
    control plane has to present something from the same authority or the
    node refuses it, and the connection fails at the handshake with nothing
    on either side saying which certificate was the problem.

    Nothing here talks to the enrollment endpoint. The control plane holds
    the CA key already, so it signs for itself; a token would be ceremony
    around an authority that is sitting in the same process.

    Both files, or neither, for the same reason as the authority above.
    """

    if certificate_path.exists() and key_path.exists():
        return False
    if certificate_path.exists() or key_path.exists():
        raise RuntimeError(
            "the control plane's client certificate is incomplete; "
            "one of its certificate and key exists without the other"
        )

    authority = load_certificate_authority(authority_certificate_path, authority_key_path)
    csr_pem, key_pem = create_certificate_request(common_name=CONTROL_PLANE_COMMON_NAME)
    certificate_pem = sign_node_certificate(
        authority,
        csr_pem,
        common_name=CONTROL_PLANE_COMMON_NAME,
        hostnames=[CONTROL_PLANE_COMMON_NAME],
    )
    write_private_key(key_path, key_pem)
    write_certificate(certificate_path, certificate_pem)
    _LOGGER.info("issued the control plane's client certificate at %s", certificate_path)
    return True


async def has_administrator(session_factory: SessionFactory) -> bool:
    async with session_scope(session_factory) as session:
        return bool(await session.scalar(select(func.count(AdminUser.id))))
