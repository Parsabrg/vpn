"""Real NativeWireGuardDriver, real `wg`/`wg-quick`, a real (namespaced)
kernel WireGuard interface.

Gated: only meaningful with root and a WireGuard-capable kernel, and only
after the CI job's own setup (netns creation, `wg0` interface, server
private key) has already run -- see the `netns-integration` job in
.github/workflows/python.yml. This file never creates the namespace or the
interface itself; it only exercises the driver against whatever `Settings()`
picks up from the environment that job already configured. It is never run
locally (skipped unless NEBULA_WG_NETNS_INTEGRATION is set), mirroring the
NEBULA_DATABASE_URL-gated Postgres integration tests in services/api.
"""

import base64
import os
from ipaddress import ip_address
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

from nebula_agent.drivers.base import (
    HealthRequest,
    ProvisionDeviceRequest,
    ReconcileRequest,
    RevokeDeviceRequest,
)
from nebula_agent.drivers.config_store import ConfigStore
from nebula_agent.drivers.wireguard import NativeWireGuardDriver
from nebula_agent.settings import Settings

NETNS_INTEGRATION_ENV = "NEBULA_WG_NETNS_INTEGRATION"

pytestmark = [
    pytest.mark.netns_integration,
    pytest.mark.skipif(
        NETNS_INTEGRATION_ENV not in os.environ,
        reason="real WireGuard netns integration is enabled in CI",
    ),
]

# A fixture-only client keypair's public half -- the private half never
# existed; the CI job only needs a syntactically valid public key to
# provision, not a real handshake-capable one.
CLIENT_PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()


@pytest.fixture
def driver(tmp_path: Path) -> NativeWireGuardDriver:
    settings = Settings()  # reads NEBULA_* from the CI job's own environment
    store = ConfigStore(PurePosixPath(str(tmp_path)), settings.wg_interface)
    return NativeWireGuardDriver(settings, store)


@pytest.mark.anyio
async def test_provision_then_revoke_against_a_real_interface(
    driver: NativeWireGuardDriver,
) -> None:
    provision = await driver.provision_device(
        ProvisionDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            desired_generation=1,
            public_key=CLIENT_PUBLIC_KEY,
            assigned_address=ip_address("10.77.0.2"),
        )
    )
    assert provision.state == "active"
    assert provision.applied_generation == 1

    health = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health.state == "healthy"
    assert health.interface_up is True
    assert health.peer_count == 1

    reconcile = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=CLIENT_PUBLIC_KEY,
            assigned_address=ip_address("10.77.0.2"),
            desired_generation=1,
        )
    )
    assert reconcile.outcome == "in_sync"
    assert reconcile.observed_generation == 1

    revoke = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=CLIENT_PUBLIC_KEY,
            desired_generation=2,
        )
    )
    assert revoke.state == "revoked"

    health_after = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health_after.peer_count == 0

    reconcile_after = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=CLIENT_PUBLIC_KEY,
            assigned_address=ip_address("10.77.0.2"),
            desired_generation=2,
        )
    )
    assert reconcile_after.outcome == "drift_detected"
