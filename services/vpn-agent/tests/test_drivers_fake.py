import base64
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    EnableDeviceRequest,
    HealthRequest,
    ProvisionDeviceRequest,
    ReconcileRequest,
    RevokeDeviceRequest,
)
from nebula_agent.drivers.config_store import ConfigStore
from nebula_agent.drivers.fake import FakeWireGuardRunner

PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()
OTHER_PUBLIC_KEY = base64.b64encode(bytes(range(33, 65))).decode()


def _provision_request(**overrides: object) -> ProvisionDeviceRequest:
    defaults: dict[str, object] = {
        "idempotency_key": uuid4(),
        "correlation_id": uuid4(),
        "target_kind": "wireguard_peer",
        "target_id": uuid4(),
        "desired_generation": 0,
        "public_key": PUBLIC_KEY,
        "assigned_address": "10.77.0.2",
    }
    defaults.update(overrides)
    return ProvisionDeviceRequest(**defaults)


@pytest.mark.anyio
async def test_provision_device_activates_a_peer() -> None:
    driver = FakeWireGuardRunner()
    response = await driver.provision_device(_provision_request())

    assert response.state == "active"
    assert response.applied_generation == 0
    assert response.error_code is None


@pytest.mark.anyio
async def test_applied_generation_echoes_the_requests_desired_generation() -> None:
    driver = FakeWireGuardRunner()
    response = await driver.provision_device(_provision_request(desired_generation=7))
    assert response.applied_generation == 7


@pytest.mark.anyio
async def test_failed_apply_reports_the_peers_last_successfully_applied_generation() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request(desired_generation=3))

    driver.fail_next_apply()
    response = await driver.provision_device(_provision_request(desired_generation=4))

    assert response.state == "failed"
    assert response.applied_generation == 3


@pytest.mark.anyio
async def test_failed_apply_for_a_never_applied_peer_reports_generation_zero() -> None:
    driver = FakeWireGuardRunner()
    driver.fail_next_apply()

    response = await driver.provision_device(_provision_request(desired_generation=4))

    assert response.state == "failed"
    assert response.applied_generation == 0


@pytest.mark.anyio
async def test_provision_device_is_reflected_in_health_peer_count() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())

    health = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health.peer_count == 1
    assert health.state == "healthy"
    assert health.interface_up is True


@pytest.mark.anyio
async def test_provisioning_the_same_public_key_twice_replaces_not_duplicates() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())
    await driver.provision_device(_provision_request(assigned_address="10.77.0.3"))

    health = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health.peer_count == 1


@pytest.mark.anyio
async def test_revoke_device_removes_the_peer() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())

    response = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert response.state == "revoked"

    health = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health.peer_count == 0


@pytest.mark.anyio
async def test_revoking_an_unknown_peer_still_succeeds() -> None:
    driver = FakeWireGuardRunner()
    response = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=0,
        )
    )
    assert response.state == "revoked"


@pytest.mark.anyio
async def test_disable_then_enable_device_round_trips_peer_count() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())

    disabled = await driver.disable_device(
        DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert disabled.state == "disabled"
    assert (await driver.health(HealthRequest(correlation_id=uuid4()))).peer_count == 0

    enabled = await driver.enable_device(
        EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=2,
        )
    )
    assert enabled.state == "enabled"
    assert (await driver.health(HealthRequest(correlation_id=uuid4()))).peer_count == 1


@pytest.mark.anyio
async def test_reconcile_reports_in_sync_when_state_matches() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.outcome == "in_sync"


@pytest.mark.anyio
async def test_reconcile_reports_drift_detected_when_peer_is_missing() -> None:
    driver = FakeWireGuardRunner()

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=1,
        )
    )
    assert response.outcome == "drift_detected"
    assert response.observed_generation is None


@pytest.mark.anyio
async def test_reconcile_reports_ambiguous_when_address_mismatches() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())

    response = await driver.reconcile(
        ReconcileRequest(
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.99",
            desired_generation=1,
        )
    )
    assert response.outcome == "ambiguous"


@pytest.mark.anyio
async def test_injected_failure_is_reported_without_mutating_state() -> None:
    driver = FakeWireGuardRunner()
    driver.fail_next_apply()

    response = await driver.provision_device(_provision_request())
    assert response.state == "failed"
    assert response.error_code == "apply_failed"

    health = await driver.health(HealthRequest(correlation_id=uuid4()))
    assert health.peer_count == 0


@pytest.mark.anyio
async def test_injected_failure_is_reported_on_revoke_device() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())
    driver.fail_next_apply()

    response = await driver.revoke_device(
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"
    assert (await driver.health(HealthRequest(correlation_id=uuid4()))).peer_count == 1


@pytest.mark.anyio
async def test_injected_failure_is_reported_on_enable_device() -> None:
    driver = FakeWireGuardRunner()
    driver.fail_next_apply()

    response = await driver.enable_device(
        EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=0,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


@pytest.mark.anyio
async def test_injected_failure_is_reported_on_disable_device() -> None:
    driver = FakeWireGuardRunner()
    await driver.provision_device(_provision_request())
    driver.fail_next_apply()

    response = await driver.disable_device(
        DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=PUBLIC_KEY,
            desired_generation=1,
        )
    )
    assert response.state == "failed"
    assert response.error_code == "apply_failed"


@pytest.mark.anyio
async def test_failure_only_affects_the_next_call() -> None:
    driver = FakeWireGuardRunner()
    driver.fail_next_apply()
    await driver.provision_device(_provision_request())

    response = await driver.provision_device(_provision_request(public_key=OTHER_PUBLIC_KEY))
    assert response.state == "active"


@pytest.mark.anyio
async def test_config_store_promotion_happens_on_successful_apply(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    driver = FakeWireGuardRunner(config_store=store)

    await driver.provision_device(_provision_request())

    assert store.last_known_good_path.exists()
    assert not store.candidate_path.exists()


@pytest.mark.anyio
async def test_driver_rehydrates_from_an_existing_config_store(tmp_path: Path) -> None:
    store = ConfigStore(PurePosixPath(str(tmp_path)), "wg0")
    seeded = FakeWireGuardRunner(config_store=store)
    await seeded.provision_device(_provision_request())

    rehydrated = FakeWireGuardRunner(config_store=ConfigStore(PurePosixPath(str(tmp_path)), "wg0"))
    health = await rehydrated.health(HealthRequest(correlation_id=uuid4()))
    assert health.peer_count == 1
