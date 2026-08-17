import base64
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from nebula_agent.drivers.base import (
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    HealthRequest,
    HealthResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ReconcileRequest,
    ReconcileResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
)
from nebula_agent.drivers.errors import DriverError
from nebula_agent.drivers.fake import FakeWireGuardRunner
from nebula_agent.ledger import OperationLedger
from nebula_agent.main import create_app
from nebula_agent.settings import Settings

PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    ledger = OperationLedger(PurePosixPath(str(tmp_path / "ledger.jsonl")), 100)
    app = create_app(Settings(env="test"), driver=FakeWireGuardRunner(), ledger=ledger)
    with TestClient(app) as test_client:
        yield test_client


def _provision_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "idempotency_key": str(uuid4()),
        "correlation_id": str(uuid4()),
        "target_kind": "wireguard_peer",
        "target_id": str(uuid4()),
        "desired_generation": 0,
        "public_key": PUBLIC_KEY,
        "assigned_address": "10.77.0.2",
    }
    body.update(overrides)
    return body


def test_provision_device_returns_200_and_an_active_peer(client: TestClient) -> None:
    response = client.post("/v1/operations/provision-device", json=_provision_body())

    assert response.status_code == 200
    assert response.json()["state"] == "active"
    assert response.json()["applied_generation"] == 0


def test_provision_device_rejects_a_malformed_public_key(client: TestClient) -> None:
    response = client.post(
        "/v1/operations/provision-device",
        json=_provision_body(public_key="; rm -rf /"),
    )
    assert response.status_code == 422


def test_provision_device_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post(
        "/v1/operations/provision-device",
        json=_provision_body(shell_command="id"),
    )
    assert response.status_code == 422


def test_revoke_device_returns_200(client: TestClient) -> None:
    provision = client.post("/v1/operations/provision-device", json=_provision_body())
    assert provision.status_code == 200

    response = client.post(
        "/v1/operations/revoke-device",
        json={
            "idempotency_key": str(uuid4()),
            "correlation_id": str(uuid4()),
            "target_kind": "wireguard_peer",
            "target_id": str(uuid4()),
            "public_key": PUBLIC_KEY,
            "desired_generation": 1,
        },
    )
    assert response.status_code == 200
    assert response.json()["state"] == "revoked"


def test_health_returns_200(client: TestClient) -> None:
    response = client.post("/v1/operations/health", json={"correlation_id": str(uuid4())})
    assert response.status_code == 200
    assert response.json()["state"] == "healthy"


def test_reconcile_reports_drift_when_peer_is_missing(client: TestClient) -> None:
    response = client.post(
        "/v1/operations/reconcile",
        json={
            "correlation_id": str(uuid4()),
            "target_kind": "wireguard_peer",
            "target_id": str(uuid4()),
            "public_key": PUBLIC_KEY,
            "assigned_address": "10.77.0.2",
            "desired_generation": 0,
        },
    )
    assert response.status_code == 200
    assert response.json()["outcome"] == "drift_detected"


def test_duplicate_idempotency_key_replays_instead_of_reapplying(client: TestClient) -> None:
    body = _provision_body()

    first = client.post("/v1/operations/provision-device", json=body)
    second = client.post("/v1/operations/provision-device", json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert second.json()["applied_generation"] == 0


def test_reused_idempotency_key_for_a_different_target_is_rejected(client: TestClient) -> None:
    key = str(uuid4())
    first = client.post(
        "/v1/operations/provision-device", json=_provision_body(idempotency_key=key)
    )
    assert first.status_code == 200

    second = client.post(
        "/v1/operations/provision-device",
        json=_provision_body(idempotency_key=key, target_id=str(uuid4())),
    )
    assert second.status_code == 409


def test_oversized_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/operations/provision-device",
        json=_provision_body(),
        headers={"content-length": str(20 * 1024)},
    )
    assert response.status_code == 413


def test_agent_still_exposes_only_the_allowlisted_operation_surface(
    client: TestClient,
) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200


class _RaisingDriver:
    """A driver whose health() escapes with an unhandled DriverError, unlike
    FakeWireGuardRunner which always catches ApplyError internally -- this is
    what exercises main.py's DriverError exception handler."""

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        raise NotImplementedError

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        raise NotImplementedError

    async def enable_device(self, request: EnableDeviceRequest) -> EnableDeviceResponse:
        raise NotImplementedError

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        raise NotImplementedError

    async def health(self, request: HealthRequest) -> HealthResponse:
        raise DriverError("boom")

    async def reconcile(self, request: ReconcileRequest) -> ReconcileResponse:
        raise NotImplementedError


def test_unhandled_driver_error_is_mapped_to_a_generic_500(tmp_path: Path) -> None:
    ledger = OperationLedger(PurePosixPath(str(tmp_path / "ledger.jsonl")), 100)
    app = create_app(Settings(env="test"), driver=_RaisingDriver(), ledger=ledger)

    with TestClient(app, raise_server_exceptions=False) as raising_client:
        response = raising_client.post(
            "/v1/operations/health", json={"correlation_id": str(uuid4())}
        )

    assert response.status_code == 500
