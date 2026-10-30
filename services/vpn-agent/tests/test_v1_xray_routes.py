from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.ledger import OperationLedger
from nebula_agent.main import create_app
from nebula_agent.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    ledger = OperationLedger(PurePosixPath(str(tmp_path / "ledger.jsonl")), 100)
    app = create_app(Settings(env="test"), xray_driver=FakeXrayRunner(), ledger=ledger)
    with TestClient(app) as test_client:
        yield test_client


def _provision_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "idempotency_key": str(uuid4()),
        "correlation_id": str(uuid4()),
        "target_kind": "xray_client",
        "target_id": str(uuid4()),
        "desired_generation": 0,
        "client_uuid": str(uuid4()),
        "protocol_profile_code": "vless-xhttp-tls",
    }
    body.update(overrides)
    return body


def test_provision_client_returns_200_and_an_active_client(client: TestClient) -> None:
    response = client.post("/v1/xray-operations/provision-client", json=_provision_body())

    assert response.status_code == 200
    assert response.json()["state"] == "active"
    assert response.json()["applied_generation"] == 0
    # XHTTP is loopback-only, nginx-fronted -- nginx terminates TLS, not
    # Xray, so this inbound's own security is "none".
    assert response.json()["transport_security"] == "none"


def test_provision_client_rejects_a_malformed_uuid(client: TestClient) -> None:
    response = client.post(
        "/v1/xray-operations/provision-client",
        json=_provision_body(client_uuid="not-a-uuid"),
    )
    assert response.status_code == 422


def test_provision_client_rejects_unknown_fields(client: TestClient) -> None:
    response = client.post(
        "/v1/xray-operations/provision-client",
        json=_provision_body(shell_command="id"),
    )
    assert response.status_code == 422


def test_revoke_client_returns_200(client: TestClient) -> None:
    body = _provision_body()
    provision = client.post("/v1/xray-operations/provision-client", json=body)
    assert provision.status_code == 200

    response = client.post(
        "/v1/xray-operations/revoke-client",
        json={
            "idempotency_key": str(uuid4()),
            "correlation_id": str(uuid4()),
            "target_kind": "xray_client",
            "target_id": str(uuid4()),
            "client_uuid": body["client_uuid"],
            "protocol_profile_code": "vless-xhttp-tls",
            "desired_generation": 1,
        },
    )
    assert response.status_code == 200
    assert response.json()["state"] == "revoked"


def test_health_returns_200(client: TestClient) -> None:
    response = client.post("/v1/xray-operations/health", json={"correlation_id": str(uuid4())})
    assert response.status_code == 200
    assert response.json()["state"] == "healthy"


def test_duplicate_idempotency_key_replays_instead_of_reapplying(client: TestClient) -> None:
    body = _provision_body()

    first = client.post("/v1/xray-operations/provision-client", json=body)
    second = client.post("/v1/xray-operations/provision-client", json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


def test_reused_idempotency_key_for_a_different_target_is_rejected(client: TestClient) -> None:
    key = str(uuid4())
    first = client.post(
        "/v1/xray-operations/provision-client", json=_provision_body(idempotency_key=key)
    )
    assert first.status_code == 200

    second = client.post(
        "/v1/xray-operations/provision-client",
        json=_provision_body(idempotency_key=key, target_id=str(uuid4())),
    )
    assert second.status_code == 409


def test_oversized_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/xray-operations/provision-client",
        json=_provision_body(),
        headers={"content-length": str(20 * 1024)},
    )
    assert response.status_code == 413
