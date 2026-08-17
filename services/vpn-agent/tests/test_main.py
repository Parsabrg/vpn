from fastapi.testclient import TestClient

from nebula_agent.drivers.wireguard import NativeWireGuardDriver
from nebula_agent.main import create_app
from nebula_agent.settings import Settings


def test_health_probe_is_non_sensitive() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "nebula-vpn-agent",
        "version": "0.1.0",
    }


def test_readiness_is_enabled_during_lifespan() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_agent_exposes_only_the_allowlisted_operation_surface() -> None:
    app = create_app(Settings(env="test"))
    application_paths = set(app.openapi()["paths"].keys())

    assert application_paths == {
        "/healthz",
        "/readyz",
        "/v1/operations/provision-device",
        "/v1/operations/revoke-device",
        "/v1/operations/enable-device",
        "/v1/operations/disable-device",
        "/v1/operations/health",
        "/v1/operations/reconcile",
    }


def test_selecting_the_native_driver_builds_a_native_driver_instance() -> None:
    app = create_app(Settings(env="test", wg_driver="native"))
    assert isinstance(app.state.driver, NativeWireGuardDriver)
