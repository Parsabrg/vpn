from fastapi.testclient import TestClient

from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.drivers.wireguard import NativeWireGuardDriver
from nebula_agent.drivers.xray import NativeXrayDriver
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
        "/v1/xray-operations/provision-client",
        "/v1/xray-operations/revoke-client",
        "/v1/xray-operations/reconcile-client",
        "/v1/xray-operations/prune-clients",
        "/v1/xray-operations/health",
        # Read-only, and the only route here that is not an operation: it
        # reports byte counters for the control plane to accumulate.
        "/v1/usage/collect",
    }


def test_selecting_the_native_driver_builds_a_native_driver_instance() -> None:
    app = create_app(Settings(env="test", wg_driver="native"))
    assert isinstance(app.state.driver, NativeWireGuardDriver)


def test_selecting_the_native_xray_driver_builds_a_native_driver_instance() -> None:
    app = create_app(Settings(env="test", xray_driver="native"))
    assert isinstance(app.state.xray_driver, NativeXrayDriver)


def test_fake_xray_driver_is_the_default() -> None:
    app = create_app(Settings(env="test"))
    assert isinstance(app.state.xray_driver, FakeXrayRunner)


class _ResyncSpy(FakeXrayRunner):
    def __init__(self, error: Exception | None = None) -> None:
        super().__init__()
        self.error = error
        self.calls = 0

    async def resync_served_config(self) -> bool:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return True


def test_startup_resyncs_the_served_xray_config() -> None:
    # A restart is how the agent is deployed, so it has to be how a change to
    # the rendered config takes effect. Without this, traffic accounting sat
    # dormant in production until an unrelated user happened to provision.
    spy = _ResyncSpy()

    with TestClient(create_app(Settings(env="test"), xray_driver=spy)) as client:
        assert client.get("/readyz").json()["status"] == "ready"

    assert spy.calls == 1


def test_a_failed_resync_does_not_stop_the_agent_starting() -> None:
    # An agent that refuses to start has stopped serving provisioning
    # entirely, which is far worse than one serving a slightly stale config.
    spy = _ResyncSpy(error=RuntimeError("xray would not reload"))

    with TestClient(create_app(Settings(env="test"), xray_driver=spy)) as client:
        response = client.get("/readyz")

    assert spy.calls == 1
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
