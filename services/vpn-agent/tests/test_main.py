from fastapi.testclient import TestClient
from starlette.routing import Route

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


def test_agent_exposes_only_probe_routes() -> None:
    app = create_app(Settings(env="test"))
    application_paths = {route.path for route in app.routes if isinstance(route, Route)}

    assert application_paths == {"/healthz", "/readyz"}
