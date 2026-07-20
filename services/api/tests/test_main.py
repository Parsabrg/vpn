from fastapi.testclient import TestClient
from starlette.routing import Route

from nebula_api.main import create_app
from nebula_api.settings import Settings


async def ready_database() -> bool:
    return True


async def unavailable_database() -> bool:
    return False


def test_health_probe_is_non_sensitive() -> None:
    with TestClient(create_app(Settings(env="test"), readiness_check=ready_database)) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "nebula-api", "version": "0.1.0"}


def test_readiness_is_enabled_during_lifespan() -> None:
    with TestClient(create_app(Settings(env="test"), readiness_check=ready_database)) as client:
        response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_readiness_is_disabled_before_startup() -> None:
    client = TestClient(create_app(Settings(env="test"), readiness_check=ready_database))
    try:
        response = client.get("/readyz")
    finally:
        client.close()

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_documentation_and_openapi_are_not_public() -> None:
    with TestClient(create_app(Settings(env="test"), readiness_check=ready_database)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_readiness_is_generic_when_database_is_unavailable() -> None:
    with TestClient(
        create_app(Settings(env="test"), readiness_check=unavailable_database)
    ) as client:
        response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "service": "nebula-api",
        "version": "0.1.0",
    }


def test_phase_1_2_exposes_only_probe_routes() -> None:
    app = create_app(Settings(env="test"), readiness_check=ready_database)
    application_paths = {route.path for route in app.routes if isinstance(route, Route)}

    assert application_paths == {"/healthz", "/readyz"}
