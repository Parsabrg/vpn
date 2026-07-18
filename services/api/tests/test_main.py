from fastapi.testclient import TestClient

from nebula_api.main import create_app
from nebula_api.settings import Settings


def test_health_probe_is_non_sensitive() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "nebula-api", "version": "0.1.0"}


def test_readiness_is_enabled_during_lifespan() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_readiness_is_disabled_before_startup() -> None:
    client = TestClient(create_app(Settings(env="test")))
    try:
        response = client.get("/readyz")
    finally:
        client.close()

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_documentation_and_openapi_are_not_public() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
