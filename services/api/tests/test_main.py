from fastapi.testclient import TestClient

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


def test_phase_1_3_registers_probes_and_separate_auth_realms() -> None:
    with TestClient(create_app(Settings(env="test"), readiness_check=ready_database)) as client:
        user = client.post(
            "/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "password-canary",
                "device_name": "Phone",
                "platform": "android",
                "client_version": "1.0",
            },
        )
        admin = client.post(
            "/v1/admin/auth/login",
            headers={"Origin": "http://localhost:3000"},
            json={"identifier": "owner@example.com", "password": "password-canary"},
        )

    assert user.status_code == admin.status_code == 503
