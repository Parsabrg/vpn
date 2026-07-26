import asyncio

from fastapi.testclient import TestClient
from starlette.types import Message, Scope

from nebula_api.main import create_app
from nebula_api.settings import Settings


async def ready() -> bool:
    return True


def test_declared_oversized_body_is_rejected_before_route_parsing() -> None:
    settings = Settings(env="test", max_request_bytes=1_024)
    with TestClient(create_app(settings, readiness_check=ready)) as client:
        response = client.post(
            "/v1/auth/login",
            content=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "1025"},
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert response.headers["cache-control"] == "no-store"


def test_body_at_or_below_limit_is_replayed_to_the_application() -> None:
    settings = Settings(env="test", max_request_bytes=1_024)
    with TestClient(create_app(settings, readiness_check=ready)) as client:
        response = client.post(
            "/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "password-canary",
                "device_name": "Phone",
                "platform": "android",
                "client_version": "1.0",
            },
        )

    assert response.status_code == 503


async def _send_chunked_body_without_content_length() -> list[Message]:
    application = create_app(
        Settings(env="test", max_request_bytes=1_024),
        readiness_check=ready,
    )
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/auth/login",
        "raw_path": b"/v1/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "client": ("203.0.113.10", 12345),
        "server": ("testserver", 80),
    }
    incoming: list[Message] = [
        {"type": "http.request", "body": b"a" * 600, "more_body": True},
        {"type": "http.request", "body": b"b" * 600, "more_body": False},
    ]
    outgoing: list[Message] = []

    async def receive() -> Message:
        return incoming.pop(0)

    async def send(message: Message) -> None:
        outgoing.append(message)

    await application(scope, receive, send)
    return outgoing


def test_chunked_body_without_content_length_is_bounded() -> None:
    messages = asyncio.run(_send_chunked_body_without_content_length())
    start = next(message for message in messages if message["type"] == "http.response.start")
    assert start["status"] == 413
