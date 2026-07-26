from collections.abc import Mapping

import pytest
from fastapi import HTTPException, Request
from starlette.types import Scope

from nebula_api.auth.http import (
    client_network_prefix,
    require_allowed_origin,
    require_json_request,
)
from nebula_api.settings import Settings


def request(
    *,
    headers: Mapping[str, str] | None = None,
    client: tuple[str, int] | None = ("127.0.0.1", 12345),
) -> Request:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/auth/login",
        "raw_path": b"/v1/auth/login",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (key.lower().encode("ascii"), value.encode("ascii"))
            for key, value in (headers or {}).items()
        ],
        "client": client,
        "server": ("testserver", 443),
    }
    return Request(scope)


def test_json_and_exact_origin_guards_accept_only_expected_values() -> None:
    settings = Settings(env="test", allowed_origins="https://admin.example.test")
    valid = request(
        headers={
            "content-type": "application/json; charset=utf-8",
            "origin": "https://admin.example.test",
        }
    )

    require_json_request(valid)
    require_allowed_origin(valid, settings)

    with pytest.raises(HTTPException) as media_error:
        require_json_request(request(headers={"content-type": "text/plain"}))
    assert media_error.value.status_code == 415

    for origin in (None, "https://attacker.example"):
        headers = {} if origin is None else {"origin": origin}
        with pytest.raises(HTTPException) as origin_error:
            require_allowed_origin(request(headers=headers), settings)
        assert origin_error.value.status_code == 403


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (None, "unknown"),
        (("not-an-address", 1), "unknown"),
        (("192.0.2.129", 1), "192.0.2.0/24"),
        (("::ffff:192.0.2.129", 1), "192.0.2.0/24"),
        (("2001:db8:abcd:1234:5678::1", 1), "2001:db8:abcd:1234::/64"),
    ],
)
def test_client_network_prefix_uses_only_the_socket_peer(
    client: tuple[str, int] | None,
    expected: str,
) -> None:
    assert client_network_prefix(request(client=client)) == expected
