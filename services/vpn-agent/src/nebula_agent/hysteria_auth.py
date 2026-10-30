"""Answers Hysteria2's authentication of each new connection.

With a client list in its config, Hysteria2 only learns about a connect or a
disconnect by restarting, which drops every Hysteria2 session on the server.
Its `auth.type: http` asks a URL instead: for each new connection it POSTs
`{"addr": ..., "auth": ..., "tx": ...}` and admits the client if the answer
is `{"ok": true, "id": ...}`. This is that URL, answered from the client set
the agent has recorded, so a change there takes effect for the next
connection with nothing restarted.

A deliberately small HTTP server rather than a second web framework instance:
one caller, one request shape, on a loopback address, and every limit below
is there so that a malformed or hostile request costs a closed socket and
nothing more. Each response closes the connection, which Go's HTTP client --
the only caller -- handles without complaint.

If the agent is down, new Hysteria2 connections are refused until it is back.
Connections already made carry on.
"""

import asyncio
import json
import logging
from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)

_MAX_HEAD_BYTES = 8192
_MAX_BODY_BYTES = 4096
_READ_TIMEOUT_SECONDS = 5.0

Authorizer = Callable[[str], str | None]
"""An auth string to the label to admit it as, or None to refuse it."""


class HysteriaAuthServer:
    def __init__(self, host: str, port: int, path: str, authorize: Authorizer) -> None:
        self._host = host
        self._port = port
        self._path = path
        self._authorize = authorize
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """The port actually bound -- the configured one, or the one the OS
        chose when asked for port 0."""

        if self._server is None or not self._server.sockets:
            return self._port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, limit=_MAX_HEAD_BYTES
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            status, payload = await asyncio.wait_for(
                self._answer(reader), timeout=_READ_TIMEOUT_SECONDS
            )
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            status, payload = 400, _REFUSED
        body = json.dumps(payload).encode()
        head = (
            f"HTTP/1.1 {status} {_REASONS[status]}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        try:
            writer.write(head + body)
            await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _answer(self, reader: asyncio.StreamReader) -> tuple[int, dict[str, object]]:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, _, rest = lines[0].partition(" ")
        target = rest.rpartition(" ")[0]
        if method != "POST" or target != self._path:
            return 404, _REFUSED

        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        if "transfer-encoding" in headers:
            # Hysteria sends a Content-Length. Anything chunked is not it.
            return 400, _REFUSED
        length = int(headers.get("content-length", "-1"))
        if length < 0 or length > _MAX_BODY_BYTES:
            return 400, _REFUSED

        request = json.loads(await reader.readexactly(length))
        auth = request.get("auth") if isinstance(request, dict) else None
        if not isinstance(auth, str):
            return 400, _REFUSED

        label = self._authorize(auth)
        if label is None:
            return 200, _REFUSED
        return 200, {"ok": True, "id": label}


_REFUSED: dict[str, object] = {"ok": False, "id": ""}
_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found"}
