"""ASGI request-body limits enforced before framework body parsing."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_TOO_LARGE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}


class RequestBodyLimitMiddleware:
    """Reject declared or streamed bodies larger than a configured byte limit."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("request body limit must be positive")
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if self._declared_body_is_too_large(scope):
            await self._reject(scope, receive, send)
            return

        buffered: list[Message] = []
        received_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self._max_bytes:
                    await self._reject(scope, receive, send)
                    return
            buffered.append(message)
            if message["type"] != "http.request" or not message.get("more_body", False):
                break

        async def replay_receive() -> Message:
            if buffered:
                return buffered.pop(0)
            return await receive()

        await self._app(scope, replay_receive, send)

    def _declared_body_is_too_large(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", ()):
            if name.lower() != b"content-length":
                continue
            try:
                return int(value) > self._max_bytes
            except ValueError:
                return False
        return False

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": "Request body too large"},
            status_code=413,
            headers=_TOO_LARGE_HEADERS,
        )
        await response(scope, receive, send)
