"""Prometheus metrics for the API, read on the host at 127.0.0.1:8000/metrics.

Requests are counted by route template (`/v1/admin/users/{user_id}`), never by
the raw path, so a scanner cannot grow the label set. nginx answers /metrics
from outside with 404.
"""

import time

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUESTS = Counter(
    "nebula_api_requests_total", "HTTP requests answered", ["method", "route", "status"]
)
LATENCY = Histogram("nebula_api_request_seconds", "Time to answer an HTTP request", ["route"])


class MetricsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started, status = time.perf_counter(), 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            route = getattr(scope.get("route"), "path", "unmatched")
            REQUESTS.labels(scope["method"], route, str(status)).inc()
            LATENCY.labels(route).observe(time.perf_counter() - started)


def exposition() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
