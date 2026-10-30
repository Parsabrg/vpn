"""Prometheus metrics for the agent, on 127.0.0.1 only (NEBULA_AGENT_METRICS_PORT).

The agent's own port takes only the control plane's client certificate, so
the metrics have a port of their own. Requests from the control plane are
counted by route template, never by raw path.
"""

import logging
import time

from prometheus_client import Counter, Histogram, start_http_server
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUESTS = Counter(
    "nebula_agent_requests_total", "HTTP requests answered", ["method", "route", "status"]
)
LATENCY = Histogram("nebula_agent_request_seconds", "Time to answer an HTTP request", ["route"])


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


_LOGGER = logging.getLogger(__name__)


def serve_metrics(port: int) -> None:
    """Starts the metrics listener on 127.0.0.1; 0 turns it off. A port that
    is taken costs the metrics, never the agent."""

    if port == 0:
        return
    try:
        start_http_server(port, addr="127.0.0.1")
    except OSError as error:
        _LOGGER.warning("metrics not served on 127.0.0.1:%s: %s", port, error)
