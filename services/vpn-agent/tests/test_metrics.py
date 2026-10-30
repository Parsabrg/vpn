import socket
import urllib.request

import pytest
import uvicorn
from fastapi.testclient import TestClient
from prometheus_client import generate_latest

from nebula_agent import serve
from nebula_agent.main import create_app
from nebula_agent.metrics import serve_metrics
from nebula_agent.settings import Settings


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_requests_are_counted_by_route_template() -> None:
    with TestClient(create_app(Settings(env="test"))) as client:
        client.get("/healthz")

    body = generate_latest().decode()
    assert 'nebula_agent_requests_total{method="GET",route="/healthz",status="200"}' in body


def test_metrics_are_served_on_loopback() -> None:
    port = free_port()
    serve_metrics(port)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as response:
        assert b"nebula_agent_requests_total" in response.read()


def test_a_taken_port_costs_only_the_metrics(caplog: pytest.LogCaptureFixture) -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        serve_metrics(int(taken.getsockname()[1]))
    assert "metrics not served" in caplog.text


def test_port_zero_serves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("nebula_agent.metrics.start_http_server", pytest.fail)
    serve_metrics(0)


def test_main_starts_metrics_then_the_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(serve, "get_settings", lambda: Settings(env="test", agent_metrics_port=0))
    monkeypatch.setattr(serve, "serve_metrics", lambda port: calls.append(("metrics", port)))
    monkeypatch.setattr(uvicorn.Server, "run", lambda self: calls.append("run"))
    serve.main()
    assert calls == [("metrics", 0), "run"]
