"""The route that hands the control plane its counters.

What matters here is not the arithmetic -- `test_usage.py` covers that -- but
which sources get asked and what happens when one of them cannot answer. A
source that fails must be named: reporting no samples for it looks exactly
like a source with nothing to report, and those mean very different things
when someone's usage suddenly stops growing.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest
from fastapi.testclient import TestClient

from nebula_agent import usage
from nebula_agent.api import v1_usage
from nebula_agent.drivers.fake import FakeXrayRunner
from nebula_agent.ledger import OperationLedger
from nebula_agent.main import create_app
from nebula_agent.settings import Settings
from nebula_agent.usage import UsageSample

SAMPLED_AT = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
WIREGUARD_DIGEST = "a" * 64
XRAY_DIGEST = "b" * 64
HYSTERIA_DIGEST = "c" * 64


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"env": "test"}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _hysteria_settings() -> Settings:
    return _settings(
        xray_hysteria_enabled=True,
        xray_hysteria_obfs_password="s3cret-salamander",  # noqa: S106 - fixture, not real
        xray_tls_cert_file=PurePosixPath("/run/nebula-secrets/xray_tls_cert"),
        xray_tls_key_file=PurePosixPath("/run/nebula-secrets/xray_tls_key"),
    )


def _sample(protocol: str, identity: str, *, rx: int = 10, tx: int = 20) -> UsageSample:
    return UsageSample(
        protocol=protocol,
        identity=identity,
        rx_bytes=rx,
        tx_bytes=tx,
        sampled_at=SAMPLED_AT,
    )


class Collectors:
    """Stands in for the three sources, recording which were asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []
        self.wireguard: list[UsageSample] | Exception = [_sample("wireguard", WIREGUARD_DIGEST)]
        self.xray: list[UsageSample] | Exception = [_sample("xray", XRAY_DIGEST)]
        self.hysteria: list[UsageSample] | Exception = [_sample("hysteria2", HYSTERIA_DIGEST)]
        self.hysteria_secrets: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def wireguard(**_kwargs: object) -> list[UsageSample]:
            self.asked.append("wireguard")
            return _result(self.wireguard)

        async def xray(**_kwargs: object) -> list[UsageSample]:
            self.asked.append("xray")
            return _result(self.xray)

        async def hysteria(**kwargs: object) -> list[UsageSample]:
            self.asked.append("hysteria2")
            self.hysteria_secrets.append(str(kwargs.get("secret")))
            return _result(self.hysteria)

        monkeypatch.setattr(v1_usage, "collect_wireguard_usage", wireguard)
        monkeypatch.setattr(v1_usage, "collect_xray_usage", xray)
        monkeypatch.setattr(v1_usage, "collect_hysteria_usage", hysteria)


def _result(value: list[UsageSample] | Exception) -> list[UsageSample]:
    if isinstance(value, Exception):
        raise value
    return value


@pytest.fixture
def collectors(monkeypatch: pytest.MonkeyPatch) -> Collectors:
    installed = Collectors()
    installed.install(monkeypatch)
    return installed


def _client(tmp_path: Path, settings: Settings) -> Iterator[TestClient]:
    ledger = OperationLedger(PurePosixPath(str(tmp_path / "ledger.jsonl")), 100)
    app = create_app(settings, xray_driver=FakeXrayRunner(), ledger=ledger)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    yield from _client(tmp_path, _settings())


def test_wireguard_is_always_read(client: TestClient, collectors: Collectors) -> None:
    # Unconditional, matching every deployment: the agent always serves it.
    response = client.post("/v1/usage/collect")

    assert response.status_code == 200
    body = response.json()
    assert body["sources_read"] == ["wireguard"]
    assert body["sources_failed"] == []
    assert [sample["identity"] for sample in body["samples"]] == [WIREGUARD_DIGEST]


def test_a_disabled_source_is_not_read_and_is_not_a_failure(
    client: TestClient, collectors: Collectors
) -> None:
    # Xray off means there are no Xray counters to miss. Listing it as failed
    # would raise an alert every poll on a WireGuard-only host.
    client.post("/v1/usage/collect")

    assert collectors.asked == ["wireguard"]


def test_xray_is_read_when_enabled(tmp_path: Path, collectors: Collectors) -> None:
    for client in _client(tmp_path, _settings(xray_enabled=True)):
        body = client.post("/v1/usage/collect").json()

    assert collectors.asked == ["wireguard", "xray"]
    assert body["sources_read"] == ["wireguard", "xray"]
    assert {sample["protocol"] for sample in body["samples"]} == {"wireguard", "xray"}


def test_hysteria_is_read_when_a_server_profile_exists(
    tmp_path: Path, collectors: Collectors
) -> None:
    for client in _client(tmp_path, _hysteria_settings()):
        body = client.post("/v1/usage/collect").json()

    assert collectors.asked == ["wireguard", "hysteria2"]
    assert body["sources_read"] == ["wireguard", "hysteria2"]


def test_the_hysteria_secret_is_derived_not_the_obfs_password(
    tmp_path: Path, collectors: Collectors
) -> None:
    # The stats endpoint is authorised with a value derived from the obfs
    # password, never the password itself -- sending the password would put a
    # live credential in a header on every poll.
    for client in _client(tmp_path, _hysteria_settings()):
        client.post("/v1/usage/collect")

    assert collectors.hysteria_secrets != ["s3cret-salamander"]
    assert len(collectors.hysteria_secrets[0]) == 64


def test_one_failing_source_does_not_cost_the_others_their_samples(
    tmp_path: Path, collectors: Collectors
) -> None:
    # The reason each source is gathered in its own try: a poll that reported
    # nothing because one engine was down would look like a quiet day.
    collectors.xray = RuntimeError("xray api unreachable")

    for client in _client(tmp_path, _settings(xray_enabled=True)):
        response = client.post("/v1/usage/collect")

    assert response.status_code == 200
    body = response.json()
    assert body["sources_read"] == ["wireguard"]
    assert body["sources_failed"] == ["xray"]
    assert [sample["identity"] for sample in body["samples"]] == [WIREGUARD_DIGEST]


def test_every_source_failing_still_answers_rather_than_erroring(
    tmp_path: Path, collectors: Collectors
) -> None:
    # A 500 here is logged by the caller as an unreachable server, which is a
    # different diagnosis from "this host's counters are all unreadable".
    collectors.wireguard = OSError("wg not installed")
    collectors.xray = RuntimeError("boom")

    for client in _client(tmp_path, _settings(xray_enabled=True)):
        response = client.post("/v1/usage/collect")

    assert response.status_code == 200
    assert response.json() == {
        "samples": [],
        "sources_read": [],
        "sources_failed": ["wireguard", "xray"],
    }


def test_samples_carry_their_counters_and_timestamp(
    client: TestClient, collectors: Collectors
) -> None:
    collectors.wireguard = [_sample("wireguard", WIREGUARD_DIGEST, rx=4096, tx=8192)]

    sample = client.post("/v1/usage/collect").json()["samples"][0]

    assert sample["protocol"] == "wireguard"
    assert sample["rx_bytes"] == 4096
    assert sample["tx_bytes"] == 8192
    # A consumer detecting a counter reset needs to know whether two readings
    # are minutes or days apart.
    assert sample["sampled_at"] == SAMPLED_AT.isoformat()


def test_collecting_is_not_replayed_from_the_ledger(
    client: TestClient, collectors: Collectors
) -> None:
    # The mutating routes dedupe on an idempotency key. This one must not:
    # a repeated poll is asking for fresh numbers, not a stored answer.
    client.post("/v1/usage/collect")
    client.post("/v1/usage/collect")

    assert collectors.asked == ["wireguard", "wireguard"]


def test_the_route_takes_no_body(client: TestClient, collectors: Collectors) -> None:
    # Nothing for the caller to narrow: the agent reports every counter it can
    # see, deliberately including credentials the control plane has forgotten.
    assert client.post("/v1/usage/collect", json={"protocol": "xray"}).status_code == 200


def test_a_source_whose_endpoint_refuses_the_connection_is_reported_as_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real collector, failing the way it failed in production.

    The stubs above replace whole collectors with ones that raise, which is
    what let the original bug through: the real collectors caught their own
    errors and returned no samples, so a source that was never reachable was
    reported as read with nothing to say -- and the totals silently never
    moved. Here only the socket is stubbed, so the collector's own error
    handling is the thing under test.
    """

    def refused(*_args: object, **_kwargs: object) -> object:
        raise OSError("connection refused")

    monkeypatch.setattr(usage, "_fetch_json", refused)

    for client in _client(tmp_path, _hysteria_settings()):
        body = client.post("/v1/usage/collect").json()

    # Only hysteria2 is asserted on: whether a real `wg` binary exists is a
    # property of the machine running the test, not of the code.
    assert "hysteria2" in body["sources_failed"]
    assert "hysteria2" not in body["sources_read"]
