"""Polling every server for its counters.

The poll is a fan-out over servers that must not be all-or-nothing: one
unreachable agent has to cost that server's samples and nothing else. Its
counters keep running while it is away, so the next successful poll still
carries the total -- which makes a failure here a delay rather than a loss,
and makes "keep going" the correct behaviour rather than merely the
convenient one.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

from nebula_api.agent_client.client import AgentClientError
from nebula_api.agent_client.models import (
    CollectUsageRequest,
    CollectUsageResponse,
    UsageSampleItem,
)
from nebula_api.db.engine import SessionFactory
from nebula_api.usage.poll import UsagePollSummary, run_usage_poll
from nebula_api.usage.service import UsageSample, UsageService

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 9, 7, 12, 15, tzinfo=UTC)


class FakeServer:
    def __init__(self, code: str) -> None:
        self.code = code
        self.agent_host = f"{code}.internal"
        self.agent_port = 9443


class FakeSession:
    """Answers the one query the poll makes: the active servers."""

    def __init__(self, servers: list[FakeServer]) -> None:
        self.servers = servers

    async def scalars(self, _statement: object) -> Any:
        return _Scalars(self.servers)


class _Scalars:
    def __init__(self, rows: list[FakeServer]) -> None:
        self._rows = rows

    def all(self) -> list[FakeServer]:
        return self._rows


def _session_factory(session: FakeSession, closed: list[bool] | None = None) -> SessionFactory:
    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        try:
            yield cast(AsyncSession, session)
        finally:
            if closed is not None:
                closed.append(True)

    return cast(SessionFactory, lambda: _scope())


class FakeAgentClient:
    def __init__(self, result: CollectUsageResponse | Exception) -> None:
        self.result = result
        self.calls: list[CollectUsageRequest] = []

    async def __aenter__(self) -> "FakeAgentClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def collect_usage(self, request: CollectUsageRequest) -> CollectUsageResponse:
        self.calls.append(request)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _builder(clients: dict[str, FakeAgentClient]) -> object:
    def _build(host: str, _port: int) -> FakeAgentClient:
        return clients[host.split(".")[0]]

    return _build


class RecordingUsageService:
    def __init__(self, moved: int = 0) -> None:
        self.recorded: list[UsageSample] = []
        self.moved = moved

    async def record(self, samples: list[UsageSample]) -> int:
        self.recorded.extend(samples)
        return self.moved


def _response(
    *,
    samples: list[UsageSampleItem] | None = None,
    read: list[str] | None = None,
    failed: list[str] | None = None,
) -> CollectUsageResponse:
    return CollectUsageResponse(
        samples=samples or [],
        sources_read=read or [],
        sources_failed=failed or [],
    )


def _sample(identity: str, rx: int = 10, tx: int = 20) -> UsageSampleItem:
    return UsageSampleItem(
        protocol="xray",
        identity=identity,
        rx_bytes=rx,
        tx_bytes=tx,
        sampled_at=NOW,
    )


def _run(
    servers: list[FakeServer],
    clients: dict[str, FakeAgentClient],
    usage: RecordingUsageService,
) -> UsagePollSummary:
    return asyncio.run(
        run_usage_poll(
            _session_factory(FakeSession(servers)),
            _builder(clients),
            cast(UsageService, usage),
        )
    )


class TestSummary:
    def test_a_clean_poll_has_no_problems(self) -> None:
        summary = UsagePollSummary(
            servers_polled=3,
            servers_failed=0,
            samples=12,
            credentials_active=4,
            sources_failed=[],
        )
        assert not summary.had_problems

    def test_an_unreachable_server_is_a_problem(self) -> None:
        summary = UsagePollSummary(
            servers_polled=2,
            servers_failed=1,
            samples=0,
            credentials_active=0,
            sources_failed=[],
        )
        assert summary.had_problems

    def test_a_server_that_answered_but_could_not_read_a_source_is_a_problem(self) -> None:
        # The poll succeeded and the totals still moved, so nothing raised --
        # but one engine's counters went unread, which understates usage. It
        # is exactly the failure that would otherwise be invisible.
        summary = UsagePollSummary(
            servers_polled=1,
            servers_failed=0,
            samples=5,
            credentials_active=2,
            sources_failed=["vps1:hysteria2"],
        )
        assert summary.had_problems


class TestRunUsagePoll:
    def test_collects_from_every_active_server(self) -> None:
        clients = {
            "vps1": FakeAgentClient(_response(samples=[_sample("a" * 64)], read=["wireguard"])),
            "vps2": FakeAgentClient(_response(samples=[_sample("b" * 64)], read=["xray"])),
        }
        usage = RecordingUsageService(moved=2)

        summary = _run([FakeServer("vps1"), FakeServer("vps2")], clients, usage)

        assert summary.servers_polled == 2
        assert summary.servers_failed == 0
        assert summary.samples == 2
        assert summary.credentials_active == 2
        assert {sample.identity for sample in usage.recorded} == {"a" * 64, "b" * 64}

    def test_an_unreachable_server_does_not_cost_the_others_their_samples(self) -> None:
        # The reason the loop catches per server instead of wrapping the whole
        # fan-out: one agent being down must not throw away counters that were
        # read successfully elsewhere.
        clients = {
            "vps1": FakeAgentClient(AgentClientError(503, "agent unreachable")),
            "vps2": FakeAgentClient(_response(samples=[_sample("b" * 64)])),
        }
        usage = RecordingUsageService(moved=1)

        summary = _run([FakeServer("vps1"), FakeServer("vps2")], clients, usage)

        assert summary.servers_failed == 1
        assert summary.servers_polled == 1
        assert [sample.identity for sample in usage.recorded] == ["b" * 64]

    def test_a_refused_connection_is_caught_like_an_agent_error(self) -> None:
        # The agent client raises AgentClientError for anything it can
        # interpret, but a socket that never opens surfaces as OSError. Both
        # mean the same thing here.
        clients = {"vps1": FakeAgentClient(OSError("connection refused"))}
        usage = RecordingUsageService()

        summary = _run([FakeServer("vps1")], clients, usage)

        assert summary.servers_failed == 1
        assert usage.recorded == []

    def test_a_failed_source_is_reported_against_the_server_that_saw_it(self) -> None:
        # "hysteria2" alone would not say which server could not read it, and
        # every server runs the same three engines.
        clients = {
            "vps1": FakeAgentClient(_response(failed=["hysteria2"])),
            "vps2": FakeAgentClient(_response(failed=["xray", "wireguard"])),
        }

        summary = _run([FakeServer("vps1"), FakeServer("vps2")], clients, RecordingUsageService())

        assert summary.sources_failed == ["vps1:hysteria2", "vps2:xray", "vps2:wireguard"]
        assert summary.had_problems

    def test_the_samples_reach_the_service_intact(self) -> None:
        clients = {"vps1": FakeAgentClient(_response(samples=[_sample("c" * 64, rx=7, tx=9)]))}
        usage = RecordingUsageService(moved=1)

        _run([FakeServer("vps1")], clients, usage)

        recorded = usage.recorded[0]
        assert recorded.protocol == "xray"
        assert recorded.identity == "c" * 64
        assert recorded.rx_bytes == 7
        assert recorded.tx_bytes == 9
        assert recorded.sampled_at == NOW

    def test_each_sample_carries_when_its_server_was_asked(self) -> None:
        # What the ledger orders readings of one credential by.
        asked = iter([NOW, LATER])
        clients = {
            "vps1": FakeAgentClient(_response(samples=[_sample("a" * 64)])),
            "vps2": FakeAgentClient(_response(samples=[_sample("b" * 64)])),
        }
        usage = RecordingUsageService()

        asyncio.run(
            run_usage_poll(
                _session_factory(FakeSession([FakeServer("vps1"), FakeServer("vps2")])),
                _builder(clients),
                cast(UsageService, usage),
                clock=lambda: next(asked),
            )
        )

        assert [sample.collected_at for sample in usage.recorded] == [NOW, LATER]

    def test_no_active_servers_records_nothing(self) -> None:
        usage = RecordingUsageService()

        summary = _run([], {}, usage)

        assert summary == UsagePollSummary(
            servers_polled=0,
            servers_failed=0,
            samples=0,
            credentials_active=0,
            sources_failed=[],
        )
        assert not summary.had_problems


def test_the_session_is_released_before_any_agent_is_dialled() -> None:
    """The servers are read into memory and the session closed first.

    Holding a database session open across a fan-out of network calls would
    pin a connection for as long as the slowest agent takes to time out, and
    the poll runs beside reconciliation on the same small pool.
    """

    closed: list[bool] = []
    dialled: list[str] = []

    class WatchfulClient(FakeAgentClient):
        async def collect_usage(self, request: CollectUsageRequest) -> CollectUsageResponse:
            assert closed, "the session was still open when the agent was dialled"
            dialled.append("yes")
            return await super().collect_usage(request)

    clients = {"vps1": WatchfulClient(_response())}

    asyncio.run(
        run_usage_poll(
            _session_factory(FakeSession([FakeServer("vps1")]), closed),
            _builder(cast(Any, clients)),
            cast(UsageService, RecordingUsageService()),
        )
    )

    assert dialled == ["yes"]
