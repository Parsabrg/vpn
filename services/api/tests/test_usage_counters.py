"""Keeping traffic counters across the changes that reset them.

Everything here fails silently when it is wrong. A missed "before" loses the
traffic a restart zeroes; a missed "gone" subtracts an old reading from new
bytes for as long as the client stays connected; forgetting a counter whose
source merely did not answer counts it twice. None of it raises, and the only
symptom is an account screen showing a figure nobody can check.
"""

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.exc import OperationalError

from nebula_api.agent_client.client import (
    AgentClientError,
    AgentRejected,
    AgentResponseAmbiguous,
    AgentUnreachable,
)
from nebula_api.agent_client.models import (
    DisableDeviceRequest,
    EnableDeviceRequest,
    HealthRequest,
    ProvisionDeviceRequest,
    ProvisionXrayClientRequest,
    PruneXrayClientsRequest,
    RevokeDeviceRequest,
    RevokeXrayClientRequest,
)
from nebula_api.settings import Settings
from nebula_api.usage.counters import (
    AFTER_CHANGE_READ_ATTEMPTS,
    CounterKeepingAgentClient,
    CounterReading,
    keep_counters_across,
)
from nebula_api.usage.service import UsageSample

BEFORE = datetime(2026, 9, 16, 12, 0, 0, tzinfo=UTC)
AFTER = datetime(2026, 9, 16, 12, 0, 2, tzinfo=UTC)
ALICE = "a" * 64
BOB = "b" * 64
PEER = "c" * 64
VALID_PUBLIC_KEY = "MjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMj0="


def _sample(
    identity: str, rx: int, *, protocol: str = "xray", at: datetime = BEFORE
) -> UsageSample:
    return UsageSample(
        protocol=protocol,
        identity=identity,
        rx_bytes=rx,
        tx_bytes=rx,
        sampled_at=at,
        collected_at=at,
    )


def _reading(
    samples: list[UsageSample],
    *,
    read: tuple[str, ...] = ("wireguard", "xray", "hysteria2"),
    at: datetime = BEFORE,
) -> CounterReading:
    return CounterReading(
        samples=samples,
        sources_read=frozenset(read),
        sources_failed=[],
        collected_at=at,
    )


class RecordingLedger:
    def __init__(self, events: list[str], *, failure: Exception | None = None) -> None:
        self.events = events
        self.failure = failure
        self.recorded: list[list[UsageSample]] = []
        self.forgotten: list[tuple[list[tuple[str, str]], datetime]] = []

    async def record(self, samples: list[UsageSample]) -> int:
        self.events.append("record")
        if self.failure is not None:
            raise self.failure
        self.recorded.append(samples)
        return len(samples)

    async def forget_readings(self, gone: list[tuple[str, str]], *, collected_at: datetime) -> int:
        self.events.append("forget")
        if self.failure is not None:
            raise self.failure
        self.forgotten.append((gone, collected_at))
        return len(gone)


class ScriptedReads:
    """Hands out one scripted result per read: a reading, or an error."""

    def __init__(self, events: list[str], results: list[CounterReading | Exception]) -> None:
        self.events = events
        self.results = results
        self.calls = 0

    async def __call__(self) -> CounterReading:
        self.events.append("read")
        self.calls += 1
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Pauses:
    def __init__(self) -> None:
        self.seconds: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.seconds.append(seconds)


def _change(events: list[str], outcome: object = "changed") -> Callable[[], Awaitable[object]]:
    async def change() -> object:
        events.append("change")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return change


def _keep(
    events: list[str],
    reads: list[CounterReading | Exception],
    *,
    outcome: object = "changed",
    ledger: RecordingLedger | None = None,
    pauses: Pauses | None = None,
) -> tuple[object, RecordingLedger, ScriptedReads]:
    ledger = ledger or RecordingLedger(events)
    read = ScriptedReads(events, reads)
    result = asyncio.run(
        keep_counters_across(
            _change(events, outcome),
            read=read,
            ledger=ledger,
            sleep=pauses or Pauses(),
        )
    )
    return result, ledger, read


class TestAroundAChange:
    def test_records_before_the_change_and_again_after_it(self) -> None:
        events: list[str] = []
        before = _reading([_sample(ALICE, 500)])
        after = _reading([_sample(ALICE, 520, at=AFTER)], at=AFTER)

        result, ledger, _ = _keep(events, [before, after])

        assert result == "changed"
        assert events == ["read", "record", "change", "read", "record", "forget"]
        assert ledger.recorded == [before.samples, after.samples]

    def test_a_counter_gone_after_the_change_has_its_reading_forgotten(self) -> None:
        # Xray restarted: Alice has not reconnected yet, Bob already has.
        events: list[str] = []
        before = _reading([_sample(ALICE, 500), _sample(BOB, 900)])
        after = _reading([_sample(BOB, 3, at=AFTER)], at=AFTER)

        _, ledger, _ = _keep(events, [before, after])

        assert ledger.forgotten == [([("xray", ALICE)], AFTER)]

    def test_a_counter_that_is_only_lower_is_left_to_the_ordinary_rule(self) -> None:
        events: list[str] = []
        before = _reading([_sample(ALICE, 500)])
        after = _reading([_sample(ALICE, 3, at=AFTER)], at=AFTER)

        _, ledger, _ = _keep(events, [before, after])

        assert ledger.forgotten == [([], AFTER)]

    def test_counters_are_matched_by_protocol_as_well_as_identity(self) -> None:
        # The same digest under two engines is two counters.
        events: list[str] = []
        before = _reading([_sample(ALICE, 500), _sample(ALICE, 700, protocol="hysteria2")])
        after = _reading([_sample(ALICE, 700, protocol="hysteria2", at=AFTER)], at=AFTER)

        _, ledger, _ = _keep(events, [before, after])

        assert ledger.forgotten == [([("xray", ALICE)], AFTER)]

    def test_a_source_that_answers_on_a_second_try_is_waited_for(self) -> None:
        # `systemctl restart` returns before Xray's stats API is listening.
        events: list[str] = []
        pauses = Pauses()
        before = _reading([_sample(ALICE, 500), _sample(PEER, 80, protocol="wireguard")])
        not_yet = _reading(
            [_sample(PEER, 80, protocol="wireguard", at=AFTER)],
            read=("wireguard", "hysteria2"),
            at=AFTER,
        )
        after = _reading([_sample(PEER, 80, protocol="wireguard", at=AFTER)], at=AFTER)

        _, ledger, read = _keep(events, [before, not_yet, after], pauses=pauses)

        assert read.calls == 3
        assert len(pauses.seconds) == 1
        assert ledger.forgotten == [([("xray", ALICE)], AFTER)]

    def test_a_source_that_never_answers_has_its_counters_left_alone(self) -> None:
        # Missing because it was not read is not the same as gone. Forgetting
        # those readings would count everything they had counted again.
        events: list[str] = []
        pauses = Pauses()
        before = _reading([_sample(ALICE, 500), _sample(PEER, 80, protocol="wireguard")])
        without_xray = _reading([], read=("wireguard", "hysteria2"), at=AFTER)

        reads: list[CounterReading | Exception] = [before]
        reads.extend([without_xray] * AFTER_CHANGE_READ_ATTEMPTS)

        _, ledger, read = _keep(events, reads, pauses=pauses)

        assert read.calls == 1 + AFTER_CHANGE_READ_ATTEMPTS
        assert len(pauses.seconds) == AFTER_CHANGE_READ_ATTEMPTS - 1
        # The peer's source did answer, and the peer is gone.
        assert ledger.forgotten == [([("wireguard", PEER)], AFTER)]

    def test_a_server_that_cannot_report_still_gets_its_change(self) -> None:
        events: list[str] = []

        result, ledger, read = _keep(events, [AgentClientError("stats unavailable")])

        assert result == "changed"
        # Nothing to compare against, so no second read either.
        assert events == ["read", "change"]
        assert read.calls == 1
        assert ledger.recorded == []

    def test_a_socket_error_is_a_failed_read_too(self) -> None:
        events: list[str] = []

        result, _, _ = _keep(events, [OSError("connection refused")])

        assert result == "changed"
        assert events == ["read", "change"]

    def test_a_failed_read_after_the_change_forgets_nothing(self) -> None:
        events: list[str] = []
        before = _reading([_sample(ALICE, 500)])

        result, ledger, _ = _keep(events, [before, AgentClientError("gone away")])

        assert result == "changed"
        assert ledger.recorded == [before.samples]
        assert ledger.forgotten == []

    def test_a_database_that_cannot_record_does_not_fail_the_change(self) -> None:
        events: list[str] = []
        ledger = RecordingLedger(
            events, failure=OperationalError("UPDATE", {}, Exception("database is down"))
        )
        before = _reading([_sample(ALICE, 500)])
        after = _reading([], at=AFTER)

        result, _, _ = _keep(events, [before, after], ledger=ledger)

        assert result == "changed"
        assert events == ["read", "record", "change", "read", "record", "forget"]

    def test_a_change_that_never_reached_the_agent_is_not_read_after(self) -> None:
        events: list[str] = []
        before = _reading([_sample(ALICE, 500)])

        with pytest.raises(AgentUnreachable):
            _keep(events, [before], outcome=AgentUnreachable("connection refused"))

        assert events == ["read", "record", "change"]

    def test_a_change_whose_answer_was_lost_is_still_read_after(self) -> None:
        # The agent may well have restarted Xray before the response was lost.
        events: list[str] = []
        before = _reading([_sample(ALICE, 500)])
        after = _reading([], at=AFTER)
        ledger = RecordingLedger(events)

        with pytest.raises(AgentResponseAmbiguous):
            _keep(
                events,
                [before, after],
                outcome=AgentResponseAmbiguous("read timeout"),
                ledger=ledger,
            )

        assert ledger.forgotten == [([("xray", ALICE)], AFTER)]

    def test_a_failed_first_read_skips_the_second_even_when_the_change_fails(self) -> None:
        events: list[str] = []

        with pytest.raises(AgentRejected):
            _keep(
                events,
                [AgentClientError("stats unavailable")],
                outcome=AgentRejected(409, "conflict"),
            )

        assert events == ["read", "change"]


def _collect_body(identity: str, rx: int) -> dict[str, object]:
    return {
        "samples": [
            {
                "protocol": "xray",
                "identity": identity,
                "rx_bytes": rx,
                "tx_bytes": rx,
                "sampled_at": BEFORE.isoformat(),
            }
        ],
        "sources_read": ["wireguard", "xray"],
        "sources_failed": [],
    }


def _client(
    handler: Callable[[httpx.Request], httpx.Response], ledger: RecordingLedger
) -> CounterKeepingAgentClient:
    asked = iter([BEFORE, AFTER])
    return CounterKeepingAgentClient(
        agent_host="vpn1.internal",
        agent_port=9443,
        settings=Settings(),
        ledger=ledger,
        clock=lambda: next(asked),
        sleep=Pauses(),
        transport=httpx.MockTransport(handler),
    )


def test_the_agent_client_brackets_a_change_with_two_reads() -> None:
    paths: list[str] = []
    collects = iter([_collect_body(ALICE, 500), _collect_body(BOB, 3)])

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/usage/collect":
            return httpx.Response(200, json=next(collects))
        return httpx.Response(200, json={"state": "pruned", "removed": 1, "kept": 1})

    events: list[str] = []
    ledger = RecordingLedger(events)

    async def scenario() -> None:
        async with _client(handler, ledger) as client:
            response = await client.prune_xray_clients(
                PruneXrayClientsRequest(correlation_id=uuid4(), expected=())
            )
        assert response.removed == 1

    asyncio.run(scenario())

    assert paths == [
        "/v1/usage/collect",
        "/v1/xray-operations/prune-clients",
        "/v1/usage/collect",
    ]
    assert [sample.collected_at for sample in ledger.recorded[0]] == [BEFORE]
    assert ledger.forgotten == [([("xray", ALICE)], AFTER)]


def test_a_read_changes_nothing_and_is_not_bracketed() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "state": "healthy",
                "source": "agent",
                "observed_at": BEFORE.isoformat(),
                "agent_version": "0.1.0",
            },
        )

    async def scenario() -> None:
        async with _client(handler, RecordingLedger([])) as client:
            with contextlib.suppress(AgentClientError):
                await client.health(HealthRequest(correlation_id=uuid4()))

    asyncio.run(scenario())

    assert "/v1/usage/collect" not in paths


_CHANGES: list[tuple[str, object]] = [
    (
        "provision_device",
        ProvisionDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            desired_generation=1,
            public_key=VALID_PUBLIC_KEY,
            assigned_address="10.77.0.2",
        ),
    ),
    (
        "revoke_device",
        RevokeDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            desired_generation=2,
        ),
    ),
    (
        "enable_device",
        EnableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            assigned_address="10.77.0.2",
            desired_generation=3,
        ),
    ),
    (
        "disable_device",
        DisableDeviceRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="wireguard_peer",
            target_id=uuid4(),
            public_key=VALID_PUBLIC_KEY,
            desired_generation=4,
        ),
    ),
    (
        "provision_xray_client",
        ProvisionXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            desired_generation=1,
            client_uuid=uuid4(),
            protocol_profile_code="vless-xhttp-tls",
        ),
    ),
    (
        "revoke_xray_client",
        RevokeXrayClientRequest(
            idempotency_key=uuid4(),
            correlation_id=uuid4(),
            target_kind="xray_client",
            target_id=uuid4(),
            client_uuid=uuid4(),
            protocol_profile_code="vless-xhttp-tls",
            desired_generation=2,
        ),
    ),
]


@pytest.mark.parametrize(("method", "request_model"), _CHANGES, ids=[c[0] for c in _CHANGES])
def test_every_change_a_server_is_asked_for_is_bracketed(
    method: str, request_model: object
) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/usage/collect":
            return httpx.Response(200, json=_collect_body(ALICE, 500))
        # Rejected, which is still a change the agent answered: the counters
        # are read again either way.
        return httpx.Response(409, content=json.dumps({"detail": "conflict"}))

    async def scenario() -> None:
        async with _client(handler, RecordingLedger([])) as client:
            with pytest.raises(AgentRejected):
                await getattr(client, method)(request_model)

    asyncio.run(scenario())

    assert paths[0] == "/v1/usage/collect"
    assert paths[-1] == "/v1/usage/collect"
    assert len(paths) == 3
