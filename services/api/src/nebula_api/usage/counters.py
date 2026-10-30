"""Read a server's traffic counters, and keep them across changes that reset them.

Changing what a server serves ends counters. Adding or removing one Xray
client restarts the whole Xray process, which zeroes every client's counters
on that server, not only the one being changed. A changed Hysteria2 client
list restarts Hysteria2. A removed WireGuard peer takes its counters with it.
Connects and disconnects are exactly these changes, so on a server people
actually use, the periodic poll saw little of what was served between two of
them.

So each such call is bracketed:

    before   read the server's counters and record them, so whatever the
             change is about to zero is already in the totals.
    change   make the call.
    after    read again and record it. A counter that was there before and is
             gone now has its last reading set back to zero
             (`UsageLedger.forget_readings`), so all of it counts when the
             client comes back.

A counter that is merely lower afterwards is a reset the ordinary rule already
handles. One that is gone is what that rule cannot see: the client's next
reading would be taken for a normal interval, and the old figure subtracted
from bytes that were all new.

Nothing here may fail the change. A server that cannot report its counters
still gets its client provisioned, and a database that cannot record them
still lets the connect through; what that costs is the traffic a restart
zeroes before anyone reads it, which is what every change used to cost.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Protocol

import httpx
from sqlalchemy.exc import SQLAlchemyError

from nebula_api.agent_client.client import AgentClient, AgentClientError, AgentUnreachable
from nebula_api.agent_client.models import (
    CollectUsageRequest,
    DisableDeviceRequest,
    DisableDeviceResponse,
    EnableDeviceRequest,
    EnableDeviceResponse,
    ProvisionDeviceRequest,
    ProvisionDeviceResponse,
    ProvisionXrayClientRequest,
    ProvisionXrayClientResponse,
    PruneXrayClientsRequest,
    PruneXrayClientsResponse,
    RevokeDeviceRequest,
    RevokeDeviceResponse,
    RevokeXrayClientRequest,
    RevokeXrayClientResponse,
)
from nebula_api.settings import Settings
from nebula_api.usage.service import UsageSample

_LOGGER = logging.getLogger(__name__)

Clock = Callable[[], datetime]
Sleep = Callable[[float], Awaitable[None]]

# `systemctl restart` returns once Xray is spawned, before its stats API is
# listening, so the read straight after a change can find that one source not
# answering yet. Asked again briefly, then given up on: the change is made and
# somebody is waiting for their connect.
AFTER_CHANGE_READ_ATTEMPTS = 6
AFTER_CHANGE_READ_PAUSE_SECONDS = 0.5


class CounterLedger(Protocol):
    async def record(self, samples: list[UsageSample]) -> int: ...

    async def forget_readings(
        self, gone: list[tuple[str, str]], *, collected_at: datetime
    ) -> int: ...


@dataclass(frozen=True, slots=True)
class CounterReading:
    """One server's counters, as one call to its agent reported them."""

    samples: list[UsageSample]
    # The agent names its sources after the protocol each one reports --
    # "wireguard", "xray", "hysteria2" -- which is what lets a sample be
    # matched to whether its source was read at all.
    sources_read: frozenset[str]
    sources_failed: list[str]
    collected_at: datetime


async def read_counters(agent: AgentClient, *, clock: Clock) -> CounterReading:
    collected_at = clock()
    response = await agent.collect_usage(CollectUsageRequest())
    return CounterReading(
        samples=[
            UsageSample(
                protocol=sample.protocol,
                identity=sample.identity,
                rx_bytes=sample.rx_bytes,
                tx_bytes=sample.tx_bytes,
                sampled_at=sample.sampled_at,
                collected_at=collected_at,
            )
            for sample in response.samples
        ],
        sources_read=frozenset(response.sources_read),
        sources_failed=list(response.sources_failed),
        collected_at=collected_at,
    )


async def keep_counters_across[ResultT](
    change: Callable[[], Awaitable[ResultT]],
    *,
    read: Callable[[], Awaitable[CounterReading]],
    ledger: CounterLedger,
    sleep: Sleep = asyncio.sleep,
) -> ResultT:
    before = await _read(read)
    if before is not None:
        await _write(ledger.record(before.samples))

    try:
        result = await change()
    except AgentUnreachable:
        # Never reached the agent, so nothing was changed or reset.
        raise
    except AgentClientError:
        # Rejected, timed out, or answered with something unreadable. The
        # last two may well have made the change, restart and all.
        if before is not None:
            await _after_change(before, read=read, ledger=ledger, sleep=sleep)
        raise

    if before is not None:
        await _after_change(before, read=read, ledger=ledger, sleep=sleep)
    return result


async def _after_change(
    before: CounterReading,
    *,
    read: Callable[[], Awaitable[CounterReading]],
    ledger: CounterLedger,
    sleep: Sleep,
) -> None:
    after = await _read(read)
    attempts = 1
    while (
        after is not None
        and not before.sources_read <= after.sources_read
        and attempts < AFTER_CHANGE_READ_ATTEMPTS
    ):
        await sleep(AFTER_CHANGE_READ_PAUSE_SECONDS)
        after = await _read(read)
        attempts += 1
    if after is None:
        return

    present = {(sample.protocol, sample.identity) for sample in after.samples}
    gone = [
        (sample.protocol, sample.identity)
        for sample in before.samples
        # Only from a source this read reached: a counter missing because its
        # source did not answer is not gone, and forgetting its reading would
        # count it twice.
        if sample.protocol in after.sources_read
        and (sample.protocol, sample.identity) not in present
    ]
    await _write(ledger.record(after.samples))
    await _write(ledger.forget_readings(gone, collected_at=after.collected_at))


async def _read(read: Callable[[], Awaitable[CounterReading]]) -> CounterReading | None:
    try:
        return await read()
    except (AgentClientError, OSError) as error:
        _LOGGER.warning("could not read usage counters around a change: %s", str(error)[:200])
        return None


async def _write(write: Awaitable[int]) -> None:
    try:
        await write
    except SQLAlchemyError as error:
        _LOGGER.warning("could not record usage counters around a change: %s", type(error).__name__)


class CounterKeepingAgentClient(AgentClient):
    """An agent client whose changes keep that server's usage counters.

    Only calls that change what the server serves are bracketed. Health checks,
    reconcile comparisons and collecting usage itself restart nothing.
    """

    def __init__(
        self,
        *,
        agent_host: str,
        agent_port: int,
        settings: Settings,
        ledger: CounterLedger,
        clock: Clock = lambda: datetime.now(UTC),
        sleep: Sleep = asyncio.sleep,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(
            agent_host=agent_host, agent_port=agent_port, settings=settings, transport=transport
        )
        self._ledger = ledger
        self._clock = clock
        self._sleep = sleep

    async def _keeping_counters[ResultT](self, change: Callable[[], Awaitable[ResultT]]) -> ResultT:
        return await keep_counters_across(
            change,
            read=partial(read_counters, self, clock=self._clock),
            ledger=self._ledger,
            sleep=self._sleep,
        )

    async def provision_device(self, request: ProvisionDeviceRequest) -> ProvisionDeviceResponse:
        return await self._keeping_counters(partial(super().provision_device, request))

    async def revoke_device(self, request: RevokeDeviceRequest) -> RevokeDeviceResponse:
        return await self._keeping_counters(partial(super().revoke_device, request))

    async def enable_device(self, request: EnableDeviceRequest) -> EnableDeviceResponse:
        return await self._keeping_counters(partial(super().enable_device, request))

    async def disable_device(self, request: DisableDeviceRequest) -> DisableDeviceResponse:
        return await self._keeping_counters(partial(super().disable_device, request))

    async def provision_xray_client(
        self, request: ProvisionXrayClientRequest
    ) -> ProvisionXrayClientResponse:
        return await self._keeping_counters(partial(super().provision_xray_client, request))

    async def revoke_xray_client(
        self, request: RevokeXrayClientRequest
    ) -> RevokeXrayClientResponse:
        return await self._keeping_counters(partial(super().revoke_xray_client, request))

    async def prune_xray_clients(
        self, request: PruneXrayClientsRequest
    ) -> PruneXrayClientsResponse:
        return await self._keeping_counters(partial(super().prune_xray_clients, request))
