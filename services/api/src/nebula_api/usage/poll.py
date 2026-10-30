"""Ask every active server for its counters and fold them into the totals.

Runs on a timer beside the reconciliation sweep. The interval is a real
trade-off rather than a tuning knob: a counter that resets loses whatever was
served between the last poll and the restart, so a longer interval means more
traffic can go unrecorded. Polling costs one cheap call per server, so the
interval should be short -- but no interval closes the window entirely, which
is why the totals are described as accumulated rather than exact.

The restarts the control plane causes itself are no longer this poll's to
catch: every change it asks an agent for records the counters around it (see
`usage.counters`). What is left here is everything else -- a crash, a reboot,
an agent upgrade -- and the traffic of people who stay connected.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from nebula_api.agent_client.client import AgentClient, AgentClientError
from nebula_api.db.engine import SessionFactory
from nebula_api.models.topology import VPNServer
from nebula_api.models.types import RUNNING_SERVER_STATES
from nebula_api.usage.counters import Clock, read_counters
from nebula_api.usage.service import UsageSample, UsageService

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class UsagePollSummary:
    servers_polled: int
    servers_failed: int
    samples: int
    credentials_active: int
    sources_failed: list[str]

    @property
    def had_problems(self) -> bool:
        return bool(self.servers_failed or self.sources_failed)


async def run_usage_poll(
    session_factory: SessionFactory,
    agent_client_builder: object,
    usage: UsageService,
    *,
    clock: Clock = lambda: datetime.now(UTC),
) -> UsagePollSummary:
    async with session_factory() as session:
        servers = (
            await session.scalars(
                select(VPNServer).where(VPNServer.state.in_(RUNNING_SERVER_STATES))
            )
        ).all()

    polled = 0
    failed = 0
    collected: list[UsageSample] = []
    sources_failed: list[str] = []

    for server in servers:
        client_factory = agent_client_builder
        client: AgentClient = client_factory(server.agent_host, server.agent_port)  # type: ignore[operator]
        try:
            async with client:
                reading = await read_counters(client, clock=clock)
        except (AgentClientError, OSError) as error:
            # An unreachable server means its counters keep running and the
            # next successful poll still carries the total, so this is a
            # delay rather than a loss. Worth counting, not worth aborting
            # the other servers for.
            _LOGGER.warning("usage poll failed for %s: %s", server.code, str(error)[:200])
            failed += 1
            continue

        polled += 1
        sources_failed.extend(f"{server.code}:{name}" for name in reading.sources_failed)
        collected.extend(reading.samples)

    active = await usage.record(collected)
    return UsagePollSummary(
        servers_polled=polled,
        servers_failed=failed,
        samples=len(collected),
        credentials_active=active,
        sources_failed=sources_failed,
    )
