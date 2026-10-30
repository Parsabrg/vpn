"""Serve the traffic counters the control plane accumulates.

Read-only, so it bypasses the idempotency ledger the mutating routes use --
there is nothing to replay, and a repeated poll is meant to return fresh
numbers rather than a stored answer.

Deliberately reports every counter the host can see rather than only those the
control plane currently knows about. A credential the control plane has
forgotten but the server is still serving is exactly the discrepancy worth
being able to notice, and filtering here would hide it.
"""

import logging
from collections.abc import Awaitable
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from nebula_agent.drivers.hysteria_config_store import (
    TRAFFIC_STATS_PORT,
    traffic_stats_secret,
)
from nebula_agent.drivers.xray_config_store import STATS_API_PORT
from nebula_agent.settings import Settings
from nebula_agent.usage import (
    UsageSample,
    collect_hysteria_usage,
    collect_wireguard_usage,
    collect_xray_usage,
)

router = APIRouter(prefix="/v1/usage", tags=["usage"])
_LOGGER = logging.getLogger(__name__)


class UsageSampleModel(BaseModel):
    protocol: str
    identity: str
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)
    sampled_at: str


class UsageResponse(BaseModel):
    samples: list[UsageSampleModel]
    # Which sources answered. A source that failed reports no samples, which
    # is indistinguishable from a source with nothing to report -- and those
    # mean very different things when a user's usage suddenly stops growing.
    sources_read: list[str]
    sources_failed: list[str]


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@router.post("/collect", response_model=UsageResponse)
async def collect_usage(
    settings: Annotated[Settings, Depends(get_settings)],
) -> UsageResponse:
    samples: list[UsageSample] = []
    read: list[str] = []
    failed: list[str] = []

    async def gather(name: str, source: Awaitable[list[UsageSample]]) -> None:
        try:
            collected = await source
        except Exception:
            # One unreadable source must not fail a poll that can still
            # report the others; the caller is told which failed.
            _LOGGER.exception("usage collection failed for %s", name)
            failed.append(name)
            return
        samples.extend(collected)
        read.append(name)

    await gather(
        "wireguard",
        collect_wireguard_usage(wg_binary=str(settings.wg_binary), interface=settings.wg_interface),
    )

    if settings.xray_enabled:
        # Address comes from the same constants the config store renders, so
        # the poller and the listener cannot drift apart.
        await gather(
            "xray",
            collect_xray_usage(
                xray_binary=str(settings.xray_binary),
                api_address=f"{settings.xray_api_host}:{STATS_API_PORT}",
            ),
        )

    hysteria_profile = settings.hysteria_server_profile()
    if hysteria_profile is not None:
        await gather(
            "hysteria2",
            collect_hysteria_usage(
                api_url=f"http://{settings.xray_api_host}:{TRAFFIC_STATS_PORT}/traffic",
                # Derived the same way the config store derives it, for the
                # same reason: one derivation, no stored secret to rotate.
                secret=traffic_stats_secret(hysteria_profile),
            ),
        )

    return UsageResponse(
        samples=[
            UsageSampleModel(
                protocol=sample.protocol,
                identity=sample.identity,
                rx_bytes=sample.rx_bytes,
                tx_bytes=sample.tx_bytes,
                sampled_at=sample.sampled_at.isoformat(),
            )
            for sample in samples
        ],
        sources_read=read,
        sources_failed=failed,
    )
