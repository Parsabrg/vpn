"""Process entry point: run the outbox poll loop forever."""

import asyncio
import logging
from typing import cast

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_worker.adapters.base import EmailAdapter
from nebula_worker.adapters.resend import ResendAdapter
from nebula_worker.adapters.smtp import SmtpAdapter
from nebula_worker.db import create_worker_engine
from nebula_worker.outbox import OutboxRedisClient
from nebula_worker.poller import poll_once
from nebula_worker.settings import Settings, get_settings

_LOGGER = logging.getLogger(__name__)


def build_adapter(settings: Settings) -> EmailAdapter:
    if settings.email_provider == "resend":
        return ResendAdapter(settings)
    return SmtpAdapter(settings)


async def run_loop(
    engine: AsyncEngine,
    redis_client: OutboxRedisClient,
    adapter: EmailAdapter,
    settings: Settings,
    *,
    iterations: int | None = None,
) -> None:
    """Poll until `iterations` batches have been attempted, or forever if `None`."""

    completed = 0
    while iterations is None or completed < iterations:
        try:
            processed = await poll_once(engine, redis_client, adapter, settings)
        except Exception:
            _LOGGER.exception("Outbox poll iteration failed")
            processed = 0
        completed += 1
        if processed == 0 and (iterations is None or completed < iterations):
            await asyncio.sleep(settings.poll_interval_seconds)


async def run_forever(settings: Settings | None = None) -> None:
    runtime_settings = settings or get_settings()
    logging.basicConfig(level=runtime_settings.log_level)
    engine = create_worker_engine(runtime_settings.database_url.get_secret_value())
    redis_client = Redis.from_url(runtime_settings.redis_url.get_secret_value())
    adapter = build_adapter(runtime_settings)
    try:
        await run_loop(engine, cast(OutboxRedisClient, redis_client), adapter, runtime_settings)
    finally:
        await engine.dispose()
        await redis_client.aclose()


def main() -> None:
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
