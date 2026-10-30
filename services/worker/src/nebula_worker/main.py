"""Process entry point: run the outbox poll loop forever."""

import asyncio
import logging
import tempfile
from pathlib import Path
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

# Touched after every delivery attempt and poll that returned, so the container's
# health check can tell a loop that is working from one that is stuck. A batch
# can contain 100 sequential deliveries and take longer than the health window,
# even while every individual delivery completes. The same arrangement the
# `usage` container uses (nebula_api/cli.py's USAGE_HEARTBEAT), and for the
# same reason: this process has no port to probe, so without a heartbeat the
# only failure Docker could see was the process exiting. A worker wedged on a
# provider that never answers keeps every activation and password-reset email
# unsent, and nothing would have said so.
POLL_HEARTBEAT = Path(tempfile.gettempdir()) / "nebula-worker-poll"


def _record_poll() -> None:
    """Never fatal: a heartbeat that cannot be written is a monitoring
    problem, and refusing to deliver mail over it would be the worse one."""

    try:
        POLL_HEARTBEAT.touch()
    except OSError:
        _LOGGER.warning("could not write the poll heartbeat", exc_info=True)


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
            processed = await poll_once(
                engine, redis_client, adapter, settings, on_progress=_record_poll
            )
        except Exception:
            _LOGGER.exception("Outbox poll iteration failed")
            processed = 0
        # After a failed poll too: the loop is still turning, and a provider
        # refusing every message is a different problem from this process
        # being wedged. The failures themselves are logged above.
        _record_poll()
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
