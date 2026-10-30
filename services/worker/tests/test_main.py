import asyncio
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from nebula_worker.adapters.resend import ResendAdapter
from nebula_worker.adapters.smtp import SmtpAdapter
from nebula_worker.main import build_adapter, run_loop
from nebula_worker.settings import Settings
from tests.test_poller import FakeAdapter, FakeEngine, FakeRedis, _BeginContext


def test_build_adapter_selects_smtp_by_default() -> None:
    assert isinstance(build_adapter(Settings()), SmtpAdapter)


def test_build_adapter_selects_resend() -> None:
    assert isinstance(build_adapter(Settings(email_provider="resend")), ResendAdapter)


def test_run_loop_sleeps_after_an_empty_batch() -> None:
    engine = FakeEngine()

    with patch("nebula_worker.main.asyncio.sleep", new_callable=AsyncMock) as sleep:
        asyncio.run(
            run_loop(
                cast(AsyncEngine, engine),
                FakeRedis(None),
                FakeAdapter(),
                Settings(poll_interval_seconds=0.5),
                iterations=1,
            )
        )

    sleep.assert_not_called()  # the last iteration never sleeps


def test_run_loop_sleeps_between_empty_iterations() -> None:
    engine = FakeEngine()

    with patch("nebula_worker.main.asyncio.sleep", new_callable=AsyncMock) as sleep:
        asyncio.run(
            run_loop(
                cast(AsyncEngine, engine),
                FakeRedis(None),
                FakeAdapter(),
                Settings(poll_interval_seconds=1.0),
                iterations=2,
            )
        )

    sleep.assert_awaited_once_with(1.0)


def test_run_loop_recovers_from_a_failing_iteration() -> None:
    class ExplodingEngine(FakeEngine):
        def begin(self) -> _BeginContext:
            raise RuntimeError("database unavailable")

    with patch("nebula_worker.main.asyncio.sleep", new_callable=AsyncMock):
        asyncio.run(
            run_loop(
                cast(AsyncEngine, ExplodingEngine()),
                FakeRedis(None),
                FakeAdapter(),
                Settings(),
                iterations=1,
            )
        )


def test_run_loop_continues_without_sleeping_while_work_remains() -> None:
    rows = [
        {
            "id": uuid4(),
            "template_code": "request_rejected",
            "recipient_address": "user@example.com",
            "attempt_count": 0,
        }
    ]
    engine = FakeEngine(claim_rows=list(rows))

    with patch("nebula_worker.main.asyncio.sleep", new_callable=AsyncMock) as sleep:
        asyncio.run(
            run_loop(
                cast(AsyncEngine, engine),
                FakeRedis("{}"),
                FakeAdapter(),
                Settings(),
                iterations=1,
            )
        )

    sleep.assert_not_called()


def test_run_loop_records_a_heartbeat_after_a_poll(tmp_path: Path) -> None:
    engine = FakeEngine()
    heartbeat = tmp_path / "worker-poll"

    with patch("nebula_worker.main.POLL_HEARTBEAT", heartbeat):
        asyncio.run(
            run_loop(
                cast(AsyncEngine, engine),
                FakeRedis(None),
                FakeAdapter(),
                Settings(),
                iterations=1,
            )
        )

    assert heartbeat.is_file()


@pytest.mark.parametrize("delivery_error", [None, RuntimeError("provider failed")])
def test_busy_worker_records_progress_before_the_whole_batch_finishes(
    delivery_error: Exception | None,
) -> None:
    rows = [
        {
            "id": uuid4(),
            "template_code": "request_rejected",
            "recipient_address": "user@example.com",
            "attempt_count": 0,
        }
        for _ in range(3)
    ]
    heartbeat = MagicMock()

    class ProgressCheckingAdapter(FakeAdapter):
        async def send(self, *, to: str, subject: str, body: str) -> str:
            # Earlier deliveries have refreshed the heartbeat before the
            # next provider call starts, including failed delivery attempts.
            assert heartbeat.touch.call_count == len(self.calls)
            return await super().send(to=to, subject=subject, body=body)

    adapter = ProgressCheckingAdapter(error=delivery_error)
    with patch("nebula_worker.main.POLL_HEARTBEAT", heartbeat):
        asyncio.run(
            run_loop(
                cast(AsyncEngine, FakeEngine(claim_rows=rows)),
                FakeRedis("{}"),
                adapter,
                Settings(),
                iterations=1,
            )
        )

    assert len(adapter.calls) == 3
    assert heartbeat.touch.call_count == 4


def test_a_heartbeat_write_failure_does_not_stop_email_delivery(
    caplog: pytest.LogCaptureFixture,
) -> None:
    engine = FakeEngine()
    heartbeat = MagicMock()
    heartbeat.touch.side_effect = OSError("read-only filesystem")

    with patch("nebula_worker.main.POLL_HEARTBEAT", heartbeat):
        asyncio.run(
            run_loop(
                cast(AsyncEngine, engine),
                FakeRedis(None),
                FakeAdapter(),
                Settings(),
                iterations=1,
            )
        )

    assert "could not write the poll heartbeat" in caplog.text
