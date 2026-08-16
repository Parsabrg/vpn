import asyncio
from typing import cast
from unittest.mock import AsyncMock, patch
from uuid import uuid4

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
