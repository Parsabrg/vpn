"""Pruning's own logic, without a database.

The SQL these statements produce is proved against real PostgreSQL in
test_retention_integration.py. What is asserted here is what a scripted
session can show and a live one would hide in timing: that the passes run in
the order the foreign keys require, that a large table is deleted in bounded
batches rather than one statement, and that a credential which is not
allowed to delete produces a reported refusal rather than an exception or a
silent success.
"""

import asyncio
from typing import Any, cast

import pytest
from sqlalchemy.exc import ProgrammingError

from nebula_api.db.engine import SessionFactory
from nebula_api.retention import PruneSummary, RetentionPolicy, prune_history


class _Result:
    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _Rows:
    def __init__(self, values: list[object]) -> None:
        self._values = values

    def all(self) -> list[object]:
        return self._values


class _Session:
    """One scripted session. `batches` is what each `scalars` call returns."""

    def __init__(self, recorder: "_Recorder") -> None:
        self._recorder = recorder

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def scalars(self, statement: Any) -> _Rows:
        return _Rows(self._recorder.next_batch(statement))

    async def execute(self, statement: Any) -> _Result:
        return self._recorder.delete(statement)

    async def commit(self) -> None:
        self._recorder.commits += 1


class _Recorder:
    def __init__(
        self,
        *,
        rows_per_table: dict[str, list[int]] | None = None,
        refuse: str | None = None,
    ) -> None:
        self.rows_per_table = rows_per_table or {}
        self.refuse = refuse
        self.tables_seen: list[str] = []
        self.commits = 0
        self._pending: list[object] = []

    def __call__(self) -> _Session:
        return _Session(self)

    def next_batch(self, statement: Any) -> list[object]:
        table = _table_of(statement)
        if not self.tables_seen or self.tables_seen[-1] != table:
            self.tables_seen.append(table)
        remaining = self.rows_per_table.get(table, [])
        count = remaining.pop(0) if remaining else 0
        self._pending = [object() for _ in range(count)]
        return list(self._pending)

    def delete(self, statement: Any) -> _Result:
        table = _table_of(statement)
        if self.refuse == table:
            raise ProgrammingError("delete", {}, Exception("permission denied for table " + table))
        return _Result(len(self._pending))


def _table_of(statement: Any) -> str:
    """The table a select or delete is against.

    A delete names its table directly; a select has to be asked for the
    tables it ended up selecting from.
    """

    target = getattr(statement, "table", None)
    if target is not None:
        return str(target.name)
    return str(statement.get_final_froms()[0].name)


def _prune(recorder: _Recorder, **kwargs: Any) -> PruneSummary:
    return asyncio.run(prune_history(cast(SessionFactory, recorder), **kwargs))


def test_the_passes_run_in_the_order_the_foreign_keys_require() -> None:
    """`reconciliation_records.agent_operation_id` references
    `agent_operations` with ON DELETE RESTRICT, so the records have to be
    gone before the operations are attempted."""

    recorder = _Recorder()

    _prune(recorder)

    assert recorder.tables_seen.index("reconciliation_records") < recorder.tables_seen.index(
        "agent_operations"
    )
    assert set(recorder.tables_seen) == {
        "reconciliation_records",
        "server_health",
        "email_deliveries",
        "agent_operations",
        "audit_logs",
    }


def test_a_large_table_is_deleted_in_committed_batches() -> None:
    """Sessions run under a five-second statement timeout, and a first prune
    can be far more rows than that allows in one statement."""

    recorder = _Recorder(rows_per_table={"audit_logs": [2_000, 2_000, 137]})

    summary = _prune(recorder)

    assert summary.deleted["audit_logs"] == 4_137
    assert summary.total_deleted == 4_137
    # One commit per batch, so the work is interruptible and never holds a
    # long lock on a table the API is still writing to.
    assert recorder.commits == 3


def test_a_short_batch_ends_the_pass() -> None:
    recorder = _Recorder(rows_per_table={"server_health": [5]})

    summary = _prune(recorder)

    assert summary.deleted["server_health"] == 5
    assert recorder.commits == 1


def test_a_refused_delete_is_reported_and_the_other_tables_still_run() -> None:
    """The application role holds INSERT and SELECT on `audit_logs` and
    nothing else, by design. Pruning under it must say so rather than raise,
    or the operational tables it *can* prune would keep growing."""

    recorder = _Recorder(
        rows_per_table={"audit_logs": [10], "server_health": [4]}, refuse="audit_logs"
    )

    summary = _prune(recorder)

    assert "audit_logs" not in summary.deleted
    assert "permission denied" in summary.refused["audit_logs"]
    assert summary.deleted["server_health"] == 4


def test_a_retention_period_shorter_than_a_day_is_refused() -> None:
    with pytest.raises(ValueError):
        RetentionPolicy(audit_days=0)
    with pytest.raises(ValueError):
        RetentionPolicy(operational_days=-1)


def test_the_default_policy_is_the_one_the_threat_model_states() -> None:
    policy = RetentionPolicy()

    assert policy.audit_days == 365
    assert policy.operational_days == 90
