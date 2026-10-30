import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from nebula_api.audit.chain import (
    GENESIS,
    AuditChainError,
    chain_lines,
    verify,
    verify_extends,
)
from nebula_api.audit.service import AuditLogEntry
from nebula_api.cli import main

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def entry(minute: int, *, outcome: str = "success") -> AuditLogEntry:
    return AuditLogEntry(
        id=uuid4(),
        actor_kind="admin",
        actor_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        target_kind="user",
        target_id=uuid4(),
        event_code="user.disabled",
        outcome=outcome,
        reason_code=None,
        request_id=None,
        recorded_at=NOW + timedelta(minutes=minute),
    )


def export(entries: list[AuditLogEntry]) -> list[str]:
    return list(chain_lines(entries, until=NOW + timedelta(hours=1)))


def test_an_intact_export_verifies() -> None:
    lines = export([entry(1), entry(2), entry(3)])
    summary = verify(lines)
    assert summary.count == 3
    assert summary.head == json.loads(lines[2])["hash"]
    assert json.loads(lines[0])["prev"] == GENESIS


def test_an_empty_log_exports_and_verifies() -> None:
    summary = verify(export([]))
    assert (summary.count, summary.head) == (0, GENESIS)


@pytest.mark.parametrize(
    "tamper",
    [
        lambda lines: [lines[0].replace('"success"', '"failure"'), *lines[1:]],
        lambda lines: [lines[0], *lines[2:]],
        lambda lines: [lines[1], lines[0], *lines[2:]],
        lambda lines: lines[:-1],
        lambda lines: [*lines[:-1], lines[-1].replace('"count":3', '"count":2')],
        lambda lines: [*lines, lines[0]],
        lambda lines: ["not json", *lines],
        lambda lines: ["[1]", *lines],
    ],
    ids=["edited", "removed", "reordered", "cut-short", "count", "after-close", "garbage", "array"],
)
def test_any_change_is_caught(tamper) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AuditChainError):
        verify(tamper(export([entry(1), entry(2), entry(3)])))


def test_a_newer_export_must_hold_the_older_one_unchanged() -> None:
    events = [entry(1), entry(2)]
    older = export(events)
    assert verify_extends(older, export([*events, entry(3)])).count == 3

    rewritten = [events[0], entry(2, outcome="failure"), entry(3)]
    with pytest.raises(AuditChainError, match="unchanged"):
        verify_extends(older, export(rewritten))
    with pytest.raises(AuditChainError, match="unchanged"):
        verify_extends(older, export(events[:1]))
    assert verify_extends(export([]), older).count == 2


def test_audit_verify_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    events = [entry(1), entry(2)]
    old, new = tmp_path / "old.jsonl", tmp_path / "new.jsonl"
    old.write_text("".join(export(events)), encoding="utf-8")
    new.write_text("".join(export([*events, entry(3)])), encoding="utf-8")

    assert main(["audit-verify", str(new)]) == 0
    assert "intact: 3 events" in capsys.readouterr().out
    assert main(["audit-verify", str(new), "--extends", str(old)]) == 0
    assert "contains" in capsys.readouterr().out

    with pytest.raises(SystemExit):
        main(["audit-verify", str(old), "--extends", str(new)])
    assert "unchanged" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["audit-verify", str(tmp_path / "missing.jsonl")])
    assert "cannot read" in capsys.readouterr().err
