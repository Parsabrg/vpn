from pathlib import Path, PurePosixPath
from uuid import uuid4

from nebula_agent.ledger import OperationLedger


def _store(tmp_path: Path, max_entries: int = 100) -> OperationLedger:
    return OperationLedger(PurePosixPath(str(tmp_path / "ledger.jsonl")), max_entries)


def test_lookup_returns_none_for_an_unknown_key(tmp_path: Path) -> None:
    ledger = _store(tmp_path)
    assert ledger.lookup(uuid4()) is None


def test_record_then_lookup_round_trips(tmp_path: Path) -> None:
    ledger = _store(tmp_path)
    key = uuid4()
    target_id = uuid4()

    ledger.record(
        idempotency_key=key,
        operation_kind="provision_device",
        target_id=target_id,
        applied_generation=1,
        response_json='{"state": "active"}',
    )

    entry = ledger.lookup(key)
    assert entry is not None
    assert entry.operation_kind == "provision_device"
    assert entry.target_id == str(target_id)
    assert entry.applied_generation == 1
    assert entry.response_json == '{"state": "active"}'


def test_recording_the_same_key_again_overwrites_the_entry(tmp_path: Path) -> None:
    ledger = _store(tmp_path)
    key = uuid4()
    target_id = uuid4()

    ledger.record(
        idempotency_key=key,
        operation_kind="provision_device",
        target_id=target_id,
        applied_generation=1,
        response_json="{}",
    )
    ledger.record(
        idempotency_key=key,
        operation_kind="provision_device",
        target_id=target_id,
        applied_generation=2,
        response_json="{}",
    )

    assert ledger.lookup(key).applied_generation == 2  # type: ignore[union-attr]


def test_a_fresh_ledger_instance_reloads_entries_from_disk(tmp_path: Path) -> None:
    key = uuid4()
    target_id = uuid4()
    first = _store(tmp_path)
    first.record(
        idempotency_key=key,
        operation_kind="revoke_device",
        target_id=target_id,
        applied_generation=1,
        response_json='{"state": "revoked"}',
    )

    reloaded = _store(tmp_path)
    entry = reloaded.lookup(key)
    assert entry is not None
    assert entry.operation_kind == "revoke_device"


def test_compaction_drops_the_oldest_entries_once_the_limit_is_exceeded(
    tmp_path: Path,
) -> None:
    ledger = _store(tmp_path, max_entries=3)
    keys = [uuid4() for _ in range(5)]
    for index, key in enumerate(keys):
        ledger.record(
            idempotency_key=key,
            operation_kind="provision_device",
            target_id=uuid4(),
            applied_generation=index,
            response_json="{}",
        )

    assert ledger.lookup(keys[0]) is None
    assert ledger.lookup(keys[1]) is None
    assert ledger.lookup(keys[2]) is not None
    assert ledger.lookup(keys[3]) is not None
    assert ledger.lookup(keys[4]) is not None


def test_compaction_persists_to_disk(tmp_path: Path) -> None:
    ledger = _store(tmp_path, max_entries=2)
    keys = [uuid4() for _ in range(4)]
    for key in keys:
        ledger.record(
            idempotency_key=key,
            operation_kind="provision_device",
            target_id=uuid4(),
            applied_generation=0,
            response_json="{}",
        )

    reloaded = _store(tmp_path, max_entries=2)
    assert reloaded.lookup(keys[0]) is None
    assert reloaded.lookup(keys[-1]) is not None
