from pathlib import Path, PurePosixPath
from uuid import UUID, uuid4

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


def test_a_truncated_final_line_does_not_prevent_startup(tmp_path: Path) -> None:
    """A process killed mid-append leaves partial JSON. Refusing to start
    would brick the agent for exactly the crash-restart case this ledger
    exists to survive, so the bad line is dropped instead."""

    ledger = _store(tmp_path)
    good_key = uuid4()
    ledger.record(
        idempotency_key=good_key,
        operation_kind="provision_device",
        target_id=uuid4(),
        applied_generation=1,
        response_json='{"state": "active"}',
    )
    path = tmp_path / "ledger.jsonl"
    with path.open("a") as handle:
        handle.write('{"idempotency_key": "partial-write-cut-off')

    reloaded = _store(tmp_path)

    assert reloaded.lookup(good_key) is not None


def test_entries_with_unexpected_fields_are_skipped(tmp_path: Path) -> None:
    """A ledger written by a build with different fields must not abort
    startup either -- LedgerEntry(**payload) would raise on an unknown key."""

    path = tmp_path / "ledger.jsonl"
    path.write_text(
        '{"idempotency_key": "k1", "operation_kind": "provision_device", '
        '"target_id": "t1", "applied_generation": 1, "response_json": "{}", '
        '"field_from_the_future": true}\n'
        '{"idempotency_key": "k2", "operation_kind": "revoke_device"}\n'
        "not json at all\n"
        "[1, 2, 3]\n"
    )

    # Constructing at all is the property under test: every line above is
    # unusable, so this must load empty rather than raise.
    ledger = _store(tmp_path)

    assert ledger.lookup(uuid4()) is None
    # The ledger stays usable afterwards rather than being wedged.
    fresh_key = uuid4()
    ledger.record(
        idempotency_key=fresh_key,
        operation_kind="provision_device",
        target_id=uuid4(),
        applied_generation=1,
        response_json="{}",
    )
    assert _store(tmp_path).lookup(fresh_key) is not None


def test_a_recoverable_ledger_still_replays_good_entries_after_bad_ones(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text(
        "corrupt\n"
        '{"idempotency_key": "11111111-1111-4111-8111-111111111111", '
        '"operation_kind": "provision_device", "target_id": "t1", '
        '"applied_generation": 2, "response_json": "{}"}\n'
    )

    ledger = _store(tmp_path)

    entry = ledger.lookup(UUID("11111111-1111-4111-8111-111111111111"))
    assert entry is not None
    assert entry.applied_generation == 2
