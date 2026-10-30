"""On-disk idempotency ledger: a local duplicate-apply guard for retried
requests.

Not a source of truth -- the control plane's `agent_operations` table is --
this only protects the agent itself against re-running a driver method for a
request it already handled, especially across a process restart, which is
exactly when retry storms are most likely.
"""

import json
import logging
from dataclasses import asdict, dataclass, fields
from pathlib import Path, PurePosixPath
from uuid import UUID

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    idempotency_key: str
    operation_kind: str
    target_id: str
    applied_generation: int
    response_json: str


def _parse_entry(line: str) -> LedgerEntry | None:
    """Return the entry this line encodes, or None if it is unusable."""

    try:
        payload = json.loads(line)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    expected = {field.name for field in fields(LedgerEntry)}
    if set(payload) != expected:
        return None
    # The exact field-set match above is what makes this construction safe:
    # LedgerEntry is an unvalidated dataclass, so with the right keys present
    # it cannot raise, and a wrong-typed value would have to come from a
    # hand-edited ledger. Entries are re-serialized on compaction anyway.
    return LedgerEntry(**payload)


class OperationLedger:
    """Append-only JSON-Lines file, replayed into memory at startup."""

    def __init__(self, path: PurePosixPath, max_entries: int) -> None:
        self._path = Path(str(path))
        self._max_entries = max_entries
        self._entries: dict[str, LedgerEntry] = {}
        self._order: list[str] = []
        self._load()

    def _load(self) -> None:
        """Replay the ledger, skipping any line that cannot be parsed.

        A process killed mid-append leaves a truncated final line, and a file
        written by a version with different fields leaves unknown keys. Either
        would abort startup if it propagated -- permanently bricking the agent
        for exactly the crash-restart case this ledger exists to survive.
        Dropping an unreadable entry only risks re-applying one operation,
        which the control plane's `agent_operations` table already guards, so
        it is strictly better than refusing to start.
        """

        if not self._path.exists():
            return
        skipped = 0
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            entry = _parse_entry(line)
            if entry is None:
                skipped += 1
                continue
            if entry.idempotency_key not in self._entries:
                self._order.append(entry.idempotency_key)
            self._entries[entry.idempotency_key] = entry
        if skipped:
            _LOGGER.warning("Skipped %d unreadable idempotency ledger entry/entries", skipped)

    def lookup(self, idempotency_key: UUID) -> LedgerEntry | None:
        return self._entries.get(str(idempotency_key))

    def record(
        self,
        *,
        idempotency_key: UUID,
        operation_kind: str,
        target_id: UUID,
        applied_generation: int,
        response_json: str,
    ) -> None:
        entry = LedgerEntry(
            idempotency_key=str(idempotency_key),
            operation_kind=operation_kind,
            target_id=str(target_id),
            applied_generation=applied_generation,
            response_json=response_json,
        )
        if entry.idempotency_key not in self._entries:
            self._order.append(entry.idempotency_key)
        self._entries[entry.idempotency_key] = entry
        self._append_to_disk(entry)
        self._compact_if_needed()

    def _append_to_disk(self, entry: LedgerEntry) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as handle:
            handle.write(json.dumps(asdict(entry)) + "\n")

    def _compact_if_needed(self) -> None:
        if len(self._order) <= self._max_entries:
            return
        overflow = len(self._order) - self._max_entries
        for key in self._order[:overflow]:
            self._entries.pop(key, None)
        self._order = self._order[overflow:]
        self._rewrite()

    def _rewrite(self) -> None:
        tmp_path = self._path.with_name(self._path.name + ".compact")
        with tmp_path.open("w") as handle:
            for key in self._order:
                handle.write(json.dumps(asdict(self._entries[key])) + "\n")
        tmp_path.replace(self._path)
