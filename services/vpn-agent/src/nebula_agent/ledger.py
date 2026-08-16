"""On-disk idempotency ledger: a local duplicate-apply guard for retried
requests.

Not a source of truth -- the control plane's `agent_operations` table is --
this only protects the agent itself against re-running a driver method for a
request it already handled, especially across a process restart, which is
exactly when retry storms are most likely.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from uuid import UUID


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    idempotency_key: str
    operation_kind: str
    target_id: str
    applied_generation: int
    response_json: str


class OperationLedger:
    """Append-only JSON-Lines file, replayed into memory at startup."""

    def __init__(self, path: PurePosixPath, max_entries: int) -> None:
        self._path = Path(str(path))
        self._max_entries = max_entries
        self._entries: dict[str, LedgerEntry] = {}
        self._order: list[str] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text().splitlines():
            if not line.strip():
                continue
            entry = LedgerEntry(**json.loads(line))
            if entry.idempotency_key not in self._entries:
                self._order.append(entry.idempotency_key)
            self._entries[entry.idempotency_key] = entry

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
