"""Hash-chained audit log export, and its verification.

Each exported line is one audit event plus `prev` (the previous line's hash)
and `hash` = SHA-256 of `prev` followed by the event's canonical JSON. The
last line names the head hash and the count. Changing, removing, reordering
or inserting an event anywhere breaks every hash after it, so an export kept
off the server proves what the log held: a later export must contain it
unchanged (`verify_extends`).
"""

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

from nebula_api.audit.service import AuditLogEntry

FORMAT = "nebula-audit-chain/1"
GENESIS = "0" * 64


class AuditChainError(ValueError):
    """The export is not an intact chain, or does not extend the older one."""


@dataclass(frozen=True, slots=True)
class ChainSummary:
    count: int
    head: str
    until: str
    hashes: tuple[str, ...]


def _canonical(entry: AuditLogEntry) -> dict[str, str | None]:
    def text(value: object) -> str | None:
        return None if value is None else str(value)

    return {
        "id": str(entry.id),
        "recorded_at": entry.recorded_at.isoformat(),
        "actor_kind": entry.actor_kind,
        "actor_id": text(entry.actor_id),
        "target_kind": entry.target_kind,
        "target_id": str(entry.target_id),
        "event_code": entry.event_code,
        "outcome": entry.outcome,
        "reason_code": entry.reason_code,
        "request_id": text(entry.request_id),
    }


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _link(prev: str, event: dict[str, str | None]) -> str:
    return hashlib.sha256((prev + _dump(event)).encode()).hexdigest()


def chain_lines(entries: Iterable[AuditLogEntry], *, until: datetime) -> Iterator[str]:
    """Newline-terminated export lines for `entries`, oldest first."""

    prev, count = GENESIS, 0
    for entry in entries:
        event = _canonical(entry)
        digest = _link(prev, event)
        yield _dump({**event, "prev": prev, "hash": digest}) + "\n"
        prev, count = digest, count + 1
    yield _dump({"format": FORMAT, "count": count, "head": prev, "until": until.isoformat()}) + "\n"


def verify(lines: Iterable[str]) -> ChainSummary:
    """Recompute every link; raise AuditChainError on the first break."""

    prev, hashes = GENESIS, []
    trailer: dict[str, object] | None = None
    for number, line in enumerate((line for line in lines if line.strip()), start=1):
        if trailer is not None:
            raise AuditChainError(f"line {number}: events after the closing line")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise AuditChainError(f"line {number}: not JSON") from error
        if not isinstance(record, dict):
            raise AuditChainError(f"line {number}: not an object")
        if "format" in record:
            trailer = record
            continue
        claimed_prev, claimed = record.pop("prev", None), record.pop("hash", None)
        if claimed_prev != prev or claimed != _link(prev, record):
            raise AuditChainError(
                f"line {number}: the chain breaks here (event {record.get('id')})"
            )
        prev = claimed
        hashes.append(claimed)
    if trailer is None or trailer.get("format") != FORMAT:
        raise AuditChainError("no closing line: the export is cut short")
    if trailer.get("count") != len(hashes) or trailer.get("head") != prev:
        raise AuditChainError("the closing line does not match the events")
    return ChainSummary(len(hashes), prev, str(trailer.get("until")), tuple(hashes))


def verify_extends(older: Iterable[str], newer: Iterable[str]) -> ChainSummary:
    """Both exports intact, and the newer one holds the older one unchanged."""

    old, new = verify(older), verify(newer)
    if old.count and (new.count < old.count or new.hashes[old.count - 1] != old.head):
        raise AuditChainError(
            f"the newer export does not contain the older one's {old.count} events unchanged"
        )
    return new
