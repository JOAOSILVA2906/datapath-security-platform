"""Tamper-evident audit log (spec 1.8).

Append-only, hash-chained. Each record carries the hash of the previous record,
so any edit or deletion in the middle breaks the chain from that point on and
is detectable by ``verify()``.

Review fix: records store probe METADATA and hashes only — never request or
response bodies. Keeping bodies in an immutable, undeletable log would pull PII
into a store you cannot erase from, conflicting with GDPR erasure. Evidence
bodies live in the separate (erasable, encrypted) evidence store; the audit log
references them by hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str = ""

    def compute_hash(self) -> str:
        body = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


class AuditLog:
    """In-memory hash-chained log.

    Production would persist to WORM storage with periodic anchoring; the chain
    semantics and verification are identical and live here.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditRecord:
        if _looks_like_body(payload):
            raise ValueError(
                "audit payload appears to contain a raw request/response body; "
                "log metadata and hashes only"
            )
        seq = len(self._records)
        prev = self._records[-1].record_hash if self._records else GENESIS
        rec = AuditRecord(
            seq=seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            payload=dict(payload),
            prev_hash=prev,
        )
        rec = AuditRecord(**{**rec.__dict__, "record_hash": rec.compute_hash()})
        self._records.append(rec)
        return rec

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def verify(self) -> tuple[bool, int | None]:
        """Verify the whole chain.

        Returns (ok, first_bad_seq). ``first_bad_seq`` is None when intact.
        """
        prev = GENESIS
        for rec in self._records:
            if rec.prev_hash != prev:
                return False, rec.seq
            if rec.record_hash != rec.compute_hash():
                return False, rec.seq
            prev = rec.record_hash
        return True, None


# Keys that would signal someone is trying to stuff a body into the audit log.
_BODY_KEYS = frozenset(
    {"body", "response_body", "request_body", "raw", "content", "snippet"}
)


def _looks_like_body(payload: dict[str, Any]) -> bool:
    return any(k in payload for k in _BODY_KEYS)
