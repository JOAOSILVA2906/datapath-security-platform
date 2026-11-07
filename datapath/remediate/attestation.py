"""One-click retest + signed "remediated" attestation (spec 6.2).

Re-runs just ONE finding's check under the same scope and produces a signed,
timestamped attestation of the result. The attestation explicitly covers only
the specific check that was re-run (a liability bound from the review), not the
whole target.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class RetestResult(enum.Enum):
    REMEDIATED = "remediated"          # the check no longer fires
    STILL_PRESENT = "still_present"    # the issue is still there


@dataclass(frozen=True)
class RemediationAttestation:
    check_id: str
    affected_url: str
    scope_ref: str
    retest_scan_id: str
    result: RetestResult
    timestamp: str
    signature: str = ""

    # Explicit scope-of-coverage statement (review note).
    coverage: str = (
        "Cobre apenas a verificação reexecutada para este achado, neste alvo. "
        "Não atesta a segurança geral do sistema."
    )

    def _body(self) -> bytes:
        payload = {
            "check_id": self.check_id,
            "affected_url": self.affected_url,
            "scope_ref": self.scope_ref,
            "retest_scan_id": self.retest_scan_id,
            "result": self.result.value,
            "timestamp": self.timestamp,
            "coverage": self.coverage,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def signed(self, key: bytes) -> "RemediationAttestation":
        import dataclasses
        sig = hmac.new(key, self._body(), hashlib.sha256).hexdigest()
        return dataclasses.replace(self, signature=sig)

    def signature_valid(self, key: bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(key, self._body(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "affected_url": self.affected_url,
            "scope_ref": self.scope_ref,
            "retest_scan_id": self.retest_scan_id,
            "result": self.result.value,
            "timestamp": self.timestamp,
            "coverage": self.coverage,
            "signature": self.signature,
        }


class Retester:
    """Signs retest outcomes. ``runner`` re-runs just the one check and returns
    True if the issue is STILL present."""

    def __init__(self, signing_key: bytes) -> None:
        self._key = signing_key

    def retest(
        self,
        check_id: str,
        affected_url: str,
        scope_ref: str,
        scan_id: str,
        runner: Callable[[], bool],
        at: datetime | None = None,
    ) -> RemediationAttestation:
        still_present = bool(runner())
        result = (
            RetestResult.STILL_PRESENT if still_present else RetestResult.REMEDIATED
        )
        att = RemediationAttestation(
            check_id=check_id,
            affected_url=affected_url,
            scope_ref=scope_ref,
            retest_scan_id=scan_id,
            result=result,
            timestamp=(at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
        )
        return att.signed(self._key)
