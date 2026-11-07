"""Two-person control for sensitive changes (review fix #7).

The platform holds test credentials for many customers and can point a scanner
fleet at their assets, so a single malicious or compromised operator is a top
threat. Changes that widen what may be tested — editing an allow-list, relaxing
a policy, raising an intensity ceiling, overriding an ownership verdict — must
be approved by at least a second, distinct person before they take effect.

This module is the mechanism, not the policy of *which* changes need it; the
caller marks a change as requiring dual control and routes it through here.
Every state transition is meant to be mirrored into the audit log by the caller.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class ChangeStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class DualControlError(Exception):
    pass


def _hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class ChangeRequest:
    """A proposed sensitive change awaiting approval.

    Mutable by design, but only through DualControl, which enforces the rules.
    """

    request_id: str
    kind: str                      # e.g. "allowlist.add", "policy.relax"
    payload: dict[str, Any]
    requested_by: str
    created_at: datetime
    min_approvals: int = 1         # approvals REQUIRED beyond the requester
    status: ChangeStatus = ChangeStatus.PENDING
    approvals: tuple[str, ...] = ()
    rejected_by: str | None = None
    payload_hash: str = ""

    def __post_init__(self) -> None:
        if self.min_approvals < 1:
            raise ValueError("sensitive changes need at least one approver")
        if not self.payload_hash:
            self.payload_hash = _hash_payload(self.payload)

    @property
    def is_approved(self) -> bool:
        return self.status is ChangeStatus.APPROVED


class DualControl:
    """Registry enforcing four-eyes approval on sensitive changes."""

    def __init__(self, default_min_approvals: int = 1) -> None:
        if default_min_approvals < 1:
            raise ValueError("default_min_approvals must be >= 1")
        self._default = default_min_approvals
        self._requests: dict[str, ChangeRequest] = {}

    def request(
        self,
        request_id: str,
        kind: str,
        payload: dict[str, Any],
        requested_by: str,
        min_approvals: int | None = None,
        at: datetime | None = None,
    ) -> ChangeRequest:
        if request_id in self._requests:
            raise DualControlError(f"request {request_id!r} already exists")
        req = ChangeRequest(
            request_id=request_id,
            kind=kind,
            payload=dict(payload),
            requested_by=requested_by,
            created_at=(at or datetime.now(timezone.utc)).astimezone(timezone.utc),
            min_approvals=self._default if min_approvals is None else min_approvals,
        )
        self._requests[request_id] = req
        return req

    def approve(self, request_id: str, approver: str) -> ChangeRequest:
        req = self._get(request_id)
        if req.status is not ChangeStatus.PENDING:
            raise DualControlError(f"request is {req.status.value}, cannot approve")
        if approver == req.requested_by:
            raise DualControlError("requester cannot approve their own change")
        if approver in req.approvals:
            raise DualControlError(f"{approver!r} already approved this change")
        req.approvals = req.approvals + (approver,)
        if len(req.approvals) >= req.min_approvals:
            req.status = ChangeStatus.APPROVED
        return req

    def reject(self, request_id: str, approver: str) -> ChangeRequest:
        req = self._get(request_id)
        if req.status not in (ChangeStatus.PENDING,):
            raise DualControlError(f"request is {req.status.value}, cannot reject")
        req.status = ChangeStatus.REJECTED
        req.rejected_by = approver
        return req

    def apply(self, request_id: str) -> ChangeRequest:
        """Mark an approved change applied. Caller performs the real mutation
        only after this returns successfully."""
        req = self._get(request_id)
        if req.status is not ChangeStatus.APPROVED:
            raise DualControlError(
                f"cannot apply: request is {req.status.value}, not approved"
            )
        req.status = ChangeStatus.APPLIED
        return req

    def get(self, request_id: str) -> ChangeRequest:
        return self._get(request_id)

    def _get(self, request_id: str) -> ChangeRequest:
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise DualControlError(f"unknown request {request_id!r}") from exc
