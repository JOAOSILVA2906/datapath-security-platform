"""The sensitive-boundary model and the hard stop condition (spec 5.2).

A path is pursued only up to — and never past — the first sensitive boundary:
any point where the next action would read real sensitive data beyond a
minimal masked existence proof, cross a tenant/user isolation boundary into
real data, mutate state, or require a destructive/exfiltrating action.

At the boundary the engine HALTS, captures a minimal masked proof that the
boundary was reachable, records the chain, and marks the path
**confirmed-reachable, not-exploited**. It never pulls the data behind the
boundary. This module defines that proof; the active confirmers enforce the
stop by construction (one request, then stop — they never enumerate).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class BoundaryKind(enum.Enum):
    CROSS_TENANT_READ = "cross_tenant_read"      # reached another tenant's object
    VERTICAL_PRIVILEGE = "vertical_privilege"    # low-priv reached privileged fn
    SENSITIVE_DATA = "sensitive_data"            # reached regulated/PII surface
    STATE_MUTATION = "state_mutation"            # next step would change state
    DESTRUCTIVE = "destructive"                  # next step would destroy/exfil


@dataclass(frozen=True)
class BoundaryProof:
    """Minimal, masked evidence that a boundary was REACHABLE, not crossed.

    ``evidence`` is a short human sentence containing only masked indicators
    (a count, a masked id) — never the data behind the boundary.
    """

    kind: BoundaryKind
    evidence: str
    reachable: bool = True
    exploited: bool = False  # always False by design — we stop at the boundary

    def __post_init__(self) -> None:
        if self.exploited:
            raise ValueError(
                "BoundaryProof.exploited must be False: the engine stops at the "
                "boundary and never realises the harm"
            )

    def to_dict(self) -> dict:
        return {
            "boundary": self.kind.value,
            "evidence": self.evidence,
            "reachable": self.reachable,
            "exploited": self.exploited,
            "status": "confirmed-reachable, not-exploited",
        }


def mask(value: str, keep: int = 4) -> str:
    """Mask an identifier for proof, keeping only a short prefix."""
    value = str(value)
    if len(value) <= keep:
        return "…"
    return value[:keep] + "…"
