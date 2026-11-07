"""DataPath Phase 2 — active confirmation with a hard stop-at-boundary.

Opt-in, bounded confirmation of the highest-value classes (BOLA / broken
access control, vertical privilege). Every probe runs through the Phase-0 gate
in ACTIVE mode, which requires the scope ceiling and grant to permit ACTIVE and
a per-scan confirmation. Each confirmer sends ONE read-only request and stops
at the first sensitive boundary, capturing masked proof — never the data.
"""

from .boundary import BoundaryKind, BoundaryProof, mask
from .active import ActiveConfirmer, Confirmation

__all__ = [
    "BoundaryKind",
    "BoundaryProof",
    "mask",
    "ActiveConfirmer",
    "Confirmation",
]
