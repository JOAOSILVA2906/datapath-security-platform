"""DataPath Phase 3 — attack-path chaining.

Composes individual findings (modelled as capabilities) into realistic attack
paths toward sensitive data, ranked by reachability-weighted risk, each ending
at the first sensitive boundary (stop condition). No network: this reasons over
the data-path graph and the findings produced by Phases 1-2.
"""

from .capability import (
    SENSITIVE_STATES,
    START_ANONYMOUS,
    START_LOW_PRIV,
    Capability,
    capability_from_bola,
    capability_from_vertical_privilege,
    enumeration_capability,
    recon_capability,
)
from .planner import AttackPath, AttackPathPlanner

__all__ = [
    "SENSITIVE_STATES",
    "START_ANONYMOUS",
    "START_LOW_PRIV",
    "Capability",
    "capability_from_bola",
    "capability_from_vertical_privilege",
    "enumeration_capability",
    "recon_capability",
    "AttackPath",
    "AttackPathPlanner",
]
