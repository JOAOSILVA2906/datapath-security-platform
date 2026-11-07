"""DataPath Phase 0 — authorization & safety core.

Everything in the platform is subordinate to this package. No target may be
touched unless an active, verified AuthorizationGrant covers the exact asset
and intensity requested, and the PolicyEngine returns ALLOW. The engine is
default-deny and fails closed.

This package contains NO probing or scanning capability. It is only the gate.
"""

from .intensity import Intensity, SideEffectClass
from .scope import Asset, AssetKind, Exclusion, Scope, TestWindow
from .grant import AuthorizationGrant, GrantStatus, ProofMethod
from .allowlist import AllowList, ResolvedTarget, ResolutionError
from .policy import Decision, PolicyEngine, PolicyInput, PolicyResult
from .audit import AuditLog, AuditRecord
from .killswitch import KillSwitch, ScanState

__all__ = [
    "Intensity",
    "SideEffectClass",
    "Asset",
    "AssetKind",
    "Exclusion",
    "Scope",
    "TestWindow",
    "AuthorizationGrant",
    "GrantStatus",
    "ProofMethod",
    "AllowList",
    "ResolvedTarget",
    "ResolutionError",
    "Decision",
    "PolicyEngine",
    "PolicyInput",
    "PolicyResult",
    "AuditLog",
    "AuditRecord",
    "KillSwitch",
    "ScanState",
]
