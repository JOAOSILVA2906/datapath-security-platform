"""Policy engine — the single decision point (spec 2.2).

Every probe request is a policy query: *is this target, at this intensity, at
this time, under this grant, with this side-effect class, allowed?* The answer
is default-DENY and the engine fails CLOSED — any error, any missing input, any
unexpected condition yields DENY, never ALLOW (review fix #7).

The engine composes the Phase-0 primitives in a fixed order and returns the
first failing reason, so decisions are explainable and auditable. It touches no
network itself; the caller passes an already-resolved, pinned target.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .allowlist import ResolvedTarget
from .audit import AuditLog
from .grant import AuthorizationGrant
from .intensity import Intensity, SideEffectClass, side_effect_permitted
from .killswitch import KillSwitch
from .scope import Scope


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyInput:
    scope: Scope
    grant: AuthorizationGrant
    target: ResolvedTarget
    requested_intensity: Intensity
    side_effect: SideEffectClass
    scan_id: str
    param: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    checks: tuple[str, ...] = ()  # names of checks that passed, in order

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


class PolicyEngine:
    def __init__(
        self,
        signing_key: bytes,
        kill_switch: KillSwitch,
        audit: AuditLog | None = None,
    ) -> None:
        self._key = signing_key
        self._kill = kill_switch
        self._audit = audit

    def evaluate(self, pin: PolicyInput) -> PolicyResult:
        try:
            return self._evaluate(pin)
        except Exception as exc:  # fail closed on ANY unexpected condition
            result = PolicyResult(Decision.DENY, f"policy error (fail-closed): {exc!r}")
            self._record(pin, result)
            return result

    def _evaluate(self, pin: PolicyInput) -> PolicyResult:
        passed: list[str] = []

        def deny(reason: str) -> PolicyResult:
            result = PolicyResult(Decision.DENY, reason, tuple(passed))
            self._record(pin, result)
            return result

        at = pin.at.astimezone(timezone.utc)

        # 1. Kill switch — authoritative, checked first and last-mile.
        if self._kill.global_halted:
            return deny("global kill switch engaged")
        if not self._kill.scan_may_probe(pin.scan_id, at):
            return deny("scan not in RUNNING state (aborted/paused/unknown)")
        passed.append("kill_switch")

        # 2. Grant validity (signature, status, scope binding, wildcard cover).
        ok, why = pin.grant.is_valid_for(pin.scope, at, self._key)
        if not ok:
            return deny(f"grant invalid: {why}")
        passed.append("grant_valid")

        # 3. Time window.
        if not pin.scope.in_window(at):
            return deny("outside test window")
        passed.append("test_window")

        # 4. Intensity ceiling: request <= scope ceiling AND <= grant ceiling.
        if pin.requested_intensity > pin.scope.intensity_ceiling:
            return deny("requested intensity exceeds scope ceiling")
        if pin.requested_intensity > pin.grant.max_intensity:
            return deny("requested intensity exceeds grant ceiling")
        passed.append("intensity_ceiling")

        # 5. Side-effect class permitted at the requested intensity.
        #    POTENTIALLY_MUTATING is refused at every tier by the taxonomy.
        if not side_effect_permitted(pin.requested_intensity, pin.side_effect):
            return deny(
                f"side-effect class {pin.side_effect.name} not permitted at "
                f"{pin.requested_intensity.name}"
            )
        passed.append("side_effect_class")

        # 6. Target scope membership (exclusions win) — on the pinned target.
        host = pin.target.host
        if pin.scope.is_excluded(host, _path_of(pin.target.url), pin.param):
            return deny("target excluded by scope")
        if not pin.scope.includes_url(pin.target.url):
            return deny("target url not in scope")
        passed.append("target_in_scope")

        result = PolicyResult(Decision.ALLOW, "", tuple(passed))
        self._record(pin, result)
        return result

    def _record(self, pin: PolicyInput, result: PolicyResult) -> None:
        if self._audit is None:
            return
        self._audit.append(
            "policy_decision",
            {
                "scan_id": pin.scan_id,
                "scope_ref": pin.scope.ref,
                "grant_id": pin.grant.grant_id,
                "host": pin.target.host,
                "pinned_ip": pin.target.pinned_ip,
                "port": pin.target.port,
                "requested_intensity": pin.requested_intensity.name,
                "side_effect": pin.side_effect.name,
                "decision": result.decision.value,
                "reason": result.reason,
                "checks_passed": list(result.checks),
            },
        )


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path or "/"
