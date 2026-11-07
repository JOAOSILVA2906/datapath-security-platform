"""Rate limiting, concurrency, budgets, and adaptive backpressure (spec 1.5).

A stressed target must never be hammered harder: the limiter treats 5xx spikes,
elevated latency, WAF challenges, 429s and ``Retry-After`` as "slow down".

Design goals:
  * conservative defaults with a hard ceiling customers cannot exceed without
    elevated approval;
  * per-target request-rate caps (token bucket) and max concurrency;
  * global and per-tenant request budgets so one engagement can't starve the
    fleet;
  * adaptive throttling (AIMD): multiplicative decrease on trouble, slow
    additive recovery;
  * honours an explicit cooldown from 429 / Retry-After.

Deterministic and thread-free: the current time is passed in as ``now`` (a float
monotonic-seconds value), matching the injected-clock style of the rest of the
core. No network, no sleeping.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


# Fleet-wide hard ceilings. Config above these requires elevated approval.
HARD_MAX_RPS = 50.0
HARD_MAX_CONCURRENCY = 20


class DenyReason(enum.Enum):
    RATE = "rate_exceeded"
    CONCURRENCY = "concurrency_exceeded"
    COOLDOWN = "cooldown_active"
    TENANT_BUDGET = "tenant_budget_exhausted"
    GLOBAL_BUDGET = "global_budget_exhausted"


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: DenyReason | None = None
    retry_after: float = 0.0  # seconds the caller should wait before retrying

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class RateLimitConfig:
    rps: float = 2.0                 # sustained requests/sec per target
    burst: int = 5                   # token-bucket capacity
    max_concurrency: int = 4         # simultaneous in-flight per target
    # Adaptive bounds: effective rate = rps * factor, factor in [min_factor, 1].
    min_factor: float = 0.1
    decrease: float = 0.5            # multiply factor by this on trouble
    increase: float = 0.05           # add this to factor per good response
    latency_ceiling: float = 2.0     # seconds; above this counts as trouble
    elevated: bool = False           # set only via approved elevation

    def __post_init__(self) -> None:
        if self.rps <= 0 or self.burst <= 0 or self.max_concurrency <= 0:
            raise ValueError("rate/burst/concurrency must be positive")
        if not self.elevated:
            if self.rps > HARD_MAX_RPS:
                raise ValueError(
                    f"rps {self.rps} exceeds hard ceiling {HARD_MAX_RPS}; "
                    f"needs elevated approval"
                )
            if self.max_concurrency > HARD_MAX_CONCURRENCY:
                raise ValueError(
                    f"concurrency {self.max_concurrency} exceeds hard ceiling "
                    f"{HARD_MAX_CONCURRENCY}; needs elevated approval"
                )
        if not (0 < self.min_factor <= 1):
            raise ValueError("min_factor must be in (0, 1]")


class _TargetState:
    def __init__(self, cfg: RateLimitConfig, now: float) -> None:
        self.cfg = cfg
        self.tokens = float(cfg.burst)
        self.last_refill = now
        self.in_flight = 0
        self.factor = 1.0
        self.cooldown_until = 0.0

    def _effective_rps(self) -> float:
        return self.cfg.rps * self.factor

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last_refill)
        self.last_refill = now
        self.tokens = min(
            float(self.cfg.burst), self.tokens + elapsed * self._effective_rps()
        )

    def try_acquire(self, now: float) -> Admission:
        if now < self.cooldown_until:
            return Admission(False, DenyReason.COOLDOWN, self.cooldown_until - now)
        if self.in_flight >= self.cfg.max_concurrency:
            return Admission(False, DenyReason.CONCURRENCY, self._retry_hint())
        self._refill(now)
        if self.tokens < 1.0:
            need = 1.0 - self.tokens
            wait = need / self._effective_rps() if self._effective_rps() > 0 else 1.0
            return Admission(False, DenyReason.RATE, wait)
        self.tokens -= 1.0
        self.in_flight += 1
        return Admission(True)

    def _retry_hint(self) -> float:
        rps = self._effective_rps()
        return 1.0 / rps if rps > 0 else 1.0

    def release(self) -> None:
        self.in_flight = max(0, self.in_flight - 1)

    def record(
        self, status: int, latency: float, retry_after: float, now: float
    ) -> None:
        trouble = (
            status >= 500
            or status == 429
            or latency > self.cfg.latency_ceiling
            or retry_after > 0
        )
        if trouble:
            self.factor = max(self.cfg.min_factor, self.factor * self.cfg.decrease)
            if retry_after > 0 or status == 429:
                # honour an explicit cooldown; default to a small backoff for 429
                self.cooldown_until = max(
                    self.cooldown_until, now + (retry_after or 1.0)
                )
        else:
            self.factor = min(1.0, self.factor + self.cfg.increase)


class _Budget:
    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.used = 0

    def available(self) -> bool:
        return self.limit is None or self.used < self.limit

    def charge(self) -> None:
        self.used += 1


class RateLimiter:
    """Orchestrates per-target rate/concurrency, budgets, and backpressure.

    Usage per candidate request:

        adm = limiter.acquire(target_key, tenant, now)
        if not adm: ...honour adm.retry_after...
        else:
            # ...perform the (already policy-approved) request...
            limiter.record_response(target_key, status, latency, retry_after, now)
            limiter.release(target_key)
    """

    def __init__(
        self,
        default_config: RateLimitConfig | None = None,
        global_budget: int | None = None,
    ) -> None:
        self._default = default_config or RateLimitConfig()
        self._configs: dict[str, RateLimitConfig] = {}
        self._targets: dict[str, _TargetState] = {}
        self._global = _Budget(global_budget)
        self._tenant: dict[str, _Budget] = {}
        self._tenant_limits: dict[str, int] = {}

    def configure_target(self, target_key: str, cfg: RateLimitConfig) -> None:
        self._configs[target_key] = cfg

    def set_tenant_budget(self, tenant: str, limit: int) -> None:
        self._tenant_limits[tenant] = limit

    def _state(self, target_key: str, now: float) -> _TargetState:
        st = self._targets.get(target_key)
        if st is None:
            cfg = self._configs.get(target_key, self._default)
            st = _TargetState(cfg, now)
            self._targets[target_key] = st
        return st

    def _tenant_budget(self, tenant: str) -> _Budget:
        b = self._tenant.get(tenant)
        if b is None:
            b = _Budget(self._tenant_limits.get(tenant))
            self._tenant[tenant] = b
        return b

    def acquire(self, target_key: str, tenant: str, now: float) -> Admission:
        # Budgets first — cheapest, and they protect the fleet globally.
        if not self._global.available():
            return Admission(False, DenyReason.GLOBAL_BUDGET)
        tb = self._tenant_budget(tenant)
        if not tb.available():
            return Admission(False, DenyReason.TENANT_BUDGET)

        adm = self._state(target_key, now).try_acquire(now)
        if adm.allowed:
            self._global.charge()
            tb.charge()
        return adm

    def release(self, target_key: str) -> None:
        st = self._targets.get(target_key)
        if st is not None:
            st.release()

    def record_response(
        self,
        target_key: str,
        status: int,
        latency: float,
        retry_after: float = 0.0,
        now: float = 0.0,
    ) -> None:
        # Create state on demand so backpressure applies even if the caller
        # records an outcome before the next acquire for this target.
        self._state(target_key, now).record(status, latency, retry_after, now)

    # introspection (for monitoring / tests)
    def effective_rps(self, target_key: str) -> float:
        st = self._targets.get(target_key)
        return st._effective_rps() if st else self._default.rps

    def global_used(self) -> int:
        return self._global.used
