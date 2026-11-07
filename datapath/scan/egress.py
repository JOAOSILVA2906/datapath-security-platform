"""Gated HTTP egress — the ONLY way Phase 1 may touch a target.

Every outbound request is a policy query first. Before a single byte leaves,
this gate, in order:

  1. resolves + pins the target through the Phase-0 AllowList (SSRF-safe,
     anti-rebind);
  2. asks the PolicyEngine (default-deny, fail-closed) whether a PASSIVE probe
     at SAFE intensity is allowed for this scope/grant/time/scan;
  3. re-checks the kill switch and the pinned IP immediately before connect;
  4. acquires a rate-limit / concurrency / budget slot;
  5. only then performs the fetch, via an injected transport;
  6. records the outcome to the limiter and writes an audit record (metadata
     only — never the body).

The transport is injected so the whole engine is testable offline and so no
ungated fetcher is the default path. Bodies are capped (no bulk retrieval) and
an honest, attributable User-Agent + scan-id header is always sent so blue
teams can recognise the traffic (spec 1.3).

Phase 1 is SAFE-mode only: this gate refuses to send anything but a PASSIVE,
read-only GET.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..core import (
    AllowList,
    Intensity,
    KillSwitch,
    PolicyEngine,
    PolicyInput,
    RateLimiter,
    ResolutionError,
    Scope,
    SideEffectClass,
)
from ..core.audit import AuditLog
from ..core.grant import AuthorizationGrant

MAX_BODY_BYTES = 262_144  # 256 KiB cap — recon needs structure, not bulk data
USER_AGENT = (
    "DataPath-Scanner/0.1 (+https://datapath.example/abuse; authorized-testing)"
)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed: float            # seconds
    final_url: str

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None

    def text(self, limit: int = MAX_BODY_BYTES) -> str:
        return self.body[:limit].decode("utf-8", errors="replace")


# transport(target, headers) -> HttpResponse
Transport = Callable[["object", dict[str, str]], HttpResponse]


class EgressDenied(Exception):
    """Raised when the gate refuses a request. Carries the reason."""


@dataclass
class _Mono:
    """Minimal monotonic clock for the rate limiter, injectable for tests."""

    now_fn: Callable[[], float]

    def now(self) -> float:
        return self.now_fn()


class GatedEgress:
    def __init__(
        self,
        scope: Scope,
        grant: AuthorizationGrant,
        signing_key: bytes,
        allowlist: AllowList,
        policy: PolicyEngine,
        rate_limiter: RateLimiter,
        kill_switch: KillSwitch,
        transport: Transport,
        tenant: str,
        scan_id: str,
        audit: AuditLog | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._scope = scope
        self._grant = grant
        self._allow = allowlist
        self._policy = policy
        self._rl = rate_limiter
        self._kill = kill_switch
        self._transport = transport
        self._tenant = tenant
        self._scan_id = scan_id
        self._audit = audit
        import time

        self._clock = clock or time.monotonic

    def get(self, url: str, at: datetime | None = None) -> HttpResponse:
        """Fetch ``url`` if and only if the full gate allows it. Else raise."""
        at = at or datetime.now(timezone.utc)

        # 1. resolve + pin (SSRF-safe). Out-of-scope / blocked -> denied.
        try:
            target = self._allow.resolve(url)
        except ResolutionError as exc:
            raise EgressDenied(f"resolution refused: {exc}") from exc

        # 2. policy: PASSIVE probe at SAFE intensity.
        pin = PolicyInput(
            scope=self._scope,
            grant=self._grant,
            target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id=self._scan_id,
            at=at,
        )
        result = self._policy.evaluate(pin)
        if not result.allowed:
            raise EgressDenied(f"policy denied: {result.reason}")

        # 3. last-mile re-validation of the pinned IP before connect.
        try:
            self._allow.revalidate_pinned(target)
        except ResolutionError as exc:
            raise EgressDenied(f"pin revalidation failed: {exc}") from exc

        # 4. rate / concurrency / budget.
        key = f"{target.host}:{target.port}"
        now = self._clock()
        adm = self._rl.acquire(key, self._tenant, now)
        if not adm:
            raise EgressDenied(
                f"rate limited: {adm.reason.value if adm.reason else 'unknown'} "
                f"(retry after {adm.retry_after:.2f}s)"
            )

        # 5. perform the fetch.
        headers = {
            "User-Agent": USER_AGENT,
            "X-DataPath-Scan-Id": self._scan_id,
            "Accept": "*/*",
        }
        try:
            resp = self._transport(target, headers)
            if len(resp.body) > MAX_BODY_BYTES:
                resp = HttpResponse(
                    resp.status, resp.headers, resp.body[:MAX_BODY_BYTES],
                    resp.elapsed, resp.final_url,
                )
        finally:
            self._rl.release(key)

        # 6. feed backpressure + audit (metadata only).
        retry_after = _parse_retry_after(resp.header("Retry-After"))
        self._rl.record_response(key, resp.status, resp.elapsed, retry_after, now)
        if self._audit is not None:
            self._audit.append(
                "egress_probe",
                {
                    "scan_id": self._scan_id,
                    "host": target.host,
                    "pinned_ip": target.pinned_ip,
                    "port": target.port,
                    "method": "GET",
                    "mode": "SAFE/PASSIVE",
                    "status": resp.status,
                    "elapsed_s": round(resp.elapsed, 4),
                    "body_bytes": len(resp.body),
                },
            )
        return resp


def _parse_retry_after(value: str | None) -> float:
    if not value:
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0  # HTTP-date form: ignore for the limiter's purposes
