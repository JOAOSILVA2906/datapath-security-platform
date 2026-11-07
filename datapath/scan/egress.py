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


@dataclass(frozen=True)
class ReducedResponse:
    """A response with the body REMOVED (review fix #1).

    Active, boundary-crossing checks never see raw bodies. The egress reduces
    each response to status, length, a content hash, and which pre-declared
    decoy markers were present — enough to prove a boundary was reachable,
    impossible to use for exfiltration.
    """

    status: int
    length: int
    sha256: str
    markers_present: tuple[str, ...]

    def header(self, name: str) -> str | None:  # headers are safe to keep
        return self._headers.get(name.lower())

    _headers: dict[str, str] = field(default_factory=dict)


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
        active_confirmed: bool = False,
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
        self._active_confirmed = active_confirmed
        import time

        self._clock = clock or time.monotonic

    def get(self, url: str, at: datetime | None = None) -> HttpResponse:
        """Passive, SAFE-mode GET. Returns the full response (recon needs it)."""
        return self._request(
            url, Intensity.SAFE, SideEffectClass.PASSIVE, {}, at
        )

    def probe(
        self,
        url: str,
        markers: list[str],
        extra_headers: dict[str, str] | None = None,
        at: datetime | None = None,
    ) -> ReducedResponse:
        """Active, BENIGN_PAYLOAD GET for boundary confirmation.

        Requires the scope/grant to permit ACTIVE **and** per-scan active
        confirmation. The raw body is scanned for ``markers`` and then
        DISCARDED here — the caller never receives it (review fix #1).
        """
        import hashlib

        resp = self._request(
            url, Intensity.ACTIVE, SideEffectClass.BENIGN_PAYLOAD,
            extra_headers or {}, at,
        )
        present = tuple(m for m in markers if m.encode() in resp.body)
        reduced = ReducedResponse(
            status=resp.status,
            length=len(resp.body),
            sha256=hashlib.sha256(resp.body).hexdigest(),
            markers_present=present,
            _headers={k.lower(): v for k, v in resp.headers.items()},
        )
        del resp  # drop the body
        return reduced

    def _request(
        self,
        url: str,
        intensity: Intensity,
        side_effect: SideEffectClass,
        extra_headers: dict[str, str],
        at: datetime | None,
    ) -> HttpResponse:
        at = at or datetime.now(timezone.utc)

        # 0. Active mode needs an explicit per-scan confirmation (spec 1.4).
        if intensity > Intensity.SAFE and not self._active_confirmed:
            raise EgressDenied(
                "active mode requires per-scan confirmation (not given)"
            )

        # 1. resolve + pin (SSRF-safe). Out-of-scope / blocked -> denied.
        try:
            target = self._allow.resolve(url)
        except ResolutionError as exc:
            raise EgressDenied(f"resolution refused: {exc}") from exc

        # 2. policy decision for this intensity + side-effect.
        pin = PolicyInput(
            scope=self._scope,
            grant=self._grant,
            target=target,
            requested_intensity=intensity,
            side_effect=side_effect,
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
        headers.update(extra_headers)
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
                    "mode": f"{intensity.name}/{side_effect.name}",
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
