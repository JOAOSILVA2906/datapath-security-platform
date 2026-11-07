"""Allow-list & SSRF-safe target resolution (spec 1.3).

The egress gateway resolves every candidate target against the allow-list at
REQUEST time, not just at discovery time. A redirect or discovered link that
points outside scope is dropped, logged, and never followed.

SSRF defences:
  * blocks private / loopback / link-local / unique-local / multicast /
    reserved ranges and cloud-metadata addresses (169.254.169.254, the IMDS
    IPv6 fd00:ec2::254) unless explicitly in-scope internal assets;
  * resolve-then-pin: the host is resolved once, every resolved IP is
    validated, and the caller must connect to the pinned IP it got back — so
    a DNS-rebinding answer that changes between validation and connect cannot
    slip through.

The DNS resolver is injected (a callable host -> list[str]) so the gate is
fully testable without real network access and so production can route through
a hardened resolver.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable

from .scope import Scope

Resolver = Callable[[str], list[str]]


class ResolutionError(Exception):
    """Raised when a target cannot be safely resolved within scope."""


# Cloud metadata endpoints that must never be reachable via egress.
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure IMDS
        ipaddress.ip_address("fd00:ec2::254"),    # AWS IMDS over IPv6
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    }
)


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    """True if an address is in a range egress must refuse by default."""
    if ip in _METADATA_IPS:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass(frozen=True)
class ResolvedTarget:
    """A target that passed every allow-list and SSRF check.

    ``pinned_ip`` is the address the caller MUST connect to. Connecting to a
    freshly re-resolved address instead defeats the rebinding protection.
    """

    host: str
    pinned_ip: str
    port: int
    url: str


class AllowList:
    """Resolve-then-pin target gate bound to one scope."""

    def __init__(self, scope: Scope, resolver: Resolver) -> None:
        self._scope = scope
        self._resolve = resolver

    def _ip_in_scope(self, ip: ipaddress._BaseAddress) -> bool:
        return self._scope.includes_ip(str(ip))

    def resolve(self, url: str) -> ResolvedTarget:
        """Resolve ``url`` and return a pinned target, or raise.

        Steps:
          1. the URL must be an in-scope URL and not excluded;
          2. the host must be an in-scope FQDN/wildcard OR an in-scope IP;
          3. resolve the host; every answer must be allow-listed or an
             explicitly in-scope internal asset;
          4. pin the first acceptable IP and return it.
        """
        from urllib.parse import urlsplit

        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        if not host:
            raise ResolutionError(f"no host in url: {url!r}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"

        # (1) URL-level scope + exclusions.
        if not self._scope.includes_url(url):
            raise ResolutionError(f"url not in scope: {url!r}")
        if self._scope.is_excluded(host, path):
            raise ResolutionError(f"url excluded by scope: {url!r}")

        # (2) host-level scope. A literal IP host is checked directly.
        literal_ip = _try_ip(host)
        if literal_ip is not None:
            candidate_ips = [literal_ip]
            host_in_scope = self._ip_in_scope(literal_ip)
        else:
            host_in_scope = self._scope.includes_host(host)
            if not host_in_scope:
                raise ResolutionError(f"host not in scope: {host!r}")
            # (3) resolve-then-pin.
            answers = self._resolve(host)
            if not answers:
                raise ResolutionError(f"host did not resolve: {host!r}")
            candidate_ips = [_require_ip(a) for a in answers]

        if literal_ip is not None and not host_in_scope:
            raise ResolutionError(f"ip host not in scope: {host!r}")

        # (4) validate every resolved IP; pin the first acceptable one.
        pinned: ipaddress._BaseAddress | None = None
        for ip in candidate_ips:
            if _is_blocked_ip(ip):
                # Allowed only if that exact IP is an explicit in-scope asset.
                if not self._ip_in_scope(ip):
                    raise ResolutionError(
                        f"resolved blocked address {ip} for {host!r} "
                        f"(SSRF-protected range, not an in-scope internal asset)"
                    )
            if pinned is None:
                pinned = ip

        if pinned is None:
            raise ResolutionError(f"no acceptable address for {host!r}")

        return ResolvedTarget(host=host, pinned_ip=str(pinned), port=port, url=url)

    def revalidate_pinned(self, target: ResolvedTarget) -> None:
        """Re-check a pinned IP immediately before connect. Raises if unsafe.

        This is the second half of resolve-then-pin: scope membership and the
        block-list are re-evaluated on the pinned address so a scope change or
        a TOCTOU gap cannot let a now-forbidden address through.
        """
        ip = _require_ip(target.pinned_ip)
        if _is_blocked_ip(ip) and not self._ip_in_scope(ip):
            raise ResolutionError(f"pinned address {ip} no longer permitted")
        # The pinned IP must still be reachable under current scope: either an
        # in-scope IP asset, or the resolution of an in-scope host.
        if _try_ip(target.host) is None:
            if not self._scope.includes_host(target.host):
                raise ResolutionError(f"host {target.host!r} no longer in scope")
        elif not self._ip_in_scope(ip):
            raise ResolutionError(f"ip {ip} no longer in scope")


def _try_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _require_ip(value: str) -> ipaddress._BaseAddress:
    ip = _try_ip(value)
    if ip is None:
        raise ResolutionError(f"not an IP address: {value!r}")
    return ip
