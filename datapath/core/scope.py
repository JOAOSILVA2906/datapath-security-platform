"""Scope — a first-class, versioned, immutable authorization boundary.

A Scope records exactly which assets may be touched, which must never be,
when, and at what intensity ceiling. Exclusions always win over inclusions
(spec 1.1). A Scope is frozen once created; a change is a new version that
requires re-authorization.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .intensity import Intensity


class AssetKind(enum.Enum):
    FQDN = "fqdn"
    WILDCARD = "wildcard"       # *.example.com
    CIDR = "cidr"               # 203.0.113.0/24  (also single IPs as /32,/128)
    URL_PREFIX = "url_prefix"   # https://api.example.com/v2/


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_FQDN_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$", re.IGNORECASE)


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError("empty host")
    return host


@dataclass(frozen=True)
class Asset:
    """A single in-scope asset. Immutable.

    A WILDCARD asset is only valid when the authorization proof covers the
    parent domain; that linkage is enforced in grant verification, not here.
    """

    kind: AssetKind
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", self._canonical())

    def _canonical(self) -> str:
        if self.kind is AssetKind.FQDN:
            host = _normalize_host(self.value)
            if not _FQDN_RE.match(host) or host.startswith("*"):
                raise ValueError(f"invalid FQDN: {self.value!r}")
            return host
        if self.kind is AssetKind.WILDCARD:
            raw = self.value.strip().lower()
            if not raw.startswith("*."):
                raise ValueError(f"wildcard must start with '*.': {self.value!r}")
            parent = _normalize_host(raw[2:])
            if not _FQDN_RE.match(parent):
                raise ValueError(f"invalid wildcard parent: {self.value!r}")
            return "*." + parent
        if self.kind is AssetKind.CIDR:
            # strict=False so a host address like 203.0.113.5/24 is accepted
            # and canonicalized to its network.
            net = ipaddress.ip_network(self.value.strip(), strict=False)
            return str(net)
        if self.kind is AssetKind.URL_PREFIX:
            return self._canonical_url(self.value)
        raise ValueError(f"unknown asset kind: {self.kind!r}")

    @staticmethod
    def _canonical_url(value: str) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(value.strip())
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"url prefix needs http(s) scheme: {value!r}")
        if not parts.hostname:
            raise ValueError(f"url prefix needs a host: {value!r}")
        host = _normalize_host(parts.hostname)
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        path = parts.path or "/"
        return f"{parts.scheme}://{netloc}{path}"

    # --- membership tests -------------------------------------------------

    def host_component(self) -> str | None:
        """The bare host this asset pins to, for FQDN and URL_PREFIX assets."""
        if self.kind is AssetKind.FQDN:
            return self.value
        if self.kind is AssetKind.URL_PREFIX:
            from urllib.parse import urlsplit

            return _normalize_host(urlsplit(self.value).hostname or "")
        return None

    def matches_host(self, host: str) -> bool:
        """True if a bare hostname falls under this asset.

        FQDN and URL_PREFIX assets match their exact host; WILDCARD matches one
        extra left label. A CIDR asset never matches a hostname (only an IP).
        """
        if self.kind in (AssetKind.FQDN, AssetKind.URL_PREFIX):
            return _normalize_host(host) == self.host_component()
        if self.kind is AssetKind.WILDCARD:
            parent = self.value[2:]
            h = _normalize_host(host)
            # *.example.com covers a.example.com but NOT example.com itself
            # and NOT a.b.example.com? -> single label only, be conservative:
            # cover exactly one additional left label.
            if not h.endswith("." + parent):
                return False
            left = h[: -(len(parent) + 1)]
            return bool(left) and "." not in left
        return False

    def matches_ip(self, ip: str) -> bool:
        if self.kind is not AssetKind.CIDR:
            return False
        return ipaddress.ip_address(ip) in ipaddress.ip_network(self.value)

    def matches_url(self, url: str) -> bool:
        if self.kind is not AssetKind.URL_PREFIX:
            return False
        from urllib.parse import urlsplit

        parts = urlsplit(url.strip())
        if not parts.hostname:
            return False
        host = _normalize_host(parts.hostname)
        netloc = host if parts.port is None else f"{host}:{parts.port}"
        candidate = f"{parts.scheme}://{netloc}{parts.path or '/'}"
        base = self.value
        # path-prefix match on a segment boundary
        if not candidate.startswith(base.rstrip("/")):
            return False
        rest = candidate[len(base.rstrip("/")):]
        return rest == "" or rest.startswith("/")


@dataclass(frozen=True)
class Exclusion:
    """Something that must never be touched. Exclusions beat inclusions.

    An exclusion may match on host, exact path, or a parameter name.
    """

    host: str | None = None
    path: str | None = None
    param: str | None = None

    def __post_init__(self) -> None:
        if not any((self.host, self.path, self.param)):
            raise ValueError("exclusion must constrain host, path, or param")
        if self.host is not None:
            object.__setattr__(self, "host", _normalize_host(self.host))

    def blocks(
        self, host: str, path: str | None = None, param: str | None = None
    ) -> bool:
        if self.host is not None and _normalize_host(host) != self.host:
            return False
        if self.path is not None:
            if path is None:
                return False
            # exact path or any descendant path
            if not (path == self.path or path.startswith(self.path.rstrip("/") + "/")):
                return False
        if self.param is not None:
            if param is None or param != self.param:
                return False
        return True


@dataclass(frozen=True)
class TestWindow:
    """An allowed UTC time range. Out-of-window requests are refused."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        for name in ("start", "end"):
            val = getattr(self, name)
            if val.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
            object.__setattr__(self, name, val.astimezone(timezone.utc))
        if self.end <= self.start:
            raise ValueError("test window end must be after start")

    def contains(self, at: datetime) -> bool:
        if at.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        at = at.astimezone(timezone.utc)
        return self.start <= at <= self.end


@dataclass(frozen=True)
class Scope:
    """A versioned, immutable scope record.

    Identity is (scope_id, version). Any change produces a new version and
    requires re-authorization; callers must treat an existing Scope as frozen.
    """

    scope_id: str
    version: int
    assets: tuple[Asset, ...]
    exclusions: tuple[Exclusion, ...] = ()
    windows: tuple[TestWindow, ...] = ()
    intensity_ceiling: Intensity = Intensity.SAFE
    allow_response_snippets: bool = False
    escalation_contact: str | None = None
    legal_contact: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("version starts at 1")
        if not self.assets:
            raise ValueError("scope must list at least one asset")
        object.__setattr__(self, "assets", tuple(self.assets))
        object.__setattr__(self, "exclusions", tuple(self.exclusions))
        object.__setattr__(self, "windows", tuple(self.windows))
        object.__setattr__(self, "intensity_ceiling", Intensity.parse(self.intensity_ceiling))

    @property
    def ref(self) -> str:
        return f"{self.scope_id}@v{self.version}"

    # --- scope decisions --------------------------------------------------

    def is_excluded(
        self, host: str, path: str | None = None, param: str | None = None
    ) -> bool:
        return any(e.blocks(host, path, param) for e in self.exclusions)

    def includes_host(self, host: str) -> bool:
        return any(a.matches_host(host) for a in self.assets)

    def includes_ip(self, ip: str) -> bool:
        return any(a.matches_ip(ip) for a in self.assets)

    def includes_url(self, url: str) -> bool:
        return any(a.matches_url(url) for a in self.assets)

    def in_window(self, at: datetime) -> bool:
        # No windows declared == no permitted time. Default-deny.
        return any(w.contains(at) for w in self.windows)
