"""Ownership verification (review fix #5).

Controlling a domain's DNS does not prove you own what sits behind a given
name or address:

  * ``shop.example.com`` may be a CNAME to a third-party SaaS (Shopify, a CDN,
    a status-page host) — testing it tests *their* infrastructure;
  * a resolved IP may belong to a shared CDN / load-balancer, or to a cloud
    provider's range the customer only rents a slice of;
  * an IP range the customer claims needs separate proof (RDAP/WHOIS org match
    or a cloud-account linkage), not just a DNS token on some domain.

This module turns that into a decision. It does NOT perform live DNS/RDAP
lookups itself — those are injected (so it is testable offline and so
production can route them through the hardened resolver). It consumes the
lookup results and classifies each asset as:

    OWNED            — safe to treat as in-scope
    THIRD_PARTY      — points at infrastructure someone else runs; excluded by
                       default (spec 1.6: never touch third-party services)
    UNVERIFIED       — could not establish ownership; excluded by default

The caller (target intake / grant verification) decides what to do with a
THIRD_PARTY or UNVERIFIED verdict; by default they are added to the Scope's
exclusions and never probed.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field
from typing import Callable

from .scope import Asset, AssetKind

# Injected lookups -----------------------------------------------------------
# cname_chain(host)   -> ordered list of CNAME targets, [] if host is an A/AAAA
# resolve(host)       -> list of IP strings
# ip_owner(ip)        -> an IpOwner describing who announces/registers the IP
CnameResolver = Callable[[str], list[str]]
AddressResolver = Callable[[str], list[str]]


class Verdict(enum.Enum):
    OWNED = "owned"
    THIRD_PARTY = "third_party"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class IpOwner:
    """Minimal network-ownership facts for an IP (from RDAP/WHOIS/ASN data)."""

    asn: int | None = None
    org: str | None = None            # registered org name / handle
    is_cloud: bool = False            # IP sits in a cloud provider range
    is_cdn: bool = False              # IP sits in a known CDN / shared edge


OwnerLookup = Callable[[str], IpOwner]


@dataclass(frozen=True)
class OwnershipResult:
    asset: Asset
    verdict: Verdict
    reason: str
    observed_cnames: tuple[str, ...] = ()
    observed_ips: tuple[str, ...] = ()
    owners: tuple[IpOwner, ...] = ()

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.OWNED


class OwnershipVerifier:
    """Classify assets by who actually controls the thing behind the name.

    ``verified_apex`` is the apex/parent domain the AuthorizationGrant actually
    proved control of (e.g. the host carrying the domain token). A CNAME that
    leaves that apex's own domains is treated as pointing at a third party.

    ``owned_networks`` lists CIDRs / ASNs / org names the customer separately
    proved (RDAP org match or cloud-account linkage). An IP is "owned" only if
    it falls under one of these, or under an explicit in-scope CIDR asset.
    """

    def __init__(
        self,
        verified_apexes: set[str],
        cname_resolver: CnameResolver,
        address_resolver: AddressResolver,
        owner_lookup: OwnerLookup,
        owned_asns: set[int] | None = None,
        owned_orgs: set[str] | None = None,
        owned_cidrs: tuple[str, ...] = (),
    ) -> None:
        self._apexes = {a.strip().lower().rstrip(".") for a in verified_apexes}
        self._cnames = cname_resolver
        self._resolve = address_resolver
        self._owner = owner_lookup
        self._asns = owned_asns or set()
        self._orgs = {o.lower() for o in (owned_orgs or set())}
        self._cidrs = tuple(ipaddress.ip_network(c) for c in owned_cidrs)

    # --- helpers ----------------------------------------------------------

    def _under_verified_apex(self, host: str) -> bool:
        h = host.strip().lower().rstrip(".")
        return any(h == apex or h.endswith("." + apex) for apex in self._apexes)

    def _ip_is_owned(self, ip: str, owner: IpOwner) -> bool:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in self._cidrs):
            return True
        if owner.asn is not None and owner.asn in self._asns:
            return True
        if owner.org is not None and owner.org.lower() in self._orgs:
            return True
        return False

    # --- classification ---------------------------------------------------

    def verify(self, asset: Asset) -> OwnershipResult:
        if asset.kind is AssetKind.CIDR:
            return self._verify_cidr(asset)
        if asset.kind in (AssetKind.FQDN, AssetKind.URL_PREFIX, AssetKind.WILDCARD):
            return self._verify_host_asset(asset)
        return OwnershipResult(asset, Verdict.UNVERIFIED, "unknown asset kind")

    def _verify_cidr(self, asset: Asset) -> OwnershipResult:
        net = ipaddress.ip_network(asset.value)
        # A claimed range is owned only if it sits within a separately proved
        # owned CIDR, or every owner lookup in it matches an owned ASN/org.
        if any(net.subnet_of(owned) for owned in self._cidrs):
            return OwnershipResult(asset, Verdict.OWNED, "within proved CIDR")
        sample = str(net.network_address)
        owner = self._owner(sample)
        if self._ip_is_owned(sample, owner):
            return OwnershipResult(
                asset, Verdict.OWNED, f"ASN/org match ({owner.asn}/{owner.org})",
                owners=(owner,),
            )
        return OwnershipResult(
            asset, Verdict.UNVERIFIED,
            "CIDR not covered by a proved ASN/org/CIDR; needs RDAP or cloud "
            "linkage",
            owners=(owner,),
        )

    def _verify_host_asset(self, asset: Asset) -> OwnershipResult:
        host = asset.host_component() if asset.kind != AssetKind.WILDCARD else (
            asset.value[2:]
        )
        if not host:
            return OwnershipResult(asset, Verdict.UNVERIFIED, "no host")

        # 1. CNAME chain: if the name delegates off the verified apex, it is a
        #    third party (the classic subdomain-takeover / SaaS-host case).
        chain = tuple(self._cnames(host))
        for target in chain:
            if not self._under_verified_apex(target):
                return OwnershipResult(
                    asset, Verdict.THIRD_PARTY,
                    f"CNAME to {target!r} leaves verified apex — third-party host",
                    observed_cnames=chain,
                )

        # 2. The name itself must be under a verified apex.
        if not self._under_verified_apex(host):
            return OwnershipResult(
                asset, Verdict.UNVERIFIED,
                f"host {host!r} is not under any verified apex {self._apexes}",
                observed_cnames=chain,
            )

        # 3. Addresses must not sit on shared CDN / cloud edge unless that
        #    network is separately proved to be the customer's.
        ips = tuple(self._resolve(host))
        if not ips:
            return OwnershipResult(
                asset, Verdict.UNVERIFIED, f"host {host!r} did not resolve",
                observed_cnames=chain,
            )
        owners = tuple(self._owner(ip) for ip in ips)
        for ip, owner in zip(ips, owners):
            if (owner.is_cdn or owner.is_cloud) and not self._ip_is_owned(ip, owner):
                kind = "CDN" if owner.is_cdn else "cloud"
                return OwnershipResult(
                    asset, Verdict.THIRD_PARTY,
                    f"{ip} is shared {kind} infrastructure "
                    f"(ASN {owner.asn}, {owner.org}) not proved as customer-owned",
                    observed_cnames=chain, observed_ips=ips, owners=owners,
                )

        return OwnershipResult(
            asset, Verdict.OWNED, "under verified apex; addresses not shared infra",
            observed_cnames=chain, observed_ips=ips, owners=owners,
        )
