"""Tests for ownership verification (review fix #5)."""

from __future__ import annotations

import unittest

from datapath.core import (
    Asset,
    AssetKind,
    IpOwner,
    OwnershipVerifier,
    Verdict,
)


def verifier(**over):
    cfg = dict(
        verified_apexes={"example.com"},
        cname_resolver=lambda h: {
            "shop.example.com": ["shops.myshopify.com"],
            "cdn.example.com": [],
            "api.example.com": [],
            "www.example.com": [],
        }.get(h, []),
        address_resolver=lambda h: {
            "api.example.com": ["93.184.216.34"],      # customer-owned host
            "cdn.example.com": ["151.101.1.1"],        # Fastly CDN edge
            "www.example.com": ["203.0.113.200"],
        }.get(h, []),
        owner_lookup=lambda ip: {
            "93.184.216.34": IpOwner(asn=64500, org="Acme Inc"),
            "151.101.1.1": IpOwner(asn=54113, org="Fastly", is_cdn=True),
            "203.0.113.200": IpOwner(asn=64500, org="Acme Inc"),
        }.get(ip, IpOwner()),
        owned_asns={64500},
        owned_orgs={"Acme Inc"},
    )
    cfg.update(over)
    return OwnershipVerifier(**cfg)


class TestOwnership(unittest.TestCase):
    def test_owned_host_passes(self):
        r = verifier().verify(Asset(AssetKind.FQDN, "api.example.com"))
        self.assertEqual(r.verdict, Verdict.OWNED, r.reason)

    def test_cname_to_saas_is_third_party(self):
        r = verifier().verify(Asset(AssetKind.FQDN, "shop.example.com"))
        self.assertEqual(r.verdict, Verdict.THIRD_PARTY)
        self.assertIn("myshopify", r.reason)

    def test_shared_cdn_edge_is_third_party(self):
        r = verifier().verify(Asset(AssetKind.FQDN, "cdn.example.com"))
        self.assertEqual(r.verdict, Verdict.THIRD_PARTY)
        self.assertIn("CDN", r.reason)

    def test_host_off_apex_is_unverified(self):
        r = verifier().verify(Asset(AssetKind.FQDN, "api.other.com"))
        self.assertEqual(r.verdict, Verdict.UNVERIFIED)

    def test_cdn_ip_owned_when_asn_proved(self):
        # If the customer actually owns the ASN behind the "CDN" IP, it's owned.
        v = verifier(owned_asns={64500, 54113})
        r = v.verify(Asset(AssetKind.FQDN, "cdn.example.com"))
        self.assertEqual(r.verdict, Verdict.OWNED, r.reason)

    def test_cidr_needs_proof(self):
        r = verifier().verify(Asset(AssetKind.CIDR, "198.18.0.0/24"))
        self.assertEqual(r.verdict, Verdict.UNVERIFIED)

    def test_cidr_owned_when_within_proved_cidr(self):
        v = verifier(owned_cidrs=("198.18.0.0/16",))
        r = v.verify(Asset(AssetKind.CIDR, "198.18.5.0/24"))
        self.assertEqual(r.verdict, Verdict.OWNED, r.reason)

    def test_wildcard_under_apex_resolving_to_owned(self):
        v = verifier(
            cname_resolver=lambda h: [],
            address_resolver=lambda h: ["93.184.216.34"],
            owner_lookup=lambda ip: IpOwner(asn=64500, org="Acme Inc"),
        )
        r = v.verify(Asset(AssetKind.WILDCARD, "*.example.com"))
        self.assertEqual(r.verdict, Verdict.OWNED, r.reason)


if __name__ == "__main__":
    unittest.main()
