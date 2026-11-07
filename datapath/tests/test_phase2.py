"""Phase-2 tests: active confirmation, stop-at-boundary, body non-exposure."""

from __future__ import annotations

import unittest
from datetime import timedelta

from datapath.core import (
    AllowList, Asset, AssetKind, AuditLog, Intensity, KillSwitch,
    PolicyEngine, RateLimiter, Scope, TestWindow,
)
from datapath.scan import GatedEgress, HttpResponse
from datapath.scan.egress import EgressDenied
from datapath.confirm import ActiveConfirmer, BoundaryKind

from .conftest import KEY, NOW, make_grant

TENANT_B_DECOY = "DECOY-TENANT-B-7f3a9c"
ADMIN_DECOY = "DECOY-ADMIN-PANEL-12ab"


def _resp(status=200, body=b"", headers=None, url="https://train/"):
    return HttpResponse(status, headers or {}, body, 0.05, url)


def build_egress(transport, *, ceiling=Intensity.ACTIVE, confirmed=True, calls=None):
    scope = Scope(
        scope_id="train", version=1,
        assets=(Asset(AssetKind.URL_PREFIX, "https://train.example.com/"),),
        windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
        intensity_ceiling=ceiling,
    )
    grant = make_grant(scope, verifier_evidence="train.example.com",
                       max_intensity=ceiling)
    ks = KillSwitch(); ks.register("scan1", at=NOW)
    policy = PolicyEngine(KEY, ks, AuditLog())
    eg = GatedEgress(
        scope=scope, grant=grant, signing_key=KEY,
        allowlist=AllowList(scope, lambda h: {"train.example.com": ["93.184.216.34"]}.get(h, [])),
        policy=policy, rate_limiter=RateLimiter(), kill_switch=ks,
        transport=transport, tenant="acme", scan_id="scan1",
        clock=lambda: 0.0, active_confirmed=confirmed,
    )
    orig = eg._request
    eg._request = lambda u, i, s, h, at=None: orig(u, i, s, h, NOW)  # type: ignore
    return eg


class TestActiveGating(unittest.TestCase):
    def test_active_denied_when_ceiling_safe(self):
        eg = build_egress(lambda t, h: _resp(), ceiling=Intensity.SAFE)
        with self.assertRaises(EgressDenied):
            eg.probe("https://train.example.com/x", markers=[])

    def test_active_denied_without_per_scan_confirmation(self):
        eg = build_egress(lambda t, h: _resp(), confirmed=False)
        with self.assertRaises(EgressDenied) as cm:
            eg.probe("https://train.example.com/x", markers=[])
        self.assertIn("confirmation", str(cm.exception))

    def test_probe_discards_body(self):
        eg = build_egress(lambda t, h: _resp(body=b"super secret data " + TENANT_B_DECOY.encode()))
        r = eg.probe("https://train.example.com/x", markers=[TENANT_B_DECOY])
        self.assertIn(TENANT_B_DECOY, r.markers_present)
        self.assertFalse(hasattr(r, "body"))     # no body attribute at all
        self.assertEqual(r.length, len(b"super secret data " + TENANT_B_DECOY.encode()))


class TestBolaConfirmation(unittest.TestCase):
    def test_bola_confirmed_stops_at_boundary(self):
        calls = []
        def transport(t, h):
            calls.append(t.url)
            return _resp(status=200, body=b'{"owner":"B","x":"' + TENANT_B_DECOY.encode() + b'"}')
        eg = build_egress(transport)
        c = ActiveConfirmer(eg).confirm_bola(
            "https://train.example.com/api/orders/1002",
            identity_a_token="token-A",
            decoy_marker_b=TENANT_B_DECOY,
        )
        self.assertTrue(c.confirmed)
        self.assertEqual(c.boundary.kind, BoundaryKind.CROSS_TENANT_READ)
        self.assertFalse(c.boundary.exploited)   # never exploited
        self.assertTrue(c.boundary.reachable)
        # STOP AT BOUNDARY: exactly one request was made, no enumeration
        self.assertEqual(len(calls), 1)
        # proof carries no raw data, only masked marker
        self.assertNotIn(TENANT_B_DECOY, c.boundary.evidence)

    def test_bola_not_confirmed_when_blocked(self):
        def transport(t, h):
            return _resp(status=403, body=b"forbidden")
        eg = build_egress(transport)
        c = ActiveConfirmer(eg).confirm_bola(
            "https://train.example.com/api/orders/1002",
            identity_a_token="token-A", decoy_marker_b=TENANT_B_DECOY,
        )
        self.assertFalse(c.confirmed)
        self.assertEqual(c.http_status, 403)
        self.assertIsNone(c.boundary)


class TestVerticalPrivilege(unittest.TestCase):
    def test_privilege_confirmed(self):
        def transport(t, h):
            return _resp(status=200, body=ADMIN_DECOY.encode())
        eg = build_egress(transport)
        c = ActiveConfirmer(eg).confirm_vertical_privilege(
            "https://train.example.com/admin/users",
            low_priv_token="token-low", admin_decoy_marker=ADMIN_DECOY,
        )
        self.assertTrue(c.confirmed)
        self.assertEqual(c.boundary.kind, BoundaryKind.VERTICAL_PRIVILEGE)

    def test_privilege_denied_by_target(self):
        def transport(t, h):
            return _resp(status=401, body=b"")
        eg = build_egress(transport)
        c = ActiveConfirmer(eg).confirm_vertical_privilege(
            "https://train.example.com/admin/users",
            low_priv_token="token-low", admin_decoy_marker=ADMIN_DECOY,
        )
        self.assertFalse(c.confirmed)


class TestBoundaryProofInvariant(unittest.TestCase):
    def test_exploited_proof_is_rejected(self):
        from datapath.confirm import BoundaryProof
        with self.assertRaises(ValueError):
            BoundaryProof(BoundaryKind.CROSS_TENANT_READ, "x", exploited=True)


if __name__ == "__main__":
    unittest.main()
