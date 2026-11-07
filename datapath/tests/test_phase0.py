"""Phase-0 acceptance + unit tests.

Run: python -m unittest discover -s datapath/tests -v
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from datapath.core import (
    AllowList,
    Asset,
    AssetKind,
    AuditLog,
    Decision,
    Exclusion,
    Intensity,
    KillSwitch,
    PolicyEngine,
    PolicyInput,
    ProofMethod,
    ResolutionError,
    SideEffectClass,
)

from .conftest import KEY, NOW, make_grant, make_scope, resolver


# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------
class TestScope(unittest.TestCase):
    def test_url_prefix_membership_on_segment_boundary(self):
        s = make_scope()
        self.assertTrue(s.includes_url("https://api.example.com/v2/search?q=1"))
        self.assertTrue(s.includes_url("https://api.example.com/v2/"))
        # /v2evil must not match the /v2/ prefix
        self.assertFalse(s.includes_url("https://api.example.com/v2evil"))
        self.assertFalse(s.includes_url("https://api.example.com/v1/x"))

    def test_exclusion_beats_inclusion(self):
        s = make_scope(
            assets=(Asset(AssetKind.FQDN, "example.com"),),
            exclusions=(Exclusion(host="example.com", path="/admin/delete"),),
        )
        self.assertTrue(s.includes_host("example.com"))
        self.assertTrue(s.is_excluded("example.com", "/admin/delete"))
        self.assertTrue(s.is_excluded("example.com", "/admin/delete/42"))
        self.assertFalse(s.is_excluded("example.com", "/admin/list"))

    def test_wildcard_covers_one_label_only(self):
        a = Asset(AssetKind.WILDCARD, "*.example.com")
        self.assertTrue(a.matches_host("a.example.com"))
        self.assertFalse(a.matches_host("example.com"))
        self.assertFalse(a.matches_host("a.b.example.com"))

    def test_no_window_means_denied(self):
        s = make_scope(windows=())
        self.assertFalse(s.in_window(NOW))

    def test_scope_is_frozen(self):
        s = make_scope()
        with self.assertRaises(Exception):
            s.version = 2  # type: ignore[misc]


# --------------------------------------------------------------------------
# Grant
# --------------------------------------------------------------------------
class TestGrant(unittest.TestCase):
    def test_signature_roundtrip_and_tamper(self):
        s = make_scope()
        g = make_grant(s)
        self.assertTrue(g.signature_valid(KEY))
        tampered = g.__class__(**{**g.__dict__, "authorizing_identity": "evil@x"})
        self.assertFalse(tampered.signature_valid(KEY))

    def test_document_proof_cannot_unlock_active(self):
        s = make_scope()
        with self.assertRaises(ValueError):
            make_grant(
                s,
                method=ProofMethod.SIGNED_DOCUMENT,
                max_intensity=Intensity.ACTIVE,
            )

    def test_document_proof_allows_safe(self):
        s = make_scope(intensity_ceiling=Intensity.SAFE)
        g = make_grant(
            s, method=ProofMethod.SIGNED_DOCUMENT, max_intensity=Intensity.SAFE
        )
        ok, why = g.is_valid_for(s, NOW, KEY)
        self.assertTrue(ok, why)

    def test_expired_grant(self):
        s = make_scope()
        g = make_grant(s, not_after=NOW - timedelta(hours=1))
        ok, why = g.is_valid_for(s, NOW, KEY)
        self.assertFalse(ok)

    def test_wildcard_requires_parent_cover(self):
        s = make_scope(assets=(Asset(AssetKind.WILDCARD, "*.other.com"),))
        g = make_grant(s, verifier_evidence="example.com")  # covers wrong parent
        ok, why = g.is_valid_for(s, NOW, KEY)
        self.assertFalse(ok)
        self.assertIn("wildcard", why)


# --------------------------------------------------------------------------
# AllowList / SSRF — acceptance tests
# --------------------------------------------------------------------------
class TestAllowListSSRF(unittest.TestCase):
    def test_unverified_host_is_refused(self):
        s = make_scope()
        al = AllowList(s, resolver({}))  # host does not resolve / not in scope
        with self.assertRaises(ResolutionError):
            al.resolve("https://not-in-scope.example.org/v2/x")

    def test_metadata_ip_is_refused(self):
        s = make_scope(assets=(Asset(AssetKind.URL_PREFIX, "https://meta.example.com/"),))
        al = AllowList(s, resolver({"meta.example.com": ["169.254.169.254"]}))
        with self.assertRaises(ResolutionError) as cm:
            al.resolve("https://meta.example.com/")
        self.assertIn("SSRF", str(cm.exception))

    def test_private_range_refused_unless_in_scope(self):
        s = make_scope(assets=(Asset(AssetKind.URL_PREFIX, "https://int.example.com/"),))
        al = AllowList(s, resolver({"int.example.com": ["10.0.0.5"]}))
        with self.assertRaises(ResolutionError):
            al.resolve("https://int.example.com/")

    def test_private_range_allowed_when_explicit_internal_asset(self):
        s = make_scope(
            assets=(
                Asset(AssetKind.URL_PREFIX, "https://int.example.com/"),
                Asset(AssetKind.CIDR, "10.0.0.0/24"),
            )
        )
        al = AllowList(s, resolver({"int.example.com": ["10.0.0.5"]}))
        t = al.resolve("https://int.example.com/")
        self.assertEqual(t.pinned_ip, "10.0.0.5")

    def test_dns_rebind_blocked_by_pin_revalidation(self):
        # Resolve returns a good public IP and we pin it. The rebinding attempt
        # is a later resolver answer pointing at metadata; because the caller
        # must connect to the PINNED ip and we re-validate the pin, the rebind
        # cannot take effect.
        s = make_scope(assets=(Asset(AssetKind.URL_PREFIX, "https://rebind.example.com/"),))
        answers = {"rebind.example.com": ["93.184.216.40"]}
        al = AllowList(s, resolver(answers))
        t = al.resolve("https://rebind.example.com/")
        self.assertEqual(t.pinned_ip, "93.184.216.40")
        # Attacker flips DNS to metadata; pin re-validation must still pass
        # because we never re-resolve — we check the pinned public IP.
        answers["rebind.example.com"] = ["169.254.169.254"]
        al.revalidate_pinned(t)  # does not raise: pinned IP is still safe

    def test_out_of_scope_redirect_target_refused(self):
        # A redirect is just another resolve() at request time; off-scope host
        # is dropped.
        s = make_scope()
        al = AllowList(s, resolver({"evil.example.net": ["93.184.216.39"]}))
        with self.assertRaises(ResolutionError):
            al.resolve("https://evil.example.net/v2/")


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
class TestAudit(unittest.TestCase):
    def test_chain_verifies(self):
        log = AuditLog()
        log.append("a", {"x": 1})
        log.append("b", {"y": 2})
        ok, bad = log.verify()
        self.assertTrue(ok)
        self.assertIsNone(bad)

    def test_tamper_detected(self):
        log = AuditLog()
        log.append("a", {"x": 1})
        log.append("b", {"y": 2})
        log.append("c", {"z": 3})
        # mutate the middle record's payload
        recs = log._records
        recs[1] = recs[1].__class__(**{**recs[1].__dict__, "payload": {"y": 999}})
        ok, bad = log.verify()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_body_rejected(self):
        log = AuditLog()
        with self.assertRaises(ValueError):
            log.append("probe", {"response_body": "secret data"})


# --------------------------------------------------------------------------
# Kill switch
# --------------------------------------------------------------------------
class TestKillSwitch(unittest.TestCase):
    def test_abort_stops_probing(self):
        ks = KillSwitch()
        ks.register("scan1", at=NOW)
        self.assertTrue(ks.scan_may_probe("scan1", at=NOW))
        ks.abort("scan1")
        self.assertFalse(ks.scan_may_probe("scan1", at=NOW))

    def test_global_halt(self):
        ks = KillSwitch()
        ks.register("scan1", at=NOW)
        ks.engage_global()
        self.assertFalse(ks.scan_may_probe("scan1", at=NOW))

    def test_dead_mans_switch_pauses(self):
        ks = KillSwitch(heartbeat_timeout=timedelta(seconds=30))
        ks.register("scan1", at=NOW)
        self.assertTrue(ks.scan_may_probe("scan1", at=NOW))
        late = NOW + timedelta(seconds=31)
        self.assertFalse(ks.scan_may_probe("scan1", at=late))
        # resumes on heartbeat
        ks.heartbeat("scan1", at=late)
        self.assertTrue(ks.scan_may_probe("scan1", at=late))

    def test_unknown_scan_denied(self):
        ks = KillSwitch()
        self.assertFalse(ks.scan_may_probe("nope", at=NOW))


# --------------------------------------------------------------------------
# Policy engine — end-to-end, default-deny, fail-closed
# --------------------------------------------------------------------------
class TestPolicyEngine(unittest.TestCase):
    def _engine(self):
        self.audit = AuditLog()
        self.ks = KillSwitch()
        self.ks.register("scan1", at=NOW)
        return PolicyEngine(KEY, self.ks, self.audit)

    def _input(self, scope, grant, **over):
        al = AllowList(scope, resolver({"api.example.com": ["93.184.216.34"]}))
        target = al.resolve("https://api.example.com/v2/search?q=1")
        base = dict(
            scope=scope,
            grant=grant,
            target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id="scan1",
            at=NOW,
        )
        base.update(over)
        return PolicyInput(**base)

    def test_happy_path_allows_and_logs(self):
        eng = self._engine()
        s = make_scope(assets=(
            Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),
        ))
        g = make_grant(s)
        res = eng.evaluate(self._input(s, g))
        self.assertEqual(res.decision, Decision.ALLOW, res.reason)
        ok, _ = self.audit.verify()
        self.assertTrue(ok)
        self.assertEqual(self.audit.records()[-1].payload["decision"], "allow")

    def test_active_denied_when_ceiling_safe(self):
        eng = self._engine()
        s = make_scope(
            assets=(Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),),
            intensity_ceiling=Intensity.SAFE,
        )
        g = make_grant(s, max_intensity=Intensity.SAFE)
        res = eng.evaluate(self._input(s, g, requested_intensity=Intensity.ACTIVE))
        self.assertEqual(res.decision, Decision.DENY)
        self.assertIn("ceiling", res.reason)

    def test_mutating_side_effect_always_denied(self):
        eng = self._engine()
        s = make_scope(assets=(
            Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),
        ))
        g = make_grant(s)
        res = eng.evaluate(
            self._input(
                s, g,
                requested_intensity=Intensity.ACTIVE,
                side_effect=SideEffectClass.POTENTIALLY_MUTATING,
            )
        )
        self.assertEqual(res.decision, Decision.DENY)

    def test_abort_mid_pipeline_denies(self):
        eng = self._engine()
        s = make_scope(assets=(
            Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),
        ))
        g = make_grant(s)
        self.ks.abort("scan1")
        res = eng.evaluate(self._input(s, g))
        self.assertEqual(res.decision, Decision.DENY)

    def test_fail_closed_on_bad_input(self):
        eng = self._engine()
        # grant signed for a different scope version -> invalid, denied (not crash)
        s = make_scope(assets=(
            Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),
        ))
        g = make_grant(s, scope_version=99)
        res = eng.evaluate(self._input(s, g))
        self.assertEqual(res.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
