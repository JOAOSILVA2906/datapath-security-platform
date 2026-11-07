"""Phase-1 tests: CVSS, detectors, gated egress, recon, ingestion, report.

A fake in-memory transport stands in for the network, so these are
deterministic and offline. The fake serves a deliberately misconfigured
"training" app.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from datapath.core import (
    AllowList,
    Asset,
    AssetKind,
    AuditLog,
    Intensity,
    KillSwitch,
    PolicyEngine,
    RateLimiter,
    Scope,
    TestWindow,
)
from datapath.scan import (
    DataPathGraph,
    GatedEgress,
    HttpResponse,
    Recon,
    build_report,
    cvss31_base,
    ingest_openapi,
    run_all,
)
from datapath.scan.egress import EgressDenied

from .conftest import KEY, NOW, make_grant


# --------------------------------------------------------------------------
# CVSS
# --------------------------------------------------------------------------
class TestCVSS(unittest.TestCase):
    def test_known_vectors(self):
        self.assertAlmostEqual(
            cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertAlmostEqual(
            cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertAlmostEqual(
            cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), 5.3)
        # classic reflected-XSS scope-changed sample
        self.assertAlmostEqual(
            cvss31_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------
def _resp(status=200, headers=None, body=b"", url="https://t/"):
    return HttpResponse(status, headers or {}, body, 0.1, url)


class TestDetectors(unittest.TestCase):
    def test_missing_security_headers(self):
        f = run_all("https://t/", _resp(headers={"Content-Type": "text/html"}))
        ids = {x.check_id for x in f}
        self.assertIn("missing-csp", ids)
        self.assertIn("missing-xcto", ids)

    def test_cors_wildcard_with_credentials_is_high(self):
        r = _resp(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        })
        f = [x for x in run_all("https://t/", r) if x.check_id == "cors-wildcard-credentials"]
        self.assertEqual(len(f), 1)
        self.assertGreaterEqual(f[0].score, 7.0)

    def test_verbose_error(self):
        r = _resp(body=b"Fatal error: Uncaught PDOException: SQLSTATE[42000]")
        f = [x for x in run_all("https://t/", r) if x.check_id == "verbose-error"]
        self.assertEqual(len(f), 1)

    def test_insecure_cookie(self):
        r = _resp(headers={"Set-Cookie": "session=abc; Path=/"})
        f = [x for x in run_all("https://t/", r) if x.check_id == "insecure-cookie"]
        self.assertEqual(len(f), 1)

    def test_secure_cookie_no_finding(self):
        r = _resp(headers={"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"})
        f = [x for x in run_all("https://t/", r) if x.check_id == "insecure-cookie"]
        self.assertEqual(len(f), 0)


# --------------------------------------------------------------------------
# Gated egress — the safety centerpiece
# --------------------------------------------------------------------------
class TestGatedEgress(unittest.TestCase):
    def _build(self, assets, transport, scan_id="scan1"):
        scope = Scope(
            scope_id="train", version=1, assets=assets,
            windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
            intensity_ceiling=Intensity.SAFE,
        )
        grant = make_grant(scope, verifier_evidence="train.example.com")
        audit = AuditLog()
        ks = KillSwitch()
        ks.register(scan_id, at=NOW)
        policy = PolicyEngine(KEY, ks, audit)
        rl = RateLimiter()
        clock = [0.0]
        eg = GatedEgress(
            scope=scope, grant=grant, signing_key=KEY,
            allowlist=AllowList(scope, lambda h: {"train.example.com": ["93.184.216.34"]}.get(h, [])),
            policy=policy, rate_limiter=rl, kill_switch=ks, transport=transport,
            tenant="acme", scan_id=scan_id, audit=audit,
            clock=lambda: clock[0],
        )
        return eg, audit, ks

    def test_in_scope_fetch_allowed_and_audited(self):
        def transport(target, headers):
            # honest attribution header must be present
            assert headers["X-DataPath-Scan-Id"] == "scan1"
            return _resp(headers={"Content-Type": "text/html"}, body=b"<html>ok</html>")
        assets = (Asset(AssetKind.URL_PREFIX, "https://train.example.com/"),)
        eg, audit, _ = self._build(assets, transport)
        resp = eg.get("https://train.example.com/", at=NOW)
        self.assertEqual(resp.status, 200)
        self.assertEqual(audit.records()[-1].event_type, "egress_probe")
        self.assertEqual(audit.records()[-1].payload["mode"], "SAFE/PASSIVE")

    def test_out_of_scope_refused(self):
        called = []
        def transport(target, headers):
            called.append(1)
            return _resp()
        assets = (Asset(AssetKind.URL_PREFIX, "https://train.example.com/"),)
        eg, _, _ = self._build(assets, transport)
        with self.assertRaises(EgressDenied):
            eg.get("https://evil.example.net/", at=NOW)
        self.assertEqual(called, [])  # transport never invoked

    def test_kill_switch_blocks_fetch(self):
        def transport(target, headers):
            return _resp()
        assets = (Asset(AssetKind.URL_PREFIX, "https://train.example.com/"),)
        eg, _, ks = self._build(assets, transport)
        ks.abort("scan1")
        with self.assertRaises(EgressDenied):
            eg.get("https://train.example.com/", at=NOW)

    def test_localhost_requires_explicit_scope(self):
        # Loopback is SSRF-blocked unless it's an explicit in-scope asset.
        def transport(target, headers):
            return _resp()
        assets = (Asset(AssetKind.URL_PREFIX, "http://localhost/"),)
        eg, _, _ = self._build_local(assets, transport, resolve={"localhost": ["127.0.0.1"]})
        with self.assertRaises(EgressDenied):
            eg.get("http://localhost/", at=NOW)
        # now add the loopback as an explicit internal asset
        assets2 = (
            Asset(AssetKind.URL_PREFIX, "http://localhost/"),
            Asset(AssetKind.CIDR, "127.0.0.1/32"),
        )
        eg2, _, _ = self._build_local(assets2, transport, resolve={"localhost": ["127.0.0.1"]})
        self.assertEqual(eg2.get("http://localhost/", at=NOW).status, 200)

    def _build_local(self, assets, transport, resolve):
        scope = Scope(
            scope_id="train", version=1, assets=assets,
            windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
            intensity_ceiling=Intensity.SAFE,
        )
        grant = make_grant(scope, verifier_evidence="localhost")
        audit = AuditLog()
        ks = KillSwitch()
        ks.register("scan1", at=NOW)
        policy = PolicyEngine(KEY, ks, audit)
        eg = GatedEgress(
            scope=scope, grant=grant, signing_key=KEY,
            allowlist=AllowList(scope, lambda h: resolve.get(h, [])),
            policy=policy, rate_limiter=RateLimiter(), kill_switch=ks,
            transport=transport, tenant="acme", scan_id="scan1", audit=audit,
            clock=lambda: 0.0,
        )
        return eg, audit, ks


# --------------------------------------------------------------------------
# Recon end-to-end against a fake training app
# --------------------------------------------------------------------------
FAKE_PAGES = {
    "https://train.example.com/": _resp(
        headers={"Content-Type": "text/html", "Server": "nginx/1.18.0",
                 "Set-Cookie": "session=xyz; Path=/"},
        body=b'<html><a href="/login">login</a>'
             b'<script>fetch("/api/v2/users?id=1")</script></html>',
        url="https://train.example.com/"),
    "https://train.example.com/login": _resp(
        headers={"Content-Type": "text/html"},
        body=b"<html>login page</html>",
        url="https://train.example.com/login"),
    "https://train.example.com/api/v2/users?id=1": _resp(
        headers={"Content-Type": "application/json",
                 "Access-Control-Allow-Origin": "*",
                 "Access-Control-Allow-Credentials": "true"},
        body=b'{"id":1}',
        url="https://train.example.com/api/v2/users?id=1"),
}


class TestReconAndReport(unittest.TestCase):
    def _egress(self, scan_id="scan1"):
        scope = Scope(
            scope_id="train", version=1,
            assets=(Asset(AssetKind.URL_PREFIX, "https://train.example.com/"),),
            windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
            intensity_ceiling=Intensity.SAFE,
        )
        grant = make_grant(scope, verifier_evidence="train.example.com")
        ks = KillSwitch(); ks.register(scan_id, at=NOW)
        policy = PolicyEngine(KEY, ks, AuditLog())

        def transport(target, headers):
            return FAKE_PAGES.get(target.url, _resp(status=404, url=target.url))

        from datetime import datetime, timezone
        eg = GatedEgress(
            scope=scope, grant=grant, signing_key=KEY,
            allowlist=AllowList(scope, lambda h: {"train.example.com": ["93.184.216.34"]}.get(h, [])),
            policy=policy, rate_limiter=RateLimiter(), kill_switch=ks,
            transport=transport, tenant="acme", scan_id=scan_id,
            clock=lambda: 0.0,
        )
        # Recon calls egress.get without an explicit `at`; patch to fixed time.
        orig = eg.get
        eg.get = lambda url, at=None: orig(url, at=NOW)  # type: ignore
        return eg, scope

    def test_recon_builds_graph_and_findings(self):
        eg, scope = self._egress()
        result = Recon(eg, max_pages=10).run(["https://train.example.com/"])
        self.assertGreaterEqual(result.pages_fetched, 2)
        # graph saw the API reference
        ids = {n.node_id for n in result.graph.nodes()}
        self.assertTrue(any("/api/v2/users" in i for i in ids))
        # findings include the high-severity CORS issue
        cids = {f.check_id for f in result.findings}
        self.assertIn("cors-wildcard-credentials", cids)
        self.assertIn("insecure-cookie", cids)

    def test_report_sorted_by_severity(self):
        eg, scope = self._egress()
        result = Recon(eg, max_pages=10).run(["https://train.example.com/"])
        report = build_report(scope.ref, "scan1", result)
        sevs = [f["cvss_score"] for f in report["findings"]]
        self.assertEqual(sevs, sorted(sevs, reverse=True))
        self.assertEqual(report["scan"]["mode"], "SAFE / passive")


# --------------------------------------------------------------------------
# OpenAPI ingestion
# --------------------------------------------------------------------------
class TestIngest(unittest.TestCase):
    def test_openapi_adds_endpoints_and_params(self):
        g = DataPathGraph()
        spec = {
            "servers": [{"url": "https://train.example.com"}],
            "paths": {
                "/users/{id}": {
                    "get": {"parameters": [{"name": "id", "in": "path"}]},
                },
                "/search": {
                    "get": {"parameters": [{"name": "q", "in": "query"}]},
                },
            },
        }
        added = ingest_openapi(g, spec)
        self.assertEqual(added, 4)  # 2 endpoints + 2 params
        labels = {n.label for n in g.nodes()}
        self.assertIn("id", labels)
        self.assertIn("q", labels)


if __name__ == "__main__":
    unittest.main()
