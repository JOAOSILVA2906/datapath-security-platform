"""Tests for the rate-limit / budget / backpressure engine (spec 1.5).

Time is passed in explicitly (``now`` in seconds), so these are deterministic
and never sleep.
"""

from __future__ import annotations

import unittest

from datapath.core import Admission, DenyReason, RateLimitConfig, RateLimiter
from datapath.core.ratelimit import HARD_MAX_CONCURRENCY, HARD_MAX_RPS


class TestConfig(unittest.TestCase):
    def test_hard_ceiling_blocks_without_elevation(self):
        with self.assertRaises(ValueError):
            RateLimitConfig(rps=HARD_MAX_RPS + 1)
        with self.assertRaises(ValueError):
            RateLimitConfig(max_concurrency=HARD_MAX_CONCURRENCY + 1)

    def test_elevation_allows_above_ceiling(self):
        cfg = RateLimitConfig(rps=HARD_MAX_RPS + 10, elevated=True)
        self.assertGreater(cfg.rps, HARD_MAX_RPS)


class TestRate(unittest.TestCase):
    def test_burst_then_throttle(self):
        rl = RateLimiter(RateLimitConfig(rps=2.0, burst=3, max_concurrency=10))
        t = "https://api.example.com/v2/"
        # 3 burst tokens available at t=0
        for _ in range(3):
            adm = rl.acquire(t, "acme", now=0.0)
            self.assertTrue(adm, adm.reason)
            rl.release(t)
        # 4th is rate-limited
        adm = rl.acquire(t, "acme", now=0.0)
        self.assertFalse(adm)
        self.assertEqual(adm.reason, DenyReason.RATE)
        self.assertGreater(adm.retry_after, 0)
        # after 1s at 2 rps, ~2 tokens refilled
        adm = rl.acquire(t, "acme", now=1.0)
        self.assertTrue(adm, adm.reason)


class TestConcurrency(unittest.TestCase):
    def test_concurrency_cap(self):
        rl = RateLimiter(RateLimitConfig(rps=40, burst=100, max_concurrency=2))
        t = "t1"
        self.assertTrue(rl.acquire(t, "acme", now=0.0))
        self.assertTrue(rl.acquire(t, "acme", now=0.0))
        adm = rl.acquire(t, "acme", now=0.0)
        self.assertFalse(adm)
        self.assertEqual(adm.reason, DenyReason.CONCURRENCY)
        rl.release(t)
        self.assertTrue(rl.acquire(t, "acme", now=0.0))


class TestBackpressure(unittest.TestCase):
    def test_5xx_reduces_effective_rate(self):
        rl = RateLimiter(RateLimitConfig(rps=10, burst=10, max_concurrency=10))
        t = "t1"
        rl.acquire(t, "acme", now=0.0)
        self.assertEqual(rl.effective_rps(t), 10.0)
        rl.record_response(t, status=503, latency=0.1, now=0.0)
        self.assertEqual(rl.effective_rps(t), 5.0)  # halved
        rl.record_response(t, status=503, latency=0.1, now=0.0)
        self.assertEqual(rl.effective_rps(t), 2.5)

    def test_retry_after_sets_cooldown(self):
        rl = RateLimiter(RateLimitConfig(rps=10, burst=10, max_concurrency=10))
        t = "t1"
        rl.acquire(t, "acme", now=0.0)
        rl.record_response(t, status=429, latency=0.1, retry_after=30.0, now=0.0)
        adm = rl.acquire(t, "acme", now=5.0)
        self.assertFalse(adm)
        self.assertEqual(adm.reason, DenyReason.COOLDOWN)
        self.assertAlmostEqual(adm.retry_after, 25.0, places=3)
        # after cooldown passes
        self.assertTrue(rl.acquire(t, "acme", now=31.0))

    def test_recovery_is_gradual(self):
        rl = RateLimiter(RateLimitConfig(rps=10, burst=10, max_concurrency=10,
                                         increase=0.05))
        t = "t1"
        rl.record_response(t, status=503, latency=0.1, now=0.0)  # factor 0.5
        self.assertEqual(rl.effective_rps(t), 5.0)
        rl.record_response(t, status=200, latency=0.1, now=0.0)  # +0.05
        self.assertAlmostEqual(rl.effective_rps(t), 5.5, places=3)

    def test_high_latency_is_trouble(self):
        rl = RateLimiter(RateLimitConfig(rps=10, burst=10, max_concurrency=10,
                                         latency_ceiling=1.0))
        t = "t1"
        rl.record_response(t, status=200, latency=2.0, now=0.0)
        self.assertEqual(rl.effective_rps(t), 5.0)


class TestBudgets(unittest.TestCase):
    def test_tenant_budget(self):
        rl = RateLimiter(RateLimitConfig(rps=40, burst=100, max_concurrency=20))
        rl.set_tenant_budget("acme", 2)
        t = "t1"
        self.assertTrue(rl.acquire(t, "acme", now=0.0))
        self.assertTrue(rl.acquire(t, "acme", now=0.0))
        adm = rl.acquire(t, "acme", now=0.0)
        self.assertFalse(adm)
        self.assertEqual(adm.reason, DenyReason.TENANT_BUDGET)
        # a different tenant is unaffected
        self.assertTrue(rl.acquire(t, "other", now=0.0))

    def test_global_budget(self):
        rl = RateLimiter(RateLimitConfig(rps=40, burst=100, max_concurrency=20),
                         global_budget=1)
        self.assertTrue(rl.acquire("t1", "acme", now=0.0))
        adm = rl.acquire("t2", "other", now=0.0)
        self.assertFalse(adm)
        self.assertEqual(adm.reason, DenyReason.GLOBAL_BUDGET)

    def test_denied_request_does_not_charge_budget(self):
        rl = RateLimiter(RateLimitConfig(rps=1, burst=1, max_concurrency=1))
        rl.set_tenant_budget("acme", 10)
        t = "t1"
        self.assertTrue(rl.acquire(t, "acme", now=0.0))   # uses the 1 token
        rl.release(t)
        rl.acquire(t, "acme", now=0.0)                    # rate-denied
        # only the successful acquire charged the budget
        self.assertEqual(rl._tenant_budget("acme").used, 1)


if __name__ == "__main__":
    unittest.main()
