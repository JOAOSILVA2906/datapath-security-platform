"""Tests for platform self-protection controls (review fix #7):
dual control and the scoped credential vault."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from datapath.core import (
    ChangeStatus,
    CredentialVault,
    DualControl,
    DualControlError,
    VaultError,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


class TestDualControl(unittest.TestCase):
    def _dc(self):
        dc = DualControl(default_min_approvals=1)
        dc.request("r1", "allowlist.add", {"host": "x.example.com"}, "alice", at=NOW)
        return dc

    def test_requester_cannot_self_approve(self):
        dc = self._dc()
        with self.assertRaises(DualControlError):
            dc.approve("r1", "alice")

    def test_second_person_approves(self):
        dc = self._dc()
        req = dc.approve("r1", "bob")
        self.assertEqual(req.status, ChangeStatus.APPROVED)
        self.assertTrue(req.is_approved)

    def test_cannot_apply_without_approval(self):
        dc = self._dc()
        with self.assertRaises(DualControlError):
            dc.apply("r1")

    def test_apply_after_approval(self):
        dc = self._dc()
        dc.approve("r1", "bob")
        req = dc.apply("r1")
        self.assertEqual(req.status, ChangeStatus.APPLIED)

    def test_two_distinct_approvers_required(self):
        dc = DualControl(default_min_approvals=2)
        dc.request("r2", "policy.relax", {"x": 1}, "alice", at=NOW)
        dc.approve("r2", "bob")
        self.assertEqual(dc.get("r2").status, ChangeStatus.PENDING)
        with self.assertRaises(DualControlError):
            dc.approve("r2", "bob")  # same approver twice
        dc.approve("r2", "carol")
        self.assertEqual(dc.get("r2").status, ChangeStatus.APPROVED)

    def test_rejected_cannot_apply(self):
        dc = self._dc()
        dc.reject("r1", "bob")
        with self.assertRaises(DualControlError):
            dc.apply("r1")


class TestCredentialVault(unittest.TestCase):
    def _vault(self):
        return CredentialVault.dev(b"dev-key-at-least-16-bytes-long")

    def test_seal_unseal_roundtrip(self):
        v = self._vault()
        v.store("c1", b"s3cr3t-token")
        lease = v.lease("c1", "scan1", timedelta(minutes=5), at=NOW)
        self.assertEqual(v.use(lease.lease_token, at=NOW), b"s3cr3t-token")

    def test_secret_never_in_repr(self):
        v = self._vault()
        v.store("c1", b"s3cr3t-token")
        lease = v.lease("c1", "scan1", timedelta(minutes=5), at=NOW)
        self.assertNotIn("s3cr3t", repr(lease))

    def test_lease_expires(self):
        v = self._vault()
        v.store("c1", b"tok")
        lease = v.lease("c1", "scan1", timedelta(seconds=30), at=NOW)
        with self.assertRaises(VaultError):
            v.use(lease.lease_token, at=NOW + timedelta(seconds=31))

    def test_revoke_scan_kills_leases(self):
        v = self._vault()
        v.store("c1", b"tok")
        l1 = v.lease("c1", "scanA", timedelta(minutes=5), at=NOW)
        v.lease("c1", "scanA", timedelta(minutes=5), at=NOW)
        self.assertEqual(v.active_lease_count(), 2)
        self.assertEqual(v.revoke_scan("scanA"), 2)
        with self.assertRaises(VaultError):
            v.use(l1.lease_token, at=NOW)

    def test_rotation_invalidates_leases(self):
        v = self._vault()
        v.store("c1", b"old")
        lease = v.lease("c1", "scan1", timedelta(minutes=5), at=NOW)
        v.rotate("c1", b"new")
        with self.assertRaises(VaultError):
            v.use(lease.lease_token, at=NOW)
        # a fresh lease gets the new secret
        lease2 = v.lease("c1", "scan1", timedelta(minutes=5), at=NOW)
        self.assertEqual(v.use(lease2.lease_token, at=NOW), b"new")

    def test_tamper_detected_by_sealer(self):
        from datapath.core.vault import _DevSealer

        s = _DevSealer(b"dev-key-at-least-16-bytes-long")
        blob = bytearray(s.seal(b"hello"))
        blob[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            s.unseal(bytes(blob))

    def test_fingerprint_stable_and_not_secret(self):
        v = self._vault()
        fp1 = v.store("c1", b"tok")
        fp2 = v.store("c2", b"tok")
        self.assertEqual(fp1, fp2)  # same secret -> same fingerprint
        self.assertNotIn("tok", fp1)


if __name__ == "__main__":
    unittest.main()
