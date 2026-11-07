"""Phase-3 tests: capability modelling and the attack-path planner."""

from __future__ import annotations

import unittest

from datapath.chain import (
    START_ANONYMOUS,
    AttackPathPlanner,
    Capability,
    enumeration_capability,
    recon_capability,
)
from datapath.confirm import ActiveConfirmer, BoundaryKind, BoundaryProof, Confirmation
from datapath.chain.capability import capability_from_bola


def _bola_conf() -> Confirmation:
    return Confirmation(
        confirmed=True,
        narrative="x",
        boundary=BoundaryProof(BoundaryKind.CROSS_TENANT_READ,
                               "marcador B presente; 1 registro"),
        http_status=200,
    )


class TestCapability(unittest.TestCase):
    def test_applicable_requires_preconditions(self):
        cap = Capability("c", "d", requires={"a"}, grants={"b"}, reachability=0.5)
        self.assertFalse(cap.applicable(frozenset()))
        self.assertTrue(cap.applicable(frozenset({"a"})))

    def test_not_applicable_if_already_granted(self):
        cap = Capability("c", "d", requires={"a"}, grants={"b"}, reachability=0.5)
        self.assertFalse(cap.applicable(frozenset({"a", "b"})))

    def test_reachability_bounds(self):
        with self.assertRaises(ValueError):
            Capability("c", "d", requires=set(), grants={"b"}, reachability=0)
        with self.assertRaises(ValueError):
            Capability("c", "d", requires=set(), grants={"b"}, reachability=1.1)


class TestPlanner(unittest.TestCase):
    def _caps(self):
        return [
            recon_capability(),                     # anon -> endpoints_known
            enumeration_capability(0.8),            # +endpoints -> object_id_known
            capability_from_bola(_bola_conf(),      # +object_id_known -> cross_tenant_read
                                 requires={"anonymous", "object_id_known"}),
        ]

    def test_finds_canonical_data_exposure_path(self):
        planner = AttackPathPlanner(self._caps(), START_ANONYMOUS)
        paths = planner.plan()
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p.reached, "cross_tenant_read")
        # chain is recon -> enumerate -> bola
        self.assertEqual([c.cap_id for c in p.steps],
                         ["surface-mapping", "id-enumeration", "bola-confirmed"])
        # reachability = 0.95 * 0.8 * 0.9
        self.assertAlmostEqual(p.reachability, 0.95 * 0.8 * 0.9, places=4)
        self.assertEqual(p.impact, 90)
        self.assertAlmostEqual(p.score, 0.95 * 0.8 * 0.9 * 90, places=2)

    def test_path_stops_at_boundary(self):
        # add a capability that would chain FURTHER past the boundary; planner
        # must not use it (the path ends at the sensitive state).
        caps = self._caps() + [
            Capability("post-boundary", "não deveria aparecer",
                       requires={"cross_tenant_read"}, grants={"more"},
                       reachability=1.0),
        ]
        paths = AttackPathPlanner(caps, START_ANONYMOUS).plan()
        self.assertEqual(len(paths), 1)
        self.assertNotIn("post-boundary", [c.cap_id for c in paths[0].steps])

    def test_no_path_when_boundary_unreachable(self):
        # recon + enumeration only, no capability granting a sensitive state
        caps = [recon_capability(), enumeration_capability()]
        self.assertEqual(AttackPathPlanner(caps, START_ANONYMOUS).plan(), [])

    def test_ranking_prefers_higher_reachability_weighted_risk(self):
        # two independent boundaries; the higher score ranks first
        high = Capability("h", "alto", requires={"anonymous"},
                          grants={"cross_tenant_read"}, reachability=0.9, impact=90)
        low = Capability("l", "baixo", requires={"anonymous"},
                         grants={"privileged_function"}, reachability=0.3, impact=50)
        paths = AttackPathPlanner([high, low], START_ANONYMOUS).plan()
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[0].reached, "cross_tenant_read")
        self.assertGreater(paths[0].score, paths[1].score)

    def test_narrative_ends_with_boundary(self):
        p = AttackPathPlanner(self._caps(), START_ANONYMOUS).plan()[0]
        narr = p.narrative()
        self.assertTrue(narr[-1].startswith("■ LIMITE SENSÍVEL"))
        self.assertIn("cross_tenant_read", narr[-1])


if __name__ == "__main__":
    unittest.main()
