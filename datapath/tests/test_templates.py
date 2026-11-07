"""Tests for scanner-template supply-chain vetting (review fix #9)."""

from __future__ import annotations

import hashlib
import unittest

from datapath.core import (
    Intensity,
    TemplateManifest,
    TemplateVerdict,
    TemplateVetter,
)
from datapath.core.templates import SideEffectClass


def man(tid: str, tags, content: bytes = b"body", source="nuclei") -> TemplateManifest:
    return TemplateManifest(template_id=tid, tags=tuple(tags), content=content,
                            source=source)


def pin(*manifests: TemplateManifest) -> dict[str, str]:
    return {m.template_id: m.content_hash for m in manifests}


class TestTemplateVetter(unittest.TestCase):
    def test_passive_template_allowed(self):
        m = man("exposed-panel", ["info", "detect"])
        v = TemplateVetter(pinned=pin(m))
        r = v.vet(m)
        self.assertTrue(r.allowed, r.reason)
        self.assertEqual(r.side_effect, SideEffectClass.PASSIVE)

    def test_unpinned_blocked(self):
        m = man("random", ["info"])
        v = TemplateVetter(pinned={})
        self.assertFalse(v.vet(m).allowed)
        self.assertIn("pinned", v.vet(m).reason)

    def test_hash_mismatch_blocked(self):
        m = man("t1", ["info"], content=b"original")
        pinned = pin(m)
        tampered = man("t1", ["info"], content=b"MALICIOUS")
        v = TemplateVetter(pinned=pinned)
        r = v.vet(tampered)
        self.assertFalse(r.allowed)
        self.assertIn("hash mismatch", r.reason)

    def test_forbidden_tag_blocked(self):
        m = man("flooder", ["info", "dos"])
        v = TemplateVetter(pinned=pin(m))
        r = v.vet(m)
        self.assertFalse(r.allowed)
        self.assertIn("forbidden", r.reason)

    def test_intrusive_and_fuzz_blocked(self):
        for tag in ("intrusive", "fuzz", "bruteforce"):
            m = man(f"t-{tag}", ["info", tag])
            v = TemplateVetter(pinned=pin(m))
            self.assertFalse(v.vet(m).allowed, tag)

    def test_unmapped_tag_blocked_by_default(self):
        m = man("mystery", ["info", "some-new-tag"])
        v = TemplateVetter(pinned=pin(m))
        r = v.vet(m)
        self.assertFalse(r.allowed)
        self.assertIn("unmapped", r.reason)

    def test_benign_payload_resolves_to_most_severe(self):
        m = man("sqli-detect", ["info", "sqli"])
        v = TemplateVetter(pinned=pin(m))
        r = v.vet(m)
        self.assertTrue(r.allowed, r.reason)
        self.assertEqual(r.side_effect, SideEffectClass.BENIGN_PAYLOAD)

    def test_benign_payload_blocked_at_safe_intensity(self):
        m = man("sqli-detect", ["sqli"])
        v = TemplateVetter(pinned=pin(m))
        self.assertFalse(v.permitted_at(m, Intensity.SAFE).allowed)
        self.assertTrue(v.permitted_at(m, Intensity.ACTIVE).allowed)

    def test_passive_allowed_at_safe_intensity(self):
        m = man("headers", ["headers"])
        v = TemplateVetter(pinned=pin(m))
        self.assertTrue(v.permitted_at(m, Intensity.SAFE).allowed)


if __name__ == "__main__":
    unittest.main()
