"""Phase-4 tests: tickets, SARIF, retest attestation, posture, notifications."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from datapath.scan.findings import Finding
from datapath.remediate import (
    Notifier,
    Retester,
    RetestResult,
    ScanRecord,
    build_slack_message,
    posture_summary,
    recurring_classes,
    time_to_remediate,
    to_github_issue,
    to_jira_issue,
    to_sarif,
)

KEY = b"phase4-key"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _finding(check_id="missing-csp", url="https://t/"):
    return Finding(
        check_id=check_id, title="CSP ausente",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        affected_url=url, evidence="sem CSP", fix="defina um CSP",
    )


class TestTickets(unittest.TestCase):
    def test_github_issue(self):
        iss = to_github_issue(_finding())
        self.assertIn("CSP ausente", iss["title"])
        self.assertIn("datapath", iss["labels"])
        self.assertIn("CVSS", iss["body"])

    def test_jira_issue(self):
        iss = to_jira_issue(_finding(), project_key="APP")
        self.assertEqual(iss["fields"]["project"]["key"], "APP")
        self.assertIn("priority", iss["fields"])


class TestSarif(unittest.TestCase):
    def test_sarif_structure(self):
        s = to_sarif([_finding(), _finding(check_id="missing-hsts")])
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(len(run["results"]), 2)
        # CVSS carried for code-scanning consumers
        self.assertIn("security-severity", run["results"][0]["properties"])


class TestRetest(unittest.TestCase):
    def test_remediated_attestation_signed(self):
        rt = Retester(KEY)
        att = rt.retest("missing-csp", "https://t/", "acme@v1", "retest-1",
                        runner=lambda: False, at=NOW)
        self.assertEqual(att.result, RetestResult.REMEDIATED)
        self.assertTrue(att.signature_valid(KEY))
        self.assertIn("apenas a verificação", att.coverage)

    def test_still_present_attestation(self):
        rt = Retester(KEY)
        att = rt.retest("missing-csp", "https://t/", "acme@v1", "retest-2",
                        runner=lambda: True, at=NOW)
        self.assertEqual(att.result, RetestResult.STILL_PRESENT)

    def test_tampered_attestation_fails(self):
        import dataclasses
        rt = Retester(KEY)
        att = rt.retest("x", "https://t/", "acme@v1", "r", runner=lambda: False, at=NOW)
        forged = dataclasses.replace(att, result=RetestResult.STILL_PRESENT)
        self.assertFalse(forged.signature_valid(KEY))


class TestPosture(unittest.TestCase):
    def _scans(self):
        f = ("missing-csp", "https://t/")
        g = ("missing-hsts", "https://t/")
        return [
            ScanRecord("s1", NOW, {f, g}),
            ScanRecord("s2", NOW + timedelta(days=10), {g}),       # f fixed
            ScanRecord("s3", NOW + timedelta(days=20), set()),     # g fixed
        ]

    def test_time_to_remediate(self):
        ttr = time_to_remediate(self._scans())
        self.assertAlmostEqual(ttr[("missing-csp", "https://t/")], 10.0)
        self.assertAlmostEqual(ttr[("missing-hsts", "https://t/")], 20.0)

    def test_recurring_classes(self):
        rec = recurring_classes(self._scans(), min_scans=2)
        self.assertIn("missing-hsts", rec)      # in s1 and s2
        self.assertNotIn("missing-csp", rec)    # only s1

    def test_posture_summary(self):
        s = posture_summary(self._scans())
        self.assertEqual(s["scans"], 3)
        self.assertEqual(s["resolved_count"], 2)
        self.assertEqual(s["avg_days_to_remediate"], 15.0)
        self.assertEqual(s["open_trend"], [("s1", 2), ("s2", 1), ("s3", 0)])


class TestNotify(unittest.TestCase):
    def test_slack_payload_and_sender(self):
        sent = []
        n = Notifier(lambda p: sent.append(p))
        payload = build_slack_message("acme@v1",
                                      {"total_findings": 16, "by_severity": {"high": 1, "medium": 12, "low": 3}},
                                      top_path="anônimo → BOLA → tenant B")
        n.notify(payload)
        self.assertEqual(len(sent), 1)
        self.assertIn("16", sent[0]["text"])
        self.assertTrue(any("crítico" not in b.get("text", {}).get("text", "")
                            for b in sent[0]["blocks"]))


if __name__ == "__main__":
    unittest.main()
