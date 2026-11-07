"""Findings, severity, and a correct CVSS v3.1 base-score calculator.

A Finding is the unit of the report (spec 6.1): title, OWASP class, severity
(a CVSS vector + computed base score, plus a qualitative band), the affected
asset, redacted evidence, and concrete fix guidance.

The CVSS v3.1 base score is computed from the vector string using the published
formula, so numbers are defensible rather than invented.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass, field


# --- CVSS v3.1 base score --------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup: smallest 1-decimal number >= x (integer-math safe)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31_base(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string.

    Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8
    """
    parts = {}
    for item in vector.split("/"):
        if ":" in item and not item.startswith("CVSS"):
            k, v = item.split(":", 1)
            parts[k] = v
    try:
        av, ac, pr, ui = _AV[parts["AV"]], _AC[parts["AC"]], parts["PR"], _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError as exc:
        raise ValueError(f"invalid or incomplete CVSS vector: {vector!r}") from exc

    pr_val = (_PR_C if scope_changed else _PR_U)[pr]
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr_val * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


class Severity(enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score == 0:
            return cls.NONE
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


@dataclass(frozen=True)
class Finding:
    check_id: str                   # which detector produced it
    title: str
    owasp: str                      # e.g. "A05:2021 Security Misconfiguration"
    cvss_vector: str
    affected_url: str
    evidence: str                   # short, redacted
    fix: str                        # concrete remediation guidance
    description: str = ""

    @property
    def score(self) -> float:
        return cvss31_base(self.cvss_vector)

    @property
    def severity(self) -> Severity:
        return Severity.from_score(self.score)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "owasp": self.owasp,
            "severity": self.severity.value,
            "cvss_score": self.score,
            "cvss_vector": self.cvss_vector,
            "affected_url": self.affected_url,
            "evidence": self.evidence,
            "description": self.description,
            "fix": self.fix,
        }
