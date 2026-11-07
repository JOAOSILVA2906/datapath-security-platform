"""Trend & posture reporting over repeat engagements (spec 6.2).

Given a chronological list of scan records, computes the metrics that justify an
ongoing subscription: time-to-remediate, recurring finding classes, and the
open/closed trend across engagements.

A ScanRecord is intentionally small: when it ran, and the set of (check_id,
affected_url) findings open at that time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    at: datetime
    open_findings: frozenset[tuple[str, str]]  # (check_id, affected_url)

    def __post_init__(self) -> None:
        object.__setattr__(self, "open_findings", frozenset(self.open_findings))


def time_to_remediate(scans: list[ScanRecord]) -> dict[tuple[str, str], float]:
    """Days from first-seen to first-absent, per finding. Only resolved ones."""
    scans = sorted(scans, key=lambda s: s.at)
    first_seen: dict[tuple[str, str], datetime] = {}
    resolved: dict[tuple[str, str], float] = {}
    for s in scans:
        for key in s.open_findings:
            first_seen.setdefault(key, s.at)
        # anything previously seen and now absent is resolved at this scan
        for key, seen_at in list(first_seen.items()):
            if key not in s.open_findings and key not in resolved:
                resolved[key] = (s.at - seen_at).total_seconds() / 86400.0
    return resolved


def recurring_classes(scans: list[ScanRecord], min_scans: int = 2) -> dict[str, int]:
    """check_ids that appear open in at least ``min_scans`` distinct scans."""
    counts: dict[str, int] = {}
    for s in scans:
        for check_id in {k[0] for k in s.open_findings}:
            counts[check_id] = counts.get(check_id, 0) + 1
    return {c: n for c, n in sorted(counts.items(), key=lambda x: -x[1]) if n >= min_scans}


def open_trend(scans: list[ScanRecord]) -> list[tuple[str, int]]:
    """Open-finding count per scan, in time order."""
    return [(s.scan_id, len(s.open_findings))
            for s in sorted(scans, key=lambda s: s.at)]


def posture_summary(scans: list[ScanRecord]) -> dict:
    ttr = time_to_remediate(scans)
    avg = round(sum(ttr.values()) / len(ttr), 2) if ttr else None
    return {
        "scans": len(scans),
        "resolved_count": len(ttr),
        "avg_days_to_remediate": avg,
        "recurring_classes": recurring_classes(scans),
        "open_trend": open_trend(scans),
    }
