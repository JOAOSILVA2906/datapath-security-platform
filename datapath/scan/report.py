"""Report assembly & JSON export (spec 6.3).

Produces a machine-readable report from a ReconResult: scan metadata, findings
(sorted by severity, highest first), and a data-path graph summary. PDF / SARIF
export are later additions; JSON is the interchange format here.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .findings import Severity
from .recon import ReconResult

_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.NONE: 4,
}


def build_report(
    scope_ref: str, scan_id: str, result: ReconResult, generated_at: datetime | None = None
) -> dict:
    findings = sorted(
        result.findings, key=lambda f: (_ORDER[f.severity], -f.score)
    )
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return {
        "scan": {
            "scope_ref": scope_ref,
            "scan_id": scan_id,
            "mode": "SAFE / passive",
            "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
            "pages_fetched": result.pages_fetched,
            "skipped_out_of_scope": result.skipped_out_of_scope,
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
        },
        "findings": [f.to_dict() for f in findings],
        "data_path_graph": result.graph.summary(),
    }


def to_json(report: dict, indent: int = 2) -> str:
    return json.dumps(report, indent=indent, ensure_ascii=False)
