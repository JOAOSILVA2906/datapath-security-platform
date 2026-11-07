"""DataPath Phase 1 — safe-mode recon, passive detection, and reporting.

Everything here runs THROUGH the Phase-0 gate: the GatedEgress sends a request
only after the policy engine (default-deny, fail-closed) and the SSRF-safe
allow-list approve it, bounded by the rate limiter and kill switch. Phase 1 is
SAFE/PASSIVE only — read-only GETs, no crafted input, no exploitation.
"""

from .findings import Finding, Severity, cvss31_base
from .graph import DataPathGraph, EdgeKind, Node, NodeKind
from .egress import EgressDenied, GatedEgress, HttpResponse, ReducedResponse
from .detectors import run_all
from .recon import Recon, ReconResult
from .ingest import ingest_openapi
from .report import build_report, to_json

__all__ = [
    "Finding",
    "Severity",
    "cvss31_base",
    "DataPathGraph",
    "EdgeKind",
    "Node",
    "NodeKind",
    "EgressDenied",
    "GatedEgress",
    "HttpResponse",
    "ReducedResponse",
    "run_all",
    "Recon",
    "ReconResult",
    "ingest_openapi",
    "build_report",
    "to_json",
]
