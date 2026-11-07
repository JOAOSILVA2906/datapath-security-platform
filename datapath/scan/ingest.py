"""Customer-provided context ingestion (spec 3.3).

An OpenAPI document is ground truth for endpoints/parameters — safer and more
accurate than blind discovery. This parses an OpenAPI (v3) dict into the
data-path graph without any network access. HAR ingestion follows the same
shape (left for a later pass).
"""

from __future__ import annotations

from urllib.parse import urljoin

from .graph import DataPathGraph, EdgeKind, NodeKind


def ingest_openapi(graph: DataPathGraph, spec: dict, base_url: str = "") -> int:
    """Add endpoints and parameters from an OpenAPI v3 dict. Returns node count added."""
    added = 0
    servers = spec.get("servers") or []
    server = base_url or (servers[0].get("url") if servers else "")
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        endpoint = urljoin(server + "/" if server and not server.endswith("/") else server, path.lstrip("/")) if server else path
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            node_id = f"{method.upper()} {endpoint}"
            graph.add_node(node_id, NodeKind.API, label=node_id,
                           method=method.upper(), source="openapi")
            added += 1
            params = (op or {}).get("parameters", []) if isinstance(op, dict) else []
            for p in params:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name")
                if not pname:
                    continue
                pid = f"{node_id}#{pname}"
                graph.add_node(pid, NodeKind.PARAM, label=pname,
                               location=str(p.get("in", "")))
                graph.add_edge(node_id, pid, EdgeKind.HAS_PARAM)
                added += 1
    return added
