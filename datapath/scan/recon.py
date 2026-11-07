"""Passive surface mapping (spec 3.1) + detection orchestration.

Crawls in-scope pages through the GatedEgress (so anything out of scope is
dropped automatically), parses each page for links and API references, builds
the data-path graph, and runs the passive detectors on every response.

Passive-first: it only issues GETs a normal browser would, bounded by the
rate limiter and a page budget. Links/APIs that the gate refuses are skipped
and counted, never forced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .detectors import run_all
from .egress import EgressDenied, GatedEgress, HttpResponse
from .findings import Finding
from .graph import DataPathGraph, EdgeKind, NodeKind

# Links in HTML and API references in inline JS.
_HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_API_REF = re.compile(
    r"""["'](/(?:api|v\d|graphql|rest)[^"'\s]*)["']""", re.IGNORECASE
)


@dataclass
class ReconResult:
    graph: DataPathGraph
    findings: list[Finding]
    pages_fetched: int
    skipped_out_of_scope: int


class Recon:
    def __init__(self, egress: GatedEgress, max_pages: int = 25) -> None:
        self._egress = egress
        self._max_pages = max_pages

    def run(self, seeds: list[str]) -> ReconResult:
        graph = DataPathGraph()
        findings: list[Finding] = []
        seen: set[str] = set()
        queue: list[str] = list(dict.fromkeys(seeds))
        fetched = 0
        skipped = 0

        while queue and fetched < self._max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = self._egress.get(url)
            except EgressDenied:
                skipped += 1
                continue
            fetched += 1

            self._record_page(graph, url, resp)
            findings.extend(run_all(url, resp))

            # Only parse HTML-ish bodies for further links.
            ctype = (resp.header("Content-Type") or "").lower()
            if "html" in ctype or "<html" in resp.text(512).lower():
                for link in self._extract_links(url, resp):
                    if link not in seen and len(seen) + len(queue) < self._max_pages * 3:
                        queue.append(link)
            # Fetch discovered GET API endpoints exactly as referenced (the same
            # request the page itself makes — passive), so detectors run on them.
            for api_url in self._extract_apis(graph, url, resp):
                if api_url not in seen and len(seen) + len(queue) < self._max_pages * 3:
                    queue.append(api_url)

        return ReconResult(graph, findings, fetched, skipped)

    # --- helpers ----------------------------------------------------------

    def _record_page(self, graph: DataPathGraph, url: str, resp: HttpResponse) -> None:
        server = resp.header("Server") or ""
        graph.add_node(url, NodeKind.PAGE, label=url, status=str(resp.status),
                       server=server)

    def _extract_links(self, base: str, resp: HttpResponse) -> list[str]:
        out = []
        host = urlsplit(base).netloc
        for m in _HREF.findall(resp.text()):
            if m.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absu = urljoin(base, m)
            # stay on the same host; the egress gate still re-checks scope
            if urlsplit(absu).netloc == host and absu.startswith(("http://", "https://")):
                out.append(absu.split("#")[0])
        return out

    def _extract_apis(
        self, graph: DataPathGraph, base: str, resp: HttpResponse
    ) -> list[str]:
        found: list[str] = []
        for path in set(_API_REF.findall(resp.text())):
            api_url = urljoin(base, path)
            graph.add_node(api_url, NodeKind.API, label=path)
            graph.add_edge(base, api_url, EdgeKind.CALLS)
            found.append(api_url)
            # a query-string parameter hints at input that may flow to a store
            q = urlsplit(api_url).query
            for pair in q.split("&"):
                if "=" in pair:
                    pname = pair.split("=", 1)[0]
                    pid = f"{api_url}#{pname}"
                    graph.add_node(pid, NodeKind.PARAM, label=pname)
                    graph.add_edge(api_url, pid, EdgeKind.HAS_PARAM)
        return found
