"""The data-path graph (spec 3).

Nodes are observable surfaces (pages, API endpoints, parameters, inferred
backend services / data stores); edges are observed or inferred relationships
(``page --links--> page``, ``page --calls--> api``, ``api --queries--> store``).

This is a plain in-memory graph; a later phase can back it with Neo4j or a
Postgres graph model. It carries no network capability — recon fills it, the
chaining module (Phase 3) walks it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class NodeKind(enum.Enum):
    PAGE = "page"
    API = "api"
    PARAM = "param"
    AUTH_FLOW = "auth_flow"
    SERVICE = "service"
    DATASTORE = "datastore"


class EdgeKind(enum.Enum):
    LINKS = "links"          # page -> page
    CALLS = "calls"          # page -> api
    HAS_PARAM = "has_param"  # api -> param
    QUERIES = "queries"      # service -> datastore (inferred)
    AUTHENTICATES = "authenticates"


@dataclass(frozen=True)
class Node:
    node_id: str             # canonical id (usually the URL or url#param)
    kind: NodeKind
    label: str = ""
    attrs: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: EdgeKind


class DataPathGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: set[Edge] = set()

    def add_node(
        self, node_id: str, kind: NodeKind, label: str = "", **attrs: str
    ) -> Node:
        node = Node(
            node_id=node_id,
            kind=kind,
            label=label or node_id,
            attrs=tuple(sorted(attrs.items())),
        )
        self._nodes[node_id] = node
        return node

    def add_edge(self, src: str, dst: str, kind: EdgeKind) -> None:
        if src in self._nodes and dst in self._nodes:
            self._edges.add(Edge(src, dst, kind))

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def nodes(self) -> tuple[Node, ...]:
        return tuple(self._nodes.values())

    def edges(self) -> tuple[Edge, ...]:
        return tuple(self._edges)

    def neighbors(self, node_id: str) -> tuple[str, ...]:
        return tuple(e.dst for e in self._edges if e.src == node_id)

    def summary(self) -> dict:
        by_kind: dict[str, int] = {}
        for n in self._nodes.values():
            by_kind[n.kind.value] = by_kind.get(n.kind.value, 0) + 1
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes_by_kind": by_kind,
        }

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.node_id, "kind": n.kind.value, "label": n.label,
                 "attrs": dict(n.attrs)}
                for n in self._nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "kind": e.kind.value}
                for e in self._edges
            ],
        }
