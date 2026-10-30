"""Unified Code Graph (UCG): the language-neutral model every other stage reads and enriches."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from . import SCHEMA_VERSION

# Node kinds
MODULE, CLASS, CALLABLE, EXTERNAL = "module", "class", "callable", "external"

# Edge kinds
CALLS, MAY_CALL, CONTAINS, IMPLEMENTS = "calls", "may_call", "contains", "implements"

# Confidence levels, strongest first. Order matters: merges keep the strongest.
OBSERVED, RESOLVED, INFERRED, POSSIBLE = "observed", "resolved", "inferred", "possible"
CONFIDENCE_RANK = {OBSERVED: 0, RESOLVED: 1, INFERRED: 2, POSSIBLE: 3}


@dataclass
class Node:
    id: str                      # e.g. "py:pkg.mod.Class.method"
    kind: str                    # module | class | callable | external
    name: str                    # short name, e.g. "method"
    qualname: str                # dotted path inside the repo, e.g. "pkg.mod.Class.method"
    file: str | None = None      # repo-relative path
    start_line: int | None = None
    end_line: int | None = None
    parent: str | None = None    # containing node id
    fingerprint: str | None = None
    signature: str | None = None
    docstring: str | None = None
    decorators: list[str] = field(default_factory=list)
    entry: dict | None = None    # {"kind": "main|route|cli|script|test", "detail": "..."}


@dataclass
class Edge:
    src: str
    dst: str
    kind: str = CALLS
    confidence: str = RESOLVED
    lines: list[int] = field(default_factory=list)  # call-site lines in src's file
    via: str | None = None       # how it was resolved, for debugging and trust
    detail: str | None = None    # e.g. "PUT /api/items/{id}" on an HTTP edge, "onClick" on a UI edge


class Graph:
    def __init__(self, repo_root: str):
        self.repo_root = repo_root
        self.nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}
        self.unresolved: dict[str, int] = {}   # callee text -> count, for honesty metrics
        self.meta: dict = {}

    # ---- nodes ----
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        return existing

    def external(self, name: str) -> Node:
        nid = f"ext:{name}"
        return self.add_node(Node(id=nid, kind=EXTERNAL, name=name.split(".")[-1], qualname=name))

    # ---- edges ----
    def add_edge(self, src: str, dst: str, kind: str = CALLS, confidence: str = RESOLVED,
                 line: int | None = None, via: str | None = None, detail: str | None = None) -> Edge:
        key = (src, dst, kind)
        e = self._edges.get(key)
        if e is None:
            e = Edge(src=src, dst=dst, kind=kind, confidence=confidence, via=via, detail=detail)
            self._edges[key] = e
        elif detail and not e.detail:
            e.detail = detail
        elif CONFIDENCE_RANK[confidence] < CONFIDENCE_RANK[e.confidence]:
            e.confidence, e.via = confidence, via or e.via
        if line is not None and line not in e.lines:
            e.lines.append(line)
        return e

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def call_edges(self) -> Iterable[Edge]:
        return (e for e in self._edges.values() if e.kind in (CALLS, MAY_CALL))

    def callees(self, nid: str) -> list[Edge]:
        return [e for e in self.call_edges() if e.src == nid]

    def callers(self, nid: str) -> list[Edge]:
        return [e for e in self.call_edges() if e.dst == nid]

    def entry_points(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.entry]

    # ---- serialization ----
    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA_VERSION,
            "repo_root": self.repo_root,
            "meta": self.meta,
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self._edges.values()],
            "unresolved": dict(sorted(self.unresolved.items(), key=lambda kv: -kv[1])[:200]),
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Graph":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        g = cls(d["repo_root"])
        g.meta = d.get("meta", {})
        for n in d["nodes"]:
            g.nodes[n["id"]] = Node(**n)
        for e in d["edges"]:
            ed = Edge(**e)
            g._edges[(ed.src, ed.dst, ed.kind)] = ed
        g.unresolved = d.get("unresolved", {})
        return g

    def stats(self) -> dict:
        kinds: dict[str, int] = {}
        for n in self.nodes.values():
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        conf: dict[str, int] = {}
        internal_calls = 0
        for e in self.call_edges():
            conf[e.confidence] = conf.get(e.confidence, 0) + 1
            if not e.dst.startswith("ext:"):
                internal_calls += 1
        return {
            "nodes": kinds,
            "call_edges": sum(conf.values()),
            "internal_call_edges": internal_calls,
            "confidence": conf,
            "entry_points": len(self.entry_points()),
            "unresolved_call_sites": sum(self.unresolved.values()),
        }
