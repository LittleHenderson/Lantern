"""Unified Code Graph (UCG): the language-neutral model every other stage reads and enriches."""

from __future__ import annotations

import json
import re
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
    lane: str | None = None      # stack lane: browser | frontend | server | data (lanes.py); None = not in the picture


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
        self.unresolved_tests: dict[str, int] = {}   # the part of `unresolved` that sits in test files (Python)
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

    def _call_index(self) -> tuple[dict[str, list[Edge]], dict[str, list[Edge]]]:
        # Edges are only ever added, so the index is rebuilt when the count changes. Without it every
        # callees()/callers() walked all edges: 15k lookups x 50k edges took four minutes on a big repo.
        idx = getattr(self, "_idx", None)
        if idx is None or idx[0] != len(self._edges):
            out: dict[str, list[Edge]] = {}
            inc: dict[str, list[Edge]] = {}
            for e in self.call_edges():
                out.setdefault(e.src, []).append(e)
                inc.setdefault(e.dst, []).append(e)
            idx = self._idx = (len(self._edges), out, inc)
        return idx[1], idx[2]

    def callees(self, nid: str) -> list[Edge]:
        return list(self._call_index()[0].get(nid, ()))

    def callers(self, nid: str) -> list[Edge]:
        return list(self._call_index()[1].get(nid, ()))

    def nodes_in(self, file: str) -> list[Node]:
        """Nodes whose file is `file`, in insertion order (indexed; rebuilt when nodes are added)."""
        idx = getattr(self, "_fidx", None)
        if idx is None or idx[0] != len(self.nodes):
            by: dict[str, list[Node]] = {}
            for n in self.nodes.values():
                if n.file:
                    by.setdefault(n.file, []).append(n)
            idx = self._fidx = (len(self.nodes), by)
        return idx[1].get(file, [])

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
            # Only the 200 most common texts are kept, but the totals are the true counts.
            "unresolved": dict(sorted(self.unresolved.items(), key=lambda kv: -kv[1])[:200]),
            "unresolved_totals": {"call_sites": sum(self.unresolved.values()), "distinct": len(self.unresolved),
                                  "in_tests": sum(self.unresolved_tests.values()),
                                  "kinds": unresolved_kinds({k: v - self.unresolved_tests.get(k, 0)
                                                             for k, v in self.unresolved.items()})},
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
        g._unresolved_totals = d.get("unresolved_totals")
        return g

    def call_sites(self) -> dict:
        """Every call site Lantern read, sorted by what it knows about the target. The same denominator for all:
        a call site is one line in a caller that calls something (an edge with three call lines counts three)."""
        out = {"resolved_internal": 0, "inferred_internal": 0, "several_possible_targets": 0, "name_only_guess": 0,
               "known_external": 0}
        for e in self.call_edges():
            n = max(1, len(e.lines))
            if e.dst.startswith("ext:"):
                out["known_external"] += n
            elif e.via in ("unique-method-name", "method-name"):
                out["name_only_guess"] += n
            elif e.confidence == POSSIBLE:
                out["several_possible_targets"] += n
            elif e.confidence == INFERRED:
                out["inferred_internal"] += n
            else:
                out["resolved_internal"] += n
        tot = getattr(self, "_unresolved_totals", None)
        if tot is not None:   # a loaded graph keeps only the 200 most common texts: use the totals it saved, or none
            out["unresolved"] = tot.get("call_sites", sum(self.unresolved.values()))
            out["unresolved_in_tests"] = tot.get("in_tests")
            out["unresolved_kinds"] = tot.get("kinds")
        else:
            out["unresolved"] = sum(self.unresolved.values())
            out["unresolved_in_tests"] = sum(self.unresolved_tests.values())
            out["unresolved_kinds"] = unresolved_kinds({k: v - self.unresolved_tests.get(k, 0)
                                                        for k, v in self.unresolved.items()})
        out["total"] = sum(v for k, v in out.items() if k not in ("unresolved_in_tests", "unresolved_kinds"))
        return out

    def stats(self) -> dict:
        kinds: dict[str, int] = {}
        for n in self.nodes.values():
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        conf: dict[str, int] = {}
        internal_calls = by_name = 0
        for e in self.call_edges():
            conf[e.confidence] = conf.get(e.confidence, 0) + 1
            by_name += e.via in ("unique-method-name", "method-name")
            if not e.dst.startswith("ext:"):
                internal_calls += 1
        return {
            "nodes": kinds,
            "call_edges": sum(conf.values()),
            "internal_call_edges": internal_calls,
            "confidence": conf,
            "entry_points": len(self.entry_points()),
            "unresolved_call_sites": (getattr(self, "_unresolved_totals", None) or {}).get(
                "call_sites", sum(self.unresolved.values())),
            "guessed_by_method_name": by_name,
            "call_sites": self.call_sites(),
        }


UNRESOLVED_KINDS = ("member of self or this", "method on a value of unknown type", "on another call's result",
                    "dynamic (subscript, getattr, computed)", "name not found")


def unresolved_kind(text: str) -> str:
    """What an unresolved callee text looks like. The text alone says nothing about *why* (a builtin, a library,
    code that is not in the repo), so the kinds describe the shape, not the cause."""
    t = text.strip()
    if re.search(r"\bgetattr\b|\[|^\(|\*\*|\beval\b", t):
        return "dynamic (subscript, getattr, computed)"
    if re.match(r"^(?:self|this|cls)\.|^super\(\)", t):
        return "member of self or this"
    if re.search(r"\)\s*\.", t):
        return "on another call's result"
    if "." in t or "::" in t or "->" in t:
        return "method on a value of unknown type"
    return "name not found"


def unresolved_kinds(counts: dict[str, int]) -> dict[str, int]:
    out = {k: 0 for k in UNRESOLVED_KINDS}
    for text, n in counts.items():
        if n > 0:
            out[unresolved_kind(text)] += n
    return out
