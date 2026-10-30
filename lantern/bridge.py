"""Bridge: link frontend HTTP calls to the backend routes that answer them.

Each HTTP call found by ts_frontend.py is matched by method and path against every route entry point
in the graph (Python or JS). The result is an ordinary call edge from the calling function to the
route handler, so paths and reachability run straight through: button -> client -> route -> database.

Match levels:
  * exact     same method, same path segments ({} params line up)       -> "resolved"
  * prefix    route path is a suffix of the call path, e.g. the backend
              mounts its routers under /api/v1 through a setting Lantern
              can't read                                                 -> "inferred"
Ties between equally good routes become "possible" edges to each, never a silent guess.
Calls that match nothing get an `ext:http ...` node so the map still shows them leaving the app.
"""

from __future__ import annotations

import re

from .graph import CALLS, EXTERNAL, INFERRED, MAY_CALL, POSSIBLE, RESOLVED, Graph, Node
from .ts_frontend import normalize_url


def _segments(path: str) -> list[str]:
    return [s for s in normalize_url(path).split("/") if s]


def _route_parts(detail: str) -> tuple[set[str], list[str]] | None:
    m = re.match(r"^([A-Za-z/]+)\s+(\S*)$", detail.strip())
    if not m:
        return None
    methods = {x.upper() for x in m.group(1).split("/") if x}
    if methods & {"ROUTE", "API_ROUTE", "ANY"}:
        methods = {"ANY"}
    return methods, _segments(m.group(2) or "/")


def _seg_match(call: list[str], route: list[str]) -> int | None:
    """Score for equal-length segment lists: literal matches count 2, param matches 1."""
    score = 0
    for c, r in zip(call, route):
        if c == r:
            score += 2
        elif c == "{}" or r == "{}":
            score += 1
        else:
            return None
    return score


def match(method: str, url: str, routes: list[tuple[str, set[str], list[str]]]) -> list[tuple[str, str, int]]:
    """-> [(route node id, level, score)] best first."""
    call = _segments(url)
    hits = []
    for rid, methods, segs in routes:
        if not ({"ANY", method} & methods) and method != "ANY":
            continue
        if len(segs) == len(call):
            s = _seg_match(call, segs)
            if s is not None:
                hits.append((rid, "exact", 1000 + s))
        elif 0 < len(segs) < len(call):
            tail = call[len(call) - len(segs):]
            s = _seg_match(tail, segs)
            # require at least one literal segment so `/{}` doesn't swallow everything
            if s is not None and any(x != "{}" for x in segs):
                hits.append((rid, "prefix", s))
    hits.sort(key=lambda h: -h[2])
    return hits


def link(g: Graph, http_calls: list[dict]) -> dict:
    routes = []
    for n in g.entry_points():
        if n.entry["kind"] == "route":
            p = _route_parts(n.entry.get("detail", ""))
            if p:
                routes.append((n.id, p[0], p[1]))
    linked, external, ambiguous, rows = 0, 0, 0, []
    for h in http_calls:
        if h["src"] not in g.nodes:
            continue
        hits = match(h["method"], h["url"], routes)
        label = f"http {h['method']} {h['url']}"
        host = re.match(r"^[a-z]+://([^/]+)", h.get("raw", ""))
        row = {**h, "route": None, "level": None}
        if hits:
            best = [x for x in hits if x[2] == hits[0][2]]
            if len(best) == 1:
                rid, level, _ = best[0]
                conf = RESOLVED if level == "exact" else INFERRED
                g.add_edge(h["src"], rid, kind=CALLS, confidence=conf, line=h["line"],
                           via=f"{label} ({level} match)")
                row.update(route=rid, level=level)
                linked += 1
            else:
                for rid, level, _ in best:
                    g.add_edge(h["src"], rid, kind=MAY_CALL, confidence=POSSIBLE, line=h["line"],
                               via=f"{label} (ambiguous: {len(best)} routes)")
                row.update(route=[b[0] for b in best], level="ambiguous")
                ambiguous += 1
        else:
            if host:   # a third-party API: keep the host so the map says where the data goes
                label = f"http {h['method']} {host.group(1)}{h['url']}"
            nid = f"ext:{label}"
            if nid not in g.nodes:
                g.add_node(Node(id=nid, kind=EXTERNAL, name=label, qualname=label))
            g.add_edge(h["src"], nid, kind=CALLS, confidence=RESOLVED, line=h["line"], via=f"{h['client']} call")
            external += 1
        rows.append(row)
    return {"http_calls": len(rows), "linked": linked, "ambiguous": ambiguous, "unmatched": external,
            "routes": len(routes), "calls": rows}
