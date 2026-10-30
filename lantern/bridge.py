"""API bridge: link frontend HTTP calls to the backend routes that serve them.

Matching is on HTTP method plus path segments, with "{}" standing for any dynamic segment
(`{id}`, `:id`, `[id]`, `${id}`).
  * exact            same segments, method matches               -> resolved
  * suffix           route matches the end of the call's path     -> inferred
                     (the call carries a global prefix the backend adds elsewhere, like /api/v1)
  * unknown prefix   `${API_URL}/items`: call matches the end of the route's path -> inferred
  * several routes tie for the best match                         -> possible, one edge each
Unmatched calls become external "HTTP" nodes, so the map shows a call whose server isn't in the repo.
"""

from __future__ import annotations

import re

from .graph import CALLS, INFERRED, POSSIBLE, RESOLVED, Graph


def _segs(path: str) -> list[str]:
    out = []
    for s in path.split("/"):
        if not s:
            continue
        if s.startswith(("{", ":", "[")) or "{" in s or s.startswith("<"):
            out.append("{}")
        else:
            out.append(s)
    return out


def _routes(g: Graph) -> list[dict]:
    out = []
    for n in g.nodes.values():
        if not n.entry or n.entry.get("kind") != "route":
            continue
        detail = n.entry.get("detail", "")
        verb, _, path = detail.partition(" ")
        if not path.startswith("/"):
            continue
        verbs = {v.upper() for v in verb.split("/")} if verb else {"ANY"}
        if verbs & {"ROUTE", "API_ROUTE", "WEBSOCKET"}:
            verbs = {"ANY"}
        out.append({"id": n.id, "verbs": verbs, "segs": _segs(path), "detail": detail})
    return out


def _seg_eq(a: str, b: str) -> bool:
    return a == b or a == "{}" or b == "{}"


def _literal_overlap(a: list[str], b: list[str]) -> int:
    return sum(1 for x, y in zip(a, b) if x == y and x != "{}")


def match(call: dict, routes: list[dict]) -> tuple[list[dict], str, str | None]:
    """Return (matched routes, confidence, how)."""
    cs = _segs(call["path"])
    best: list[tuple[int, int, dict, str]] = []   # (score, literal overlap, route, how)
    for r in routes:
        if "ANY" not in r["verbs"] and call["method"] not in r["verbs"]:
            continue
        rs = r["segs"]
        how, score = None, 0
        if not call["prefix_unknown"] and len(cs) == len(rs) and all(_seg_eq(a, b) for a, b in zip(cs, rs)):
            how, score = "exact", 1000 + len(rs)
        elif not call["prefix_unknown"] and len(rs) < len(cs) and rs and \
                all(_seg_eq(a, b) for a, b in zip(cs[-len(rs):], rs)):
            how, score = "suffix", 500 + len(rs)
        elif call["prefix_unknown"] and cs and len(cs) <= len(rs) and \
                all(_seg_eq(a, b) for a, b in zip(cs, rs[-len(cs):])):
            how, score = "unknown-prefix", 500 + len(cs)
        if how is None:
            continue
        a = cs[-len(rs):] if how == "suffix" else cs
        b = rs[-len(cs):] if how == "unknown-prefix" else rs
        if _literal_overlap(a, b) == 0 and len(rs) > 0:
            continue   # all-wildcard matches ("/{}" vs "/x") prove nothing
        # specificity: segments that match shape-for-shape ({} with {}, "me" with "me") beat
        # a variable matching a literal, so /users/{id} wins over /users/me for /users/${id}
        same = sum(1 for x, y in zip(a, b) if x == y)
        best.append((score, same, r, how))
    if not best:
        return [], "", None
    best.sort(key=lambda x: (-x[0], -x[1]))
    top = [b for b in best if (b[0], b[1]) == (best[0][0], best[0][1])]
    how = top[0][3]
    if len(top) > 1:
        return [b[2] for b in top], POSSIBLE, how
    return [top[0][2]], RESOLVED if how == "exact" else INFERRED, how


def link(g: Graph) -> dict:
    calls = g.meta.get("http_calls", [])
    routes = _routes(g)
    stats = {"http_calls": len(calls), "routes": len(routes), "matched": 0, "exact": 0, "suffix": 0,
             "unknown-prefix": 0, "ambiguous": 0, "external": 0, "unmatched": 0, "unmatched_examples": []}
    for c in calls:
        label = f"{c['method']} {c['raw'] if c['host'] else c['path']}"
        if c["host"]:
            name = f"HTTP {c['method']} {c['host']}"
            g.external(name)
            g.add_edge(c["src"], f"ext:{name}", kind=CALLS, confidence=RESOLVED, line=c["line"],
                       via="http-external", detail=label)
            stats["external"] += 1
            continue
        hits, conf, how = match(c, routes)
        if not hits:
            name = f"HTTP {c['method']} {c['path']}"
            g.external(name)
            g.add_edge(c["src"], f"ext:{name}", kind=CALLS, confidence=RESOLVED, line=c["line"],
                       via="http-unmatched", detail=label)
            stats["unmatched"] += 1
            if len(stats["unmatched_examples"]) < 25:
                stats["unmatched_examples"].append(f"{label}  ({c['file']}:{c['line']})")
            continue
        stats["matched"] += 1
        stats[how] += 1
        if len(hits) > 1:
            stats["ambiguous"] += 1
        for r in hits:
            g.add_edge(c["src"], r["id"], kind=CALLS, confidence=conf, line=c["line"],
                       via=f"http-{how}", detail=label)
    g.meta["bridge"] = stats
    return stats
