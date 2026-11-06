"""A results bundle cut down to the layers (lanes) one person may see: per-layer permissions in a team workspace
(directive: user first, step 4).

The four layers are the map's lanes: browser, frontend, server, data. Someone who may see only some of them gets a
copy of the report data built here, on the server, before anything reaches their browser. Their browser never
holds the rest, so nothing about a hidden layer can be read out of the page.

- Functions, files and classes in a hidden layer are left out.
- A call that crosses into a hidden layer ends at one *sealed* node for that layer ("Something in the Server"),
  so the person sees that their code depends on something there, and nothing about what it is.
- Findings, explanations and source snippets are kept only for what they may see. A finding whose path to a
  visitor runs through a hidden layer keeps its sealed path, without the story that names the hidden steps.
- Anything else that names a hidden file or function (readiness evidence, hotspots, the AI and phone cards, the
  frontend-to-backend bridge) is dropped or replaced with a plain sentence.

The engine's facts are never changed, only left out. The cut is deterministic: the same bundle and layers give
the same copy.
"""

from __future__ import annotations

import copy

LANES = ("browser", "frontend", "server", "data")
WORD = {"browser": "Browser", "frontend": "Frontend", "server": "Server", "data": "Data"}
LINK_KINDS = ("calls", "may_call", "implements")
HIDDEN_TEXT = "This is in a layer you can't see."


def parse(lanes) -> tuple[str, ...] | None:
    """A clean, ordered tuple of layers, or None for "all of them". ValueError on anything else."""
    if lanes is None:
        return None
    if not isinstance(lanes, (list, tuple)) or not lanes or not all(isinstance(x, str) for x in lanes):
        raise ValueError("Choose at least one layer: browser, frontend, server or data.")
    bad = set(lanes) - set(LANES)
    if bad:
        raise ValueError("Layers are browser, frontend, server and data.")
    got = tuple(x for x in LANES if x in set(lanes))
    return None if len(got) == len(LANES) else got


def code(lanes: tuple[str, ...] | None) -> str:
    """A short, stable spelling for a set of layers: "all", or the first letters in lane order ("bf")."""
    return "all" if lanes is None else "".join(x[0] for x in lanes)


def decode(c: str) -> tuple[str, ...] | None:
    if c == "all":
        return None
    by = {x[0]: x for x in LANES}
    if not c or any(ch not in by for ch in c) or len(set(c)) != len(c):
        raise ValueError("not a layer code")
    return parse([by[ch] for ch in c])


def sealed_id(lane: str) -> str:
    return f"ext:sealed:{lane}"


def _sealed_node(lane: str) -> dict:
    return {"id": sealed_id(lane), "kind": "external", "name": f"Something in the {WORD[lane]}",
            "qualname": f"Something in the {WORD[lane]}", "file": None, "start_line": None, "end_line": None,
            "parent": None, "fingerprint": None, "signature": None, "docstring": None, "decorators": [],
            "entry": None, "lane": lane, "sealed": True}


def scope_bundle(data: dict, lanes) -> dict:
    """The report data for someone who may see only `lanes` (None: everything, returned unchanged)."""
    lanes = parse(list(lanes)) if lanes is not None else None
    if lanes is None:
        return data
    keep_lanes = set(lanes)
    d = copy.deepcopy(data)
    g = d.get("graph") or {}
    nodes = [n for n in g.get("nodes") or [] if isinstance(n, dict) and isinstance(n.get("id"), str)]
    lane_of = {n["id"]: n.get("lane") for n in nodes}

    def visible(n: dict) -> bool:
        ln = n.get("lane")
        return ln in keep_lanes or (ln is None and n.get("kind") == "external")   # a library outside every layer

    kept = {n["id"] for n in nodes if visible(n)}
    hidden = {n["id"] for n in nodes} - kept
    kept_files = {n.get("file") for n in nodes if n["id"] in kept and n.get("file")}
    hidden_files = {n.get("file") for n in nodes if n["id"] in hidden and n.get("file")} - kept_files
    hidden_names = {n.get("qualname") for n in nodes if n["id"] in hidden and n.get("kind") != "module"
                    and isinstance(n.get("qualname"), str) and len(n.get("qualname")) > 3}

    def seal(nid):
        if nid in kept or not isinstance(nid, str):
            return nid
        ln = lane_of.get(nid)
        return sealed_id(ln) if ln in LANES else None

    used_seals: set[str] = set()
    edges, seen = [], set()
    for e in g.get("edges") or []:
        if not isinstance(e, dict):
            continue
        s, t = e.get("src"), e.get("dst")
        if s in kept and t in kept:
            edges.append(e)
            continue
        if e.get("kind") not in LINK_KINDS or (s not in kept and t not in kept):
            continue                                           # inside a hidden layer, or a file holding a function
        s2, t2 = seal(s), seal(t)
        if not s2 or not t2 or (s2, t2, e.get("kind")) in seen:
            continue
        seen.add((s2, t2, e.get("kind")))
        used_seals.update(x for x in (s2, t2) if x.startswith("ext:sealed:"))
        edges.append({"src": s2, "dst": t2, "kind": e.get("kind"), "confidence": e.get("confidence"),
                      "lines": e.get("lines") if s2 in kept else [], "via": None, "detail": None})
    g["nodes"] = [n for n in nodes if n["id"] in kept] + [_sealed_node(x.rsplit(":", 1)[1]) for x in sorted(used_seals)]
    g["edges"] = edges
    g["unresolved"], g["unresolved_totals"] = {}, {"call_sites": 0, "distinct": 0}
    meta = g.get("meta") or {}
    g["meta"] = {"language": meta.get("language"), "languages": meta.get("languages"),
                 "files": len(kept_files), "lines": None,
                 "lanes": {k: v for k, v in (meta.get("lanes") or {}).items() if k in keep_lanes}}

    def mentions_hidden(text: str) -> bool:
        return any(f in text for f in hidden_files) or any(q in text for q in hidden_names)

    def scrub(v):
        """Drop list items and replace strings that name a hidden file or function; drop dicts about a hidden node."""
        if isinstance(v, str):
            return HIDDEN_TEXT if mentions_hidden(v) else v
        if isinstance(v, list):
            out = []
            for x in v:
                if isinstance(x, str) and mentions_hidden(x):
                    continue
                if isinstance(x, dict) and (x.get("node") in hidden or x.get("id") in hidden or x.get("src") in hidden
                                            or x.get("file") in hidden_files):
                    continue
                out.append(scrub(x))
            return out
        if isinstance(v, dict):
            return {k: scrub(x) for k, x in v.items() if k not in hidden}   # e.g. findings or AI calls by node id
        return v

    sec = d.get("security") or {}
    findings = []
    for f in sec.get("findings") or []:
        if not isinstance(f, dict) or f.get("node") not in kept:
            continue
        f = dict(f)
        crossed = False
        for path_key in ("ui_path",):
            if isinstance(f.get(path_key), list):
                p2 = [seal(x) for x in f[path_key]]
                crossed |= p2 != f[path_key]
                f[path_key] = [x for i, x in enumerate(p2) if x and (i == 0 or x != p2[i - 1])]
        r = f.get("reachable")
        if isinstance(r, dict):
            r = dict(r)
            if isinstance(r.get("path"), list):
                p2 = [seal(x) for x in r["path"]]
                crossed |= p2 != r["path"]
                r["path"] = [x for i, x in enumerate(p2) if x and (i == 0 or x != p2[i - 1])]
            if r.get("entry") not in kept:
                r["entry"] = seal(r.get("entry"))
                crossed = True
            f["reachable"] = r
        if isinstance(f.get("lanes"), list):
            f["lanes"] = [x for x in f["lanes"] if x in keep_lanes] or f["lanes"][:0]
        if crossed:
            f.pop("scenario", None)
            f.pop("input", None)
        findings.append(scrub(f))
    counts = {k: 0 for k in ("critical", "high", "medium", "low")}     # as security.scan counts them
    for f in findings:
        if f.get("status") == "open" and not f.get("in_tests") and f.get("rank") in counts:
            counts[f["rank"]] += 1
    d["security"] = {"findings": findings, "tools": sec.get("tools"), "id_version": sec.get("id_version"),
                     "counts": {**counts, "in_tests": sum(1 for f in findings if f.get("in_tests")),
                                "accepted": sum(1 for f in findings if f.get("status") == "accepted")},
                     "ai": scrub(sec.get("ai")) if "frontend" in keep_lanes or "server" in keep_lanes else None,
                     "mobile": scrub(sec.get("mobile")) if "frontend" in keep_lanes else None}
    d["explanations"] = {k: v for k, v in (d.get("explanations") or {}).items() if k in kept}
    d["sources"] = {k: v for k, v in (d.get("sources") or {}).items() if k in kept}
    st = d.get("stats") or {}
    kinds: dict[str, int] = {}
    for n in g["nodes"]:
        kinds[n.get("kind")] = kinds.get(n.get("kind"), 0) + 1
    calls = [e for e in edges if e.get("kind") in ("calls", "may_call")]
    conf: dict[str, int] = {}
    for e in calls:
        conf[e.get("confidence")] = conf.get(e.get("confidence"), 0) + 1
    d["stats"] = {"nodes": kinds, "call_edges": len(calls), "internal_call_edges": sum(1 for e in calls if not e["dst"].startswith("ext:")),
                  "confidence": conf, "entry_points": sum(1 for n in g["nodes"] if n.get("entry")),
                  "unresolved_call_sites": 0, "guessed_by_method_name": 0} if st else st
    if isinstance(d.get("readiness"), dict):
        # the starter deploy files Lantern writes describe how to run the whole app (a Dockerfile names its server
        # module), so someone who sees only part of it doesn't get them
        d["readiness"] = scrub({k: v for k, v in d["readiness"].items() if k != "starter"})
    d["scope"] = {"lanes": list(lanes), "hidden": [x for x in LANES if x not in keep_lanes]}
    return d
