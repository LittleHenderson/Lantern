"""The case for one finding: what is claimed, what the evidence is, what has to be true for it to hurt, how sure Lantern
is, and what it does not know. Built only from facts already on the finding (tool, rule, map, input check, context.py,
scenario); it never changes a rank, never removes a finding, and never says a problem is confirmed in a running app.

`build(f, g)` runs in `security.scan` for every finding outside test code. `stamp(sec, git, earlier)` adds the
revision and the status words in `pipeline.analyze`, where the commit and the earlier run's ids are known.

Status words (one record per word, each with `done` true/false/None and a reason):
  reported               Lantern raised it in this run (always true).
  reproduced             the same finding id was raised by an earlier run of this folder (`earlier` ids), so the
                         result repeats; None on a first run.
  fixed                  false while the finding is listed; fixed findings leave the list (Evidence report).
  tested                 None: Lantern keeps no record of a test written for this finding.
  independently reviewed a person accepted it with a written reason (`lantern accept`): that is a review by the
                         builder, not an independent one, so `done` stays None and the reason says who reviewed it.
"""
from __future__ import annotations

from .graph import CONFIDENCE_RANK, Graph

CASE_VERSION = 1
CONF_WORD = {"observed": "seen running", "resolved": "certain", "inferred": "likely", "possible": "possible"}
OUTSIDE_KINDS = {"route", "page"}
STATUS_WORDS = ("reported", "reproduced", "fixed", "tested", "independently reviewed")


def _cond(need: str, known, why: str) -> dict:
    """One condition the harm depends on. `known` is True (Lantern saw it is so), False (saw it is not) or None."""
    return {"need": need, "met": known, "why": why}


def weakest_link(g: Graph, path: list[str] | None) -> str | None:
    """The least certain link on a path from an entry point: a path is only as sure as its weakest hop."""
    if not path or len(path) < 2:
        return None
    idx = getattr(g, "_pair_idx", None)
    if idx is None or idx[0] != len(g._edges):
        pairs: dict[tuple[str, str], str] = {}
        for e in g.edges:   # any kind: calls, HTTP links, clicks
            k = (e.src, e.dst)
            if k not in pairs or CONFIDENCE_RANK[e.confidence] < CONFIDENCE_RANK[pairs[k]]:
                pairs[k] = e.confidence
        idx = g._pair_idx = (len(g._edges), pairs)
    worst = None
    for a, b in zip(path, path[1:]):
        best = idx[1].get((a, b))
        if best is not None and (worst is None or CONFIDENCE_RANK[best] > CONFIDENCE_RANK[worst]):
            worst = best
    return worst


def _entry_text(g: Graph, r: dict | None) -> str:
    if not r:
        return ""
    n = g.nodes.get(r.get("entry") or "")
    detail = ((n.entry or {}).get("detail") if n is not None else None) or \
             (n.qualname if n is not None else r.get("entry"))
    return f"{r.get('kind')} {detail}"


def build(f: dict, g: Graph) -> dict:
    from .scenarios import TYPED, kind_of
    from .security import UNTRUSTED_ENTRY_KINDS, rank_reason
    kind = kind_of(f)
    node = g.nodes.get(f.get("node") or "")
    where = {"file": f.get("file"), "line": f.get("line"), "function": node.qualname if node is not None else None,
             "revision": None}
    evidence: list[dict] = []
    conditions: list[dict] = []
    unknown: list[str] = []

    # 1. the tool's own match
    evidence.append({"fact": f"{f.get('tool')} rule {f.get('rule')} matched"
                     + (f" at line {f['line']}" if f.get("line") else "") + f": {f.get('title')}",
                     "from": f.get("tool") or "scanner"})

    # 2. who can reach it (the map)
    r = f.get("reachable")
    link_r = weakest_link(g, (r or {}).get("path"))
    link_ui = weakest_link(g, f.get("ui_path"))
    links = [x for x in (link_r, link_ui) if x]
    link = max(links, key=lambda c: CONFIDENCE_RANK[c]) if links else None
    sure = lambda c: f"; the least certain link on that path is {CONF_WORD.get(c, c)}" if c else ""
    if r:
        hops = max(len((r.get("path") or [])) - 1, 0)
        evidence.append({"fact": (f"It is an entry point itself: {_entry_text(g, r)}" if not hops else
                                  f"Reached from {_entry_text(g, r)} in {hops} step{'s' if hops != 1 else ''}"
                                  + sure(link_r)), "from": "map"})
    elif f.get("reachable_from_tests_only"):
        evidence.append({"fact": "Only the test suite reaches this code", "from": "map"})
    elif node is not None and f.get("category") == "code":
        evidence.append({"fact": "No page, route or command in the map reaches this code", "from": "map"})
    ui = f.get("ui_path") or []
    ui_start = g.nodes.get(ui[0]) if ui else None
    ui_kind = ((ui_start.entry or {}).get("kind") if ui_start is not None else None)
    if ui and ui_kind == "page":
        evidence.append({"fact": f"A click path from the page {(ui_start.entry or {}).get('detail') or ui_start.qualname} "
                                 "reaches it" + sure(link_ui), "from": "map"})

    # 3. what the code around the line shows
    ctx = f.get("context") or {}
    if ctx.get("hash"):
        h = ctx["hash"]
        evidence.append({"fact": f"The hash looks like it is for {'protection' if h['purpose'] == 'security' else 'an identifier, seed or checksum' if h['purpose'] == 'non-security' else 'something Lantern could not tell'}: {h['why']}",
                         "from": "context (names)"})
    if ctx.get("sql"):
        s = ctx["sql"]
        evidence.append({"fact": ("Only fixed text is spliced into the SQL" if s["fixed_only"] else
                                  "Text that is not fixed is spliced into the SQL") + ": " +
                         "; ".join(f"{x['expr']} ({x['why']})" for x in s.get("spliced", [])[:4]),
                         "from": "context (code)"})
    if f.get("input"):
        evidence.append({"fact": f"Request data reaches this line ({f['input'].get('via')})", "from": "input check"})
    elif f.get("input") is False:
        evidence.append({"fact": "Nothing from the request reaches this line inside its function", "from": "input check"})
    if f.get("category") == "dependency":
        evidence.append({"fact": f"{f.get('package') or 'The library'} {f.get('version') or ''} is listed by the "
                                 f"advisory database ({f.get('advisory') or f.get('rule')})".replace("  ", " "),
                         "from": f.get("tool") or "audit"})

    # 4. what has to be true for this to hurt
    if f.get("category") == "secret":
        conditions.append(_cond("The value is a real key that still works", None,
                                "Lantern sees the text, not whether the key is live or revoked"))
        conditions.append(_cond("Someone else can read this file (a public repository, a shared copy)", None,
                                "Lantern does not know who can read the repository"))
        unknown.append("whether the key is real, still valid, and what it can do")
    elif f.get("rule") == "LW-PUBLIC-SECRET" and f.get("trust"):
        t = f["trust"]
        conditions.append(_cond("The value reaches the browser", True, f"set in {t['browser'].get('where')}"))
        conditions.append(_cond("The server accepts it as proof of who is calling",
                                True if t.get("server_trusts") == "server-checks-it" else
                                False if t.get("server_trusts") == "not-seen-on-server" else None,
                                {"server-checks-it": "server code checks it",
                                 "server-reads-it": "server code reads the setting; no comparison seen",
                                 "not-seen-on-server": "no server code in this repository reads it",
                                 "no-server-code": "the server is not in this repository"}.get(t.get("server_trusts"), "")))
        conditions.append(_cond("Nothing else on the server stops a stranger", None,
                                "depends on production settings Lantern cannot see"
                                + (f" ({', '.join(t['conditions'][:4])})" if t.get("conditions") else "")))
        unknown += list(t.get("unknown") or [])
    elif f.get("category") == "dependency":
        conditions.append(_cond("The app ships this version", True, "from the lock file or build file"))
        conditions.append(_cond("The app uses the affected part of the library", None,
                                "Lantern does not trace calls into libraries"))
        unknown.append("whether the affected code in the library is ever called")
    elif f.get("category") in ("code", "exposure"):
        if node is not None or r:
            outside = bool((r and r.get("kind") in OUTSIDE_KINDS) or ui_kind in OUTSIDE_KINDS)
            if r and r.get("kind") in OUTSIDE_KINDS:
                why_reach = f"reached from {_entry_text(g, r)}"
            elif ui_kind in OUTSIDE_KINDS:
                why_reach = f"a click path from the page {(ui_start.entry or {}).get('detail') or ui_start.qualname}"
            elif r:
                why_reach = (f"reached only from {_entry_text(g, r)}, which runs when someone runs the program; "
                             "whether outsiders can start it is not known")
            else:
                why_reach = "no entry point leads here today"
            conditions.append(_cond("Someone outside can reach this code",
                                    True if outside else (None if r and r.get("kind") in UNTRUSTED_ENTRY_KINDS else False),
                                    why_reach))
        if kind in TYPED:
            conditions.append(_cond("What they send reaches this line", f.get("input") and True,
                                    "input check: " + (f["input"].get("via") if f.get("input") else
                                                       "nothing from the request" if f.get("input") is False
                                                       else "not checked (input is followed from server routes, commands and scripts only)")))
            if ctx.get("sql") and ctx["sql"]["fixed_only"]:
                conditions[-1] = _cond("What they send becomes part of the SQL text", False,
                                       "only fixed text is spliced; values go to the driver separately")
        if ctx.get("hash"):
            h = ctx["hash"]
            conditions.append(_cond("The hash protects a password, token or signature",
                                    {"security": True, "non-security": False}.get(h["purpose"]), h["why"]))
        if f.get("category") == "exposure":
            unknown.append("whether the exposed value gives access to anything")
    if f.get("category") in ("code", "exposure"):
        unknown.append("Lantern read the code; it did not run the app or see production settings")
    if f.get("tool_confidence") == "LOW":
        unknown.append("this check is a pattern match (heuristic) and can misfire")
    if link in ("inferred", "possible"):
        unknown.append(f"one link on the path is only {CONF_WORD[link]}, so the path itself may not exist")

    # 5. how bad, how sure
    sev = {"rank": f.get("rank"), "tool_severity": f.get("tool_severity"), "why": rank_reason(f)}
    if f.get("rank_before_context"):
        sev["before_context"] = f["rank_before_context"]
        sev["context_note"] = f.get("rank_note")
    tc = str(f.get("tool_confidence") or "").upper()
    level = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(tc, "unknown")
    why = [f"{f.get('tool')} rates its own match {tc.lower() or 'unrated'}"]
    if level == "high" and link in ("inferred", "possible"):
        level = "medium"
        why.append(f"lowered: the path depends on a {CONF_WORD[link]} link")
    if any(c["met"] is False for c in conditions):
        why.append("at least one condition for harm is not met")
    open_q = sum(1 for c in conditions if c["met"] is None)
    if open_q:
        why.append(f"{open_q} condition{'s' if open_q != 1 else ''} Lantern cannot check")
    impact = (f.get("scenario") or {}).get("harm") or ""
    return {"version": CASE_VERSION, "where": where, "claim": _claim(f, kind), "evidence": evidence,
            "conditions": conditions, "impact": impact, "severity": sev,
            "confidence": {"level": level, "why": "; ".join(why), "about": "How sure Lantern is that the flagged pattern "
                           "is there and reached, not that it is exploitable"},
            "unknown": unknown, "status": _status(f, None)}


def _claim(f: dict, kind: str) -> str:
    """What the finding says, attributed to the tool and stated no more strongly than the evidence."""
    base = str(f.get("title") or "").rstrip(".")
    if f.get("category") == "secret":
        return f"{base}. The text looks like a key; Lantern does not test it."
    if f.get("rule") == "LW-PUBLIC-SECRET":
        return f"{base}. Visible in the browser; that alone is not proof anyone can get in."
    if f.get("category") == "dependency":
        return f"{base}. The version is affected; whether the app uses the affected part is not checked."
    return f"{f.get('tool')} says: {base}. A pattern in the code, not a confirmed attack."


def _status(f: dict, earlier: set | None) -> list[dict]:
    acc = f.get("accepted") or {}
    rows = [
        {"word": "reported", "done": True, "why": "raised in this run"},
        {"word": "reproduced", "done": (f.get("id") in earlier) if earlier is not None else None,
         "why": ("the same id was raised by an earlier run" if earlier and f.get("id") in earlier else
                 "not raised by the earlier run" if earlier is not None else "no earlier run to compare")},
        {"word": "fixed", "done": False, "why": "still flagged"},
        {"word": "tested", "done": None, "why": "Lantern keeps no record of a test for this finding"},
        {"word": "independently reviewed", "done": None,
         "why": (f"accepted by {acc.get('by') or 'the builder'} with a reason; that is not an independent review"
                 if f.get("status") == "accepted" else "no review recorded")},
    ]
    return rows


def attach(findings: list[dict], g: Graph) -> None:
    for f in findings:
        if not f.get("in_tests"):
            f["case"] = build(f, g)


def stamp(sec: dict | None, git: dict | None, earlier: set | None) -> None:
    """Revision and status words, once the commit and the earlier run's finding ids are known."""
    rev = (git or {}).get("commit")
    for f in (sec or {}).get("findings", []):
        c = f.get("case")
        if not c:
            continue
        c["where"]["revision"] = rev
        if rev and (git or {}).get("dirty"):
            c["where"]["revision_note"] = "the folder has changes that are not committed"
        c["status"] = _status(f, earlier)
