"""Flows as findings (directive point 4): what `lantern/flow.py` followed, put into the list `security.scan` builds.

One problem is one finding. A flow that passes a line another tool already flagged for the same kind of problem
(Bandit's B608 where the query text is built, B602 on the command) is attached to that finding as `flow`; any other
flow becomes a finding of its own, rule `LT-<KIND>`, tool `lantern-flow`. Either way the finding carries the steps
from the request to the sensitive action, each with its file and line, so a reader can check them one by one.

The other direction is evidence too: where a tool flagged a query or a command and every call Lantern found hands
that function fixed text, the finding gets `context["fixed"]` with those calls (`fixed_evidence`), and
`security.rank` lowers it with the reason written on it. Nothing is ever removed."""

from __future__ import annotations

import time

from . import flow, scanresult
from . import flow_rules as R

VERSION = "1"
NEAR = 2            # lines: a tool names the line a statement starts on, the engine the line of the call
CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
LANGS = ("python", "typescript/javascript")      # as `engine.build_graph` names them in `g.meta["languages"]`


def _same(f: dict, cls: str) -> bool:
    rx = R.SAME_PROBLEM.get(cls)
    return bool(rx is not None and f.get("category") == "code" and f.get("line") and rx.search(str(f.get("rule"))))


def _signed_in(g, n, adj: dict, why: str, src: list[str]) -> bool:
    """Whether a route's sign of a login says that somebody is signed in when it runs. A sign found only in the names
    of what the route calls is also what a sign-in route shows (it makes a token, it checks a password), and there
    nobody is signed in yet: such a name counts only beside a function named for checking, or the framework's own view
    of the caller in the handler's lines."""
    from .websec import BODY_AUTH_SHAPED, auth_callees, code_only, segments
    if not why.startswith("calls `"):
        return True
    if any(not R.SIGNS_IN.search(segments(name)) for name in auth_callees(g, n, adj)):
        return True
    first = n.start_line or 1
    raw = "\n".join(src[first - 1:(n.end_line or first)])
    return bool(BODY_AUTH_SHAPED.search(code_only(raw, not (n.file or "").endswith((".py", ".rb")))))


def _shape(group: list[dict]) -> dict:
    """What a finding keeps of the flows that end on one line: the surest and shortest one whole, the other origins
    named."""
    group = sorted(group, key=lambda fl: (CONF_ORDER.get(fl["confidence"], 3), len(fl["steps"]), fl["source"]["file"],
                                          fl["source"]["line"]))
    main = group[0]
    others = [dict(fl["source"]) for fl in group[1:6]]
    return {"class": main["class"], "confidence": main["confidence"], "severity": R.SEVERITY[main["class"]],
            "source": dict(main["source"]),
            "sink": {"file": main["file"], "line": main["line"], "what": main["sink"]},
            "steps": [dict(s) for s in main["steps"]], "others": others, "count": len(group)}


def run(g, findings: list[dict], lines_for=None) -> tuple[list[dict], dict, flow.Result | None]:
    """(findings of its own, the tool's record, the engine's result). Flows that belong to a finding already in
    `findings` are written on that finding."""
    langs = g.meta.get("languages") or {}
    if not any(k in langs for k in LANGS):
        return [], scanresult.record("lantern-flow", "skipped", "no Python or JavaScript code to follow data through",
                                     applicable=False, version=VERSION), None
    t0 = time.perf_counter()
    try:
        res = flow.analyze(g)
    except Exception as ex:   # noqa: BLE001  the scan goes on without the flows, and its record says so
        return [], scanresult.record("lantern-flow", "failed", f"{type(ex).__name__}: {ex}"[:300], version=VERSION,
                                     duration_ms=int((time.perf_counter() - t0) * 1000)), None
    groups: dict[tuple, list[dict]] = {}
    for fl in res.flows:
        groups.setdefault((fl["class"], fl["file"], fl["line"]), []).append(fl)
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("file"):
            by_file.setdefault(f["file"], []).append(f)
    out: list[dict] = []
    attached = 0
    from .websec import _finding, login_check
    for (cls, file, line), group in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        shaped = _shape(group)
        # the action's own line first, then the lines the value passed on its way (where the query text was built)
        places = [(file, line, 0)] + [(s["file"], s["line"], 1) for s in shaped["steps"][1:-1]]
        best = None
        for pf, pl, order in places:
            for f in by_file.get(pf, ()):
                if _same(f, cls) and abs(f["line"] - pl) <= NEAR:
                    key = (order, abs(f["line"] - pl))
                    if best is None or key < best[0]:
                        best = (key, f)
        if best is not None:
            f = best[1]
            old = f.get("flow")
            if old is None or (CONF_ORDER.get(shaped["confidence"], 3), len(shaped["steps"])) < \
                    (CONF_ORDER.get(old["confidence"], 3), len(old["steps"])):
                if old is not None:
                    shaped["count"] += old["count"]
                f["flow"] = shaped
            else:
                old["count"] += shaped["count"]
            attached += 1
            continue
        conf = shaped["confidence"]
        text = ""
        if lines_for is not None:
            src = lines_for(file)
            text = src[line - 1].strip() if 0 < line <= len(src) else ""
        # a flow that rests on a guess (a call matched by name only) is said as a guess and not ranked above medium
        fixed = R.FIXED_RANK.get(cls) or ("medium" if conf == "LOW" else None)
        f = _finding(R.RULE[cls], R.TITLE[cls], R.SEVERITY[cls], file, line, conf=conf, cwe=R.CWE[cls], snippet=text,
                     fixed_rank=fixed)
        f["tool"] = "lantern-flow"
        f["flow"] = shaped
        out.append(f)
        by_file.setdefault(file, []).append(f)
    # who may reach what, route by route: only where the route shows that someone has to be signed in (a route with
    # no login at all is LW-AUTH-MISSING's business, and "another person's record" means nothing there)
    adj = None
    for a in res.authz:
        n = g.nodes.get(a["node"])
        if n is None:
            continue
        if adj is None:
            from .websec import call_adjacency
            adj = call_adjacency(g)
        src = lines_for(a["file"]) if lines_for is not None else []
        sign = login_check(g, n, adj, "\n".join(src) if src else None)
        if not sign or sign[0] != "strong" or not _signed_in(g, n, adj, sign[1], src):
            continue
        cls = "role" if a["role"] else "record"
        line = a["line"]
        f = _finding(R.RULE[cls], f"{a['detail']} {R.TITLE[cls]}", R.SEVERITY[cls], a["file"], line, conf="LOW",
                     cwe=R.CWE[cls], snippet=src[line - 1].strip() if 0 < line <= len(src) else "",
                     fixed_rank=R.FIXED_RANK[cls])
        f["tool"] = "lantern-flow"
        if cls == "record":
            f["flow"] = _shape(a["records"])
        out.append(f)
    st = res.stats
    notes = []
    if st.get("skipped_files"):
        notes.append(f"{st['skipped_files']} file(s) could not be read")
    if res.errors:
        notes.append(f"{len(res.errors)} function(s) could not be followed")
    if st.get("stopped_early"):
        notes.append("the time limit was reached before every function was read")
    fields = {"version": VERSION, "findings": len(out), "duration_ms": int((time.perf_counter() - t0) * 1000),
              "scope": {"files": st.get("files", 0), "functions": st.get("functions", 0), "flows": len(res.flows),
                        "on_other_findings": attached, "not_followed_further": st.get("stopped", 0)}}
    if notes:
        rec = scanresult.record("lantern-flow", "partial", "; ".join(notes), errors=res.errors[:20], **fields)
    else:
        rec = scanresult.record("lantern-flow", "ok", **fields)
    return out, rec, res


def whole(res: flow.Result | None) -> bool:
    """Whether the engine read everything it was given: only then can it say that no other call exists."""
    return res is not None and not res.errors and not res.stats.get("skipped_files") and \
        not res.stats.get("stopped_early") and not res.stats.get("unread")


def fixed_evidence(res: flow.Result | None, f: dict) -> dict | None:
    """For a finding on a query or a command with no flow: the calls that show only fixed text reaches it, or None."""
    if not whole(res) or f.get("flow") or f.get("category") != "code" or not f.get("file") or not f.get("line"):
        return None
    for cls in ("sql", "shell"):
        if _same(f, cls):
            got = res.fixed_only(f["file"], f["line"], cls)
            if got:
                return dict(got, **{"class": cls})
    return None


def raised_severity(f: dict) -> str:
    """The severity the rank starts from: the tool's own, or the flow's kind when request data was followed to the
    line and that kind is graver (a query built from request data is high whatever the pattern alone was rated)."""
    sev = f["tool_severity"]
    fl = f.get("flow")
    if fl and fl.get("confidence") != "LOW" and SEV_ORDER.get(fl.get("severity"), 0) > SEV_ORDER.get(sev, 0):
        return fl["severity"]
    return sev
