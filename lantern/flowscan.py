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
RAW_PLACE = "LW-XSS-RAW"                         # websec.template_rules: a template prints a value without escaping


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
    # "no login check was found" is said by the names around a route (`websec.missing_auth`). Where the route's
    # code itself turns away whoever is not signed in (a check with a plain name, one written in place, a hook that
    # runs before every request), the sentence is wrong and the finding is not kept; how many, in the record
    shown = {(n.file, n.start_line) for n in (g.nodes.get(x) for x in res.logins) if n is not None}
    named_open = [f for f in findings if f.get("rule") == "LW-AUTH-MISSING" and (f.get("file"), f.get("line")) in shown]
    if named_open:
        findings[:] = [f for f in findings if not any(f is x for x in named_open)]
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
    _raw_places(findings, res)
    # who may reach what, route by route: only where the route shows that someone has to be signed in (a route with
    # no login at all is LW-AUTH-MISSING's business, and "another person's record" means nothing there)
    adj = None
    lets_on = 0     # findings on routes where a token library is called and a request with no valid token goes on
    claims: dict[tuple, dict] = {}
    owned: dict[tuple, dict] = {}       # (file, line) a record is reached at -> its records and the routes that reach it
    for a in res.authz:
        n = g.nodes.get(a["node"])
        if n is None:
            continue
        for c in a.get("client") or ():     # asked of every route, signed in or not: the visitor writes the answer
            claims.setdefault((c["file"], c["line"]), dict(c, routes=[]))["routes"].append(a["detail"])
        if not a["records"] and not a["role"]:
            continue
        if adj is None:
            from .websec import call_adjacency
            adj = call_adjacency(g)
        src = lines_for(a["file"]) if lines_for is not None else []
        # a route on whose way a token library is called and nothing turns anybody away: the library's name, and
        # the names of the functions that let such a request on, are no sign of a login there
        let_on = a["node"] in res.caught
        sign = login_check(g, n, adj, "\n".join(src) if src else None, doubt=res.soft if let_on else None)
        # `login`: the code itself turns away whoever is not signed in, whatever the function that asks is called
        if not a.get("login"):
            if not sign or sign[0] != "strong":
                f = _open_route(a, n, sign, findings, src, let_on)
                if f is not None:
                    out.append(f)
                    lets_on += let_on
                continue
            if not _signed_in(g, n, adj, sign[1], src):
                continue
        if not a["role"]:       # another person's record: one finding for each line a record is reached on
            for r in a["records"]:
                place = owned.setdefault((r["file"], r["line"]), {"records": [], "routes": []})
                place["records"].append(r)
                if a["detail"] not in place["routes"]:
                    place["routes"].append(a["detail"])
            continue
        line = a["line"]        # an admin route that asks for no admin: about the route, and on it
        f = _finding(R.RULE["role"], f"{a['detail']} {R.TITLE['role']}", R.SEVERITY["role"], a["file"], line,
                     conf="LOW", cwe=R.CWE["role"], snippet=src[line - 1].strip() if 0 < line <= len(src) else "",
                     fixed_rank=R.FIXED_RANK["role"])
        f["tool"] = "lantern-flow"
        out.append(f)
    # the other routes of that kind (one that adds a record, one that changes something picked by no id): asked by
    # the rule that asks the routes the frontend calls, which took the library's name for a login check
    if res.caught:
        from .websec import missing_auth
        have = {(f.get("file"), f.get("line")) for f in [*findings, *out] if f.get("rule") == "LW-AUTH-MISSING"}
        for f in missing_auth(g, only=res.caught, doubt=res.soft):
            if (f["file"], f["line"]) not in have:
                f["tool"] = "lantern-flow"
                out.append(f)
                lets_on += 1
    for (file, line), place in sorted(owned.items()):
        out.append(_owner(file, line, place, lines_for(file) if lines_for is not None else []))
    for _place, c in sorted(claims.items()):
        out.append(_client_role(c, lines_for(c["file"]) if lines_for is not None else []))
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
                        "on_other_findings": attached, "not_followed_further": st.get("stopped", 0),
                        "login_read_from_code": len(named_open),
                        "token_check_lets_on": lets_on}}
    if notes:
        rec = scanresult.record("lantern-flow", "partial", "; ".join(notes), errors=res.errors[:20], **fields)
    else:
        rec = scanresult.record("lantern-flow", "ok", **fields)
    return out, rec, res


def _client_role(c: dict, src: list[str]) -> dict:
    """Routes that decide what the caller may do on a value the caller writes: a cookie, a header, a word in the
    address or the body (LT-AUTHZ-CLIENT-ROLE, a heuristic ranked medium). One finding for the place the value is
    read, with the routes that decide on it."""
    from .websec import _finding
    routes = sorted(set(c["routes"]))
    place = R.CLAIM_PLACE.get(c["part"], "the address")
    name, line = c["name"], c["line"]
    more_routes = len(routes) - 1
    who = routes[0] + (f" and {more_routes} more route{'s' if more_routes > 1 else ''} decide" if more_routes
                       else " decides")
    listed = ", ".join(routes[:8]) + (f" and {len(routes) - 8} more" if len(routes) > 8 else "")
    more = (f"Heuristic, read from names. `{name}` arrives in {place}, and whoever sends the request writes it: a "
            "browser's own tools or one line of curl set it to any value. "
            f"{'These routes decide' if more_routes else 'This route decides'} on it ({listed}), and Lantern found "
            "nothing on the way that asks what the signed-in person may do: a role kept in the session, in a token "
            "the server checks, or in the database. If the value is signed and checked before this line (a signed "
            "cookie, a token), or a proxy in front of the app writes it and removes the visitor's own, ignore this.")
    f = _finding(R.RULE["client"], f"{who} {R.TITLE['client'].format(place=place, name=name)}", R.SEVERITY["client"],
                 c["file"], line, conf="LOW", cwe=R.CWE["client"], fixed_rank=R.FIXED_RANK["client"], more=more,
                 snippet=src[line - 1].strip() if 0 < line <= len(src) else "")
    f["tool"] = "lantern-flow"
    f["claim"] = {"name": name, "sent_as": place, "what": c["what"], "routes": routes}
    return f


def _owner(file: str, line: int, place: dict, src: list[str]) -> dict:
    """Another person's record (LT-AUTHZ-OWNER, a heuristic ranked medium): one finding for the line a record is
    reached on by an id from the request, with the routes that reach it and compare no owner. That line is where the
    owner has to be asked for, and one service function five routes use is one place to fix. `late`: every route
    does ask whose the record is, but only after this line, where a record is changed or something is done that
    cannot be taken back (`flow.Engine.acted`)."""
    from .websec import _finding
    recs, routes = place["records"], sorted(place["routes"])
    many = len(routes) > 1
    who = routes[0] + (f" and {len(routes) - 1} more route{'s' if len(routes) > 2 else ''}" if many else "")
    late = next((r.get("act") or "change" for r in recs), None) if all(r.get("late") for r in recs) else None
    title = f"{who} {R.LATE_DOES[late][many]} {R.LATE_TAIL[many]}" if late else f"{who} {R.OWNER_TITLE[many]}"
    listed = ", ".join(routes[:8]) + (f" and {len(routes) - 8} more" if len(routes) > 8 else "")
    more = "Heuristic. " + (
        "The route asks whose the record is (or for a role) only after this line: whoever is turned away has "
        "already had it done. " if late else
        "This is the line the record is reached on: the place to ask for the owner as well as the id, or to compare "
        "the owner of what comes back. ")
    if many:
        more += f"Reached this way by {listed}. "
    more += "A route that makes that comparison before this line is not listed."
    f = _finding(R.RULE["record"], title, R.SEVERITY["record"], file, line, conf="LOW", cwe=R.CWE["record"],
                 snippet=src[line - 1].strip() if 0 < line <= len(src) else "", fixed_rank=R.FIXED_RANK["record"],
                 more=more)
    f["tool"] = "lantern-flow"
    f["flow"] = _shape(recs)
    f["routes"] = routes
    if late:
        f["late"] = late
    return f


def _open_route(a: dict, n, sign, findings: list[dict], src: list[str], let_on: bool = False) -> dict | None:
    """A route that shows no login and changes or removes a record picked by an id from the request: whoever sends
    the request chooses the record. It is the finding `websec.missing_auth` makes for a route the project's frontend
    calls (LW-AUTH-MISSING, a heuristic ranked medium), made here for a route nothing in the project calls, with the
    way from the request to the record. None when that finding is already on the route, when the path is one made
    to be open (sign-in, a webhook: `is_public_route`), and when the route only reads or adds."""
    from .websec import TOKEN_LETS_ON, _finding, is_public_route, passed_over_words
    changed = [r for r in a["records"] if r["change"] and not r.get("act")]     # a record, not a command or a file
    line = n.start_line or a["line"]
    if not changed or is_public_route(a["detail"]) or any(
            f.get("rule") == "LW-AUTH-MISSING" and f.get("file") == n.file and f.get("line") == line
            for f in findings):
        return None
    more = ("Heuristic: Lantern looked three calls deep for anything named like an auth check (current_user, auth, "
            "login_required, token, permission...), read the handler's own lines for the same words, and looked at "
            "what the app puts in front of the route. ")
    if sign:
        more += f"The only sign in the handler is that {sign[1]}: that finds a record, not the caller. "
    more += passed_over_words(n, "\n".join(src) if src else None)
    more += ("Whoever sends the request picks the record by its id. If this route is meant to be open to everyone, "
             "ignore it.")
    found = "no login check was found"
    if let_on:      # a token library is called on the way, and a request whose token does not hold goes on
        found = "Lantern found nothing that turns away a request whose login token does not hold"
        more = TOKEN_LETS_ON + more
    f = _finding("LW-AUTH-MISSING", f"{a['detail']} changes or removes a record picked by an id from the request, "
                 f"and {found}", "MEDIUM", n.file, line, conf="LOW", cwe=306, fixed_rank="medium",
                 more=more, snippet=src[line - 1].strip() if 0 < line <= len(src) else "")
    f["tool"] = "lantern-flow"
    f["flow"] = _shape(changed)
    return f


def _raw_places(findings: list[dict], res: flow.Result) -> None:
    """A place in a page template that prints a value without escaping it (LW-XSS-RAW, a pattern match ranked
    medium) is ranked by what Lantern knows of the value: request data followed into it ranks as any flow into a
    page; fixed text, or a value made safe for a page, in every place that shows the page ranks low, with those
    places named; anything else stays medium, and the reason says what is not known."""
    for f in findings:
        if f.get("rule") != RAW_PLACE:
            continue
        fl = f.get("flow")
        if fl:
            if fl["confidence"] != "LOW":       # a flow that rests on a guess is not ranked above medium either
                f.pop("fixed_rank", None)
            continue
        recs = res.engine.handed_pages.get((f["file"], f["line"])) or {}
        unknown = sorted(k for k, state in recs.items() if state == "open")
        if unknown:
            file, line, name = unknown[0]
            f["fixed_why"] = (f"The page prints `{name}` as it is, and `{file}:{line}` shows the page with a value "
                              "Lantern did not follow to where it comes from (a database, a file, another service, "
                              "or nothing handed over under that name). If a visitor can write that value, the page "
                              "prints their HTML. A pattern match: ranked medium whatever reaches it.")
        elif recs and whole(res):
            places = sorted({f"`{file}:{line}`" for file, line, _name in recs})
            more = f" and {len(places) - 3} more" if len(places) > 3 else ""
            f["fixed_rank"] = "low"
            f["fixed_why"] = (f"Every place Lantern found that shows this page ({', '.join(places[:3])}{more}) "
                              "hands it text written in the code, a number or a value made safe for a page under "
                              "the name printed here. A new place that hands it something else would change this.")
        else:
            f["fixed_why"] = ("The page prints a value as it is, and Lantern found no place in the code that shows "
                              "this page, so it cannot say what the value holds. A pattern match: ranked medium "
                              "whatever reaches it.")


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
