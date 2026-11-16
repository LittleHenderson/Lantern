"""What a change does to an app: two checks of one project, compared (roadmap of 2026-11-14, stage 2; `lantern diff`).

A pull request is read line by line by people, and what Lantern knows of a project is not in the lines: which
doors it has (pages, routes, commands), whether a door asks who is calling, which request of a page a route of the
server answers, which finding a door reaches. `compare(base, head)` takes the results of two checks (the folders
`lantern analyze` writes) and says what is different between them, as a **change receipt**:

* `doors`: entry points that are new, gone, whose address changed, or whose login check changed
  (`security.json` `route_logins`, written by `websec.route_logins`);
* `links`: a request a page still makes that a route answered before and no route answers now, with what became
  of that route (gone, another verb, another path), and a new request no route answers;
* `findings`: new, fixed, changed and still open, reached from a door now and not before, ranked higher or lower,
  accepted in this change;
* `paid`: a door that now reaches a call that costs money (a model, an email, a payment) and did not before;
* `touches`: the functions whose code changed, the doors that reach them and what they reach outside the app
  (database tables, the shell, paid calls, other services);
* `release`: the release decision before and after, with what moved it.

Facts only. Every line of a receipt is a difference between two result files that deterministic code wrote; no
model writes or ranks any of it, and a receipt never creates, closes or re-ranks a finding. Nothing here reads the
project: `compare` is a function of two results folders, so the command line, the GitHub Action and the website
make the same receipt from the same two checks. What is the same on both sides is not said, and neither is a
difference that only formatting or a comment makes (a function is changed when its fingerprint is, which is taken
from its code without comments and spacing).

Identity across the two sides: a door is its kind and its words (`POST /api/notes`), wherever its handler stands;
a finding is its id (made from the flagged line's text, not its number); a function is its id on the map; a
request of a page is the function that makes it and its words (`DELETE /api/notes/{}`).

What a receipt does not say is said in it (`limits`): results an older Lantern wrote hold no login record, a
side whose scanners did not finish, tests that were not run on either side.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
from pathlib import Path

from . import results
from .graph import outside, route_words

SCHEMA = 1
RANKS = ("critical", "high", "medium", "low")
SERIOUS = ("critical", "high")
MOST = 200              # rows of one kind a receipt keeps; the rest are counted (`more`)
MOST_SHOWN = 12         # rows of one kind the text for a pull request shows
MOST_DEEP = 200000      # links followed from the changed functions before the walk stops and says so
MARK = "<!-- lantern-change -->"       # the first line of the text for a pull request: how its comment is found again
FILES = ("graph.json", "security.json", "readiness.json")
LOGIN_WORDS = {"shown": "a login check is shown", "lookup": "it only looks a user up by a value of the request",
               "none": "no login check found"}
# What the changed code reaches outside the app, by the name the map gives it: the shell and a few words for the rest.
SHELL = ("subprocess", "os.system", "os.popen", "child_process", "node:child_process", "shell_exec", "exec",
         "system", "passthru", "proc_open", "popen", "Kernel.system", "Kernel.exec", "Kernel.spawn", "Kernel.`",
         "Process.Start", "Runtime.exec", "ProcessBuilder", "std.process", "std.system", "os/exec")
# A function is changed when its fingerprint is. The readers of Python, JavaScript/TypeScript, Go, Rust and Java take it
# from the function's code without comments and spacing; the readers below take it from the function's text as it is
# written, so there a comment or other spacing inside a function reads as a change, and a receipt that lists such a
# function says so (`touches.by_text`, a line of `limits`). `tests/test_diff.py` asks every reader which it is.
BY_TEXT = {"kt": "Kotlin", "sw": "Swift", "dt": "Dart", "cs": "C#", "php": "PHP", "rb": "Ruby", "cc": "C and C++"}
BY_CODE_WORDS = "by the code itself: a comment or a reformatting changes none"


class NotResults(ValueError):
    """A folder that does not hold the results of a check (the sentence says which file is missing)."""


# ---------------------------------------------------------------------------------------------------- one side
AS_THEY_ARE = "the files as they are now"


def sides(spec) -> tuple[str, str | None, bool]:
    """What the person wrote after `lantern diff`, as (the name of the commit before, the name of the commit after
    or None for the files as they are now, whether the first is to be the commit where the two parted):
    nothing → the last commit and the files as they are; `A` → A and the files as they are; `A..B`; `A...B`
    (from the commit A and B both come from, which is what a pull request shows). A side left empty is `HEAD`.
    The names are checked where they are read (`gitfacts.resolve`)."""
    spec = spec.strip() if isinstance(spec, str) else ""
    if not spec:
        return "HEAD", None, False
    for dots, parted in (("...", True), ("..", False)):
        if dots in spec:
            a, _, b = spec.partition(dots)
            return a or "HEAD", b or "HEAD", parted
    return spec, None, False


def load(out, label: str | None = None, commit: str | None = None, notes=()) -> dict:
    """The results of one check, as `compare` takes them: the three files read the strict way (`results.table`: a
    link, a pipe or a damaged file is an error, never "nothing found"). `label`: what the person called this side
    (a branch, a commit, "the files as they are"). `notes`: sentences about how this side's code was got, which
    the receipt repeats among what it does not say."""
    out = Path(out)
    side = {"out": str(out), "label": label, "commit": commit, "notes": [str(x) for x in notes]}
    for name in FILES:
        got = results.table(out / name)
        if not isinstance(got, dict):
            raise NotResults(f"{out} does not hold the results of a check: {name} is "
                             f"{'missing' if got is None else 'not what Lantern writes'}. Run `lantern analyze` first.")
        side[name.split(".")[0]] = got
    return side


def _nodes(side: dict) -> dict[str, dict]:
    return {n["id"]: n for n in side["graph"].get("nodes") or [] if isinstance(n, dict) and isinstance(n.get("id"), str)}


def _calls(side: dict) -> list[dict]:
    return [e for e in side["graph"].get("edges") or []
            if isinstance(e, dict) and e.get("kind") in ("calls", "may_call")
            and isinstance(e.get("src"), str) and isinstance(e.get("dst"), str)]


def _is_test(file) -> bool:
    from .js_frontend import TEST_RE
    from .python_frontend import TEST_FILE_RE
    return bool(isinstance(file, str) and (TEST_FILE_RE.search(file) or TEST_RE.search(file)))


def _where(n: dict | None) -> str:
    if not n or not n.get("file"):
        return ""
    return f"{n['file']}:{n['start_line']}" if n.get("start_line") else str(n["file"])


def _cut(rows: list, most: int = MOST) -> tuple[list, int]:
    return rows[:most], max(0, len(rows) - most)


# ------------------------------------------------------------------------------------------------------- doors
def _doors(side: dict, nodes: dict[str, dict]) -> dict[tuple[str, str], list[dict]]:
    """Every door of one side outside test code: (kind, words) -> its records, with the login record where the
    check wrote one (`route_logins`; None where it did not: an older Lantern, a door that is no route)."""
    logins = {r.get("node"): r for r in side["security"].get("route_logins") or [] if isinstance(r, dict)}
    recorded = isinstance(side["security"].get("route_logins"), list)
    out: dict[tuple[str, str], list[dict]] = {}
    for n in nodes.values():
        e = n.get("entry")
        if not isinstance(e, dict) or e.get("kind") in (None, "test") or _is_test(n.get("file")):
            continue
        detail = str(e.get("detail") or n.get("name") or "")
        login = logins.get(n["id"])
        rec = {"kind": str(e["kind"]), "detail": detail, "words": route_words(detail), "node": n["id"],
               "file": n.get("file"), "line": n.get("start_line"),
               "login": None if login is None else {"state": login.get("login"), "why": login.get("why"),
                                                    "public": bool(login.get("public")),
                                                    "changes": bool(login.get("changes"))},
               "login_recorded": recorded and e["kind"] == "route"}
        out.setdefault((rec["kind"], detail), []).append(rec)
    for rows in out.values():
        rows.sort(key=lambda r: (r["file"] or "", r["line"] or 0, r["node"]))
    return out


def _login_state(rec: dict) -> str | None:
    return (rec.get("login") or {}).get("state")


def _compare_doors(base: dict, head: dict, bn: dict, hn: dict) -> dict:
    was, now = _doors(base, bn), _doors(head, hn)
    added, removed, moved, login = [], [], [], []
    for key in sorted(set(was) | set(now)):
        a, b = was.get(key, []), now.get(key, [])
        for i in range(max(len(a), len(b))):
            if i >= len(a):
                added.append(b[i])
            elif i >= len(b):
                removed.append(a[i])
            else:
                before, after = _login_state(a[i]), _login_state(b[i])
                if before != after and before is not None and after is not None:
                    login.append({"kind": key[0], "detail": key[1], "words": b[i]["words"], "node": b[i]["node"],
                                  "file": b[i]["file"], "line": b[i]["line"],
                                  "before": a[i]["login"], "after": b[i]["login"],
                                  "weaker": _strength(after) < _strength(before)})
    # the same function under another address: one door that changed its words, not one gone and one new
    by_node = {r["node"]: r for r in removed}
    for r in list(added):
        old = by_node.get(r["node"])
        if old is not None and old["kind"] == r["kind"]:
            moved.append({"kind": r["kind"], "node": r["node"], "file": r["file"], "line": r["line"],
                          "before": old["detail"], "after": r["detail"],
                          "before_words": old["words"], "after_words": r["words"], "login": r["login"],
                          "login_before": old["login"]})
            added.remove(r)
            removed.remove(old)
            del by_node[r["node"]]
    return {"added": added, "removed": removed, "moved": moved, "login_changed": login}


def _strength(state: str | None) -> int:
    return {"shown": 2, "lookup": 1, "none": 0}.get(state or "", 0)


# ------------------------------------------------------------------------------------- links of page and server
def _requests(side: dict, nodes: dict[str, dict]) -> dict[tuple[str, str], dict]:
    """Every request a function of the project makes to a path of its own server: (function, words) -> where it
    leads on this side (`routes`: the routes that answer it; empty when none does, `http-unmatched`)."""
    out: dict[tuple[str, str], dict] = {}
    for e in _calls(side):
        via = e.get("via") or ""
        if not via.startswith("http-") or via == "http-external" or via == "http-trpc":
            continue
        key = (e["src"], str(e.get("detail") or ""))
        rec = out.setdefault(key, {"src": e["src"], "words": key[1], "routes": [], "how": [], "lines": []})
        rec["lines"] = sorted(set(rec["lines"]) | {x for x in e.get("lines") or [] if isinstance(x, int)})
        if via != "http-unmatched" and not outside(e["dst"]):
            rec["routes"].append(e["dst"])
            rec["how"].append(via[5:])
    for rec in out.values():
        n = nodes.get(rec["src"]) or {}
        rec["file"], rec["line"] = n.get("file"), (rec["lines"][0] if rec["lines"] else n.get("start_line"))
    return {k: v for k, v in out.items() if not _is_test(v.get("file"))}


def _route_of(nodes: dict[str, dict], nid: str) -> dict:
    n = nodes.get(nid) or {}
    detail = str((n.get("entry") or {}).get("detail") or "")
    return {"node": nid, "detail": detail, "words": route_words(detail), "file": n.get("file"), "line": n.get("start_line")}


def _became(old: dict, hn: dict, now_doors: dict) -> dict:
    """What became of a route that answered a request before: `gone`, or the same function under another address
    (`verb`, `path`, or both), with its words now."""
    n = hn.get(old["node"])
    e = (n or {}).get("entry") if n else None
    if n is None or not isinstance(e, dict) or e.get("kind") != "route":
        # the handler may have been renamed: is a route with the same path still there under another verb?
        verb, _, path = old["detail"].partition(" ")
        same_path = sorted(d for (k, d) in now_doors if k == "route" and d.partition(" ")[2] == path and path)
        if same_path:
            return {"what": "verb", "now": same_path[0], "now_words": route_words(same_path[0])}
        return {"what": "gone"}
    detail = str(e.get("detail") or "")
    if detail == old["detail"]:
        return {"what": "same", "now": detail, "now_words": route_words(detail)}
    v0, _, p0 = old["detail"].partition(" ")
    v1, _, p1 = detail.partition(" ")
    what = "verb" if p0 == p1 else "path" if v0 == v1 else "address"
    return {"what": what, "now": detail, "now_words": route_words(detail)}


def _compare_links(base: dict, head: dict, bn: dict, hn: dict) -> dict:
    was, now = _requests(base, bn), _requests(head, hn)
    now_doors = _doors(head, hn)
    broken, unanswered, mended = [], [], []
    for key in sorted(now):
        b, a = now[key], was.get(key)
        row = {"src": b["src"], "words": b["words"], "file": b["file"], "line": b["line"]}
        if not b["routes"]:
            if a is not None and a["routes"]:
                answered = [_route_of(bn, r) for r in a["routes"]]
                broken.append(row | {"answered_by": answered,
                                     "became": [_became(r, hn, now_doors) for r in answered]})
            elif a is None:
                unanswered.append(row)
        elif a is not None and not a["routes"]:
            mended.append(row | {"answered_by": [_route_of(hn, r) for r in b["routes"]]})
    # the other way round: a route some page asked before, that is still there, and that no page asks now
    asked_was = {r for v in was.values() for r in v["routes"]}
    asked_now = {r for v in now.values() for r in v["routes"]}
    unasked = []
    for nid in sorted(asked_was - asked_now):
        n = hn.get(nid)
        if n is not None and isinstance(n.get("entry"), dict) and n["entry"].get("kind") == "route":
            unasked.append(_route_of(hn, nid))
    return {"broken": broken, "unanswered": unanswered, "mended": mended, "unasked": unasked}


# ---------------------------------------------------------------------------------------------------- findings
def _brief(f: dict, nodes: dict[str, dict] | None = None) -> dict:
    out = {k: f.get(k) for k in ("id", "rank", "rule", "title", "file", "line", "tool")}
    out["heuristic"] = f.get("tool_confidence") == "LOW"
    reach = f.get("reachable") if isinstance(f.get("reachable"), dict) else None
    out["reached"] = _reached(f)
    if reach and nodes is not None:
        entry = nodes.get(reach.get("entry")) or {}
        detail = str((entry.get("entry") or {}).get("detail") or "")
        out["door"] = {"node": reach.get("entry"), "kind": reach.get("kind"), "detail": detail,
                       "words": route_words(detail) or entry.get("name")}
    if isinstance(f.get("ui_path"), list) and f["ui_path"]:
        out["clicks"] = len(f["ui_path"])
    return out


def _reached(f: dict) -> bool:
    """Does a door outside the tests reach the finding's line on the map?"""
    state = (f.get("reachability") or {}).get("state") if isinstance(f.get("reachability"), dict) else None
    if state is not None:
        return state == "reached"
    return bool(f.get("reachable")) and not f.get("reachable_from_tests_only")


def _open(side: dict) -> dict[str, dict]:
    return {f["id"]: f for f in side["security"].get("findings") or []
            if isinstance(f, dict) and isinstance(f.get("id"), str) and not f.get("in_tests")}


def _rank_no(rank) -> int:
    return RANKS.index(rank) if rank in RANKS else len(RANKS)


def _compare_findings(base: dict, head: dict, bn: dict, hn: dict) -> dict:
    was, now = _open(base), _open(head)
    gone = [was[k] for k in was if k not in now and was[k].get("status") != "accepted"]
    new = [now[k] for k in now if k not in was and now[k].get("status") != "accepted"]
    # a finding that is gone while its rule shows again in the same file was changed or moved, not fixed
    places = {(f.get("rule"), f.get("file")) for f in new}
    old_places = {(f.get("rule"), f.get("file")) for f in gone}
    fixed = [f for f in gone if (f.get("rule"), f.get("file")) not in places]
    still = [f for f in new if (f.get("rule"), f.get("file")) in old_places]
    new = [f for f in new if (f.get("rule"), f.get("file")) not in old_places]
    reached, ranked, accepted, reopened = [], [], [], []
    for k in sorted(set(was) & set(now)):
        a, b = was[k], now[k]
        if a.get("status") != "accepted" and b.get("status") == "accepted":
            acc = b.get("accepted") if isinstance(b.get("accepted"), dict) else {}
            accepted.append(_brief(b, hn) | {"how": acc.get("how") or "accepted", "reason": acc.get("reason")})
            continue
        if a.get("status") == "accepted" and b.get("status") != "accepted":
            reopened.append(_brief(b, hn))
            continue
        if b.get("status") == "accepted":
            continue
        if _reached(b) and not _reached(a):
            reached.append(_brief(b, hn) | {"rank_before": a.get("rank")})
        elif _rank_no(a.get("rank")) != _rank_no(b.get("rank")):
            ranked.append(_brief(b, hn) | {"rank_before": a.get("rank"),
                                           "raised": _rank_no(b.get("rank")) < _rank_no(a.get("rank"))})
    order = lambda f: (_rank_no(f.get("rank")), f.get("file") or "", f.get("line") or 0, f.get("id") or "")  # noqa: E731
    return {"new": [_brief(f, hn) for f in sorted(new, key=order)],
            "fixed": [_brief(f, bn) for f in sorted(fixed, key=order)],
            "still_open": [_brief(f, hn) for f in sorted(still, key=order)],
            "now_reached": sorted(reached, key=order), "rank_changed": sorted(ranked, key=order),
            "accepted": sorted(accepted, key=order), "reopened": sorted(reopened, key=order)}


# ------------------------------------------------------------------- the map: who reaches what, on one side
class _Map:
    def __init__(self, side: dict, nodes: dict[str, dict]):
        self.nodes = nodes
        self.down: dict[str, list[str]] = {}
        self.up: dict[str, list[str]] = {}
        for e in _calls(side):
            self.down.setdefault(e["src"], []).append(e["dst"])
            self.up.setdefault(e["dst"], []).append(e["src"])
        self.cut = False

    def walk(self, start, index: dict[str, list[str]]) -> set[str]:
        seen, todo, steps = set(start), list(start), 0
        while todo:
            cur = todo.pop()
            for nxt in index.get(cur, ()):
                steps += 1
                if nxt not in seen:
                    seen.add(nxt)
                    todo.append(nxt)
            if steps > MOST_DEEP:
                self.cut = True
                break
        return seen

    def doors(self, ids) -> list[dict]:
        out = []
        for nid in sorted(ids):
            n = self.nodes.get(nid) or {}
            e = n.get("entry")
            if isinstance(e, dict) and e.get("kind") not in (None, "test") and not _is_test(n.get("file")):
                detail = str(e.get("detail") or n.get("name") or "")
                out.append({"kind": str(e["kind"]), "detail": detail, "words": route_words(detail), "node": nid,
                            "file": n.get("file"), "line": n.get("start_line")})
        return out


def _paid(side: dict) -> dict[str, list[dict]]:
    """The calls that cost money, by the function that makes them (`security.json` `ai.calls`)."""
    out: dict[str, list[dict]] = {}
    ai = side["security"].get("ai") if isinstance(side["security"].get("ai"), dict) else {}
    for c in ai.get("calls") or []:
        if isinstance(c, dict) and isinstance(c.get("node"), str):
            out.setdefault(c["node"], []).append({k: c.get(k) for k in ("kind", "provider", "file", "line", "what")})
    return out


def _compare_paid(base: dict, head: dict, bmap: _Map, hmap: _Map) -> list[dict]:
    """A door that reaches a paid call now and did not before (the door is new, the call is new, or the way from
    one to the other is)."""
    def pairs(side, m):
        got = {}
        for fn, calls in _paid(side).items():
            for d in m.doors(m.walk([fn], m.up)):
                if d["kind"] == "route":
                    got[(d["kind"], d["detail"], fn)] = (d, calls)
        return got
    was, now = pairs(base, bmap), pairs(head, hmap)
    logins = {r.get("node"): r for r in head["security"].get("route_logins") or [] if isinstance(r, dict)}
    out = []
    for key in sorted(k for k in now if k not in was):
        d, calls = now[key]
        fn = hmap.nodes.get(key[2]) or {}
        login = logins.get(d["node"])
        out.append(d | {"calls": calls[:5], "in": {"node": key[2], "file": fn.get("file"), "line": fn.get("start_line")},
                        "login": None if login is None else login.get("login")})
    return out


def _kind_outside(nid: str) -> str:
    if nid.startswith("db:"):
        return "table"
    if nid.startswith("ext:HTTP "):
        return "service"
    name = nid[4:]
    return "shell" if any(name == s or name.startswith(s + ".") for s in SHELL) else "outside"


def _compare_touch(base: dict, head: dict, bn: dict, hn: dict, bmap: _Map, hmap: _Map) -> dict:
    """The functions whose code changed (by fingerprint), were added or are gone; the doors that reach them now;
    what they reach outside the app now. A function with no fingerprint on a side is not compared."""
    def code(nodes):
        return {i: n for i, n in nodes.items() if n.get("kind") == "callable" and not outside(i)}
    was, now = code(bn), code(hn)
    changed = sorted(i for i in set(was) & set(now)
                     if was[i].get("fingerprint") and now[i].get("fingerprint")
                     and was[i]["fingerprint"] != now[i]["fingerprint"])
    added = sorted(set(now) - set(was))
    removed = sorted(set(was) - set(now))
    live = [i for i in changed + added if not _is_test(now[i].get("file"))]
    # the callers of what is gone were changed too, or call something that is no longer there: they are in `changed`
    up = hmap.walk(live, hmap.up) if live else set()
    down = hmap.walk(live, hmap.down) if live else set()
    paid = _paid(head)
    reaches = {"table": [], "shell": [], "service": [], "outside": []}
    for nid in sorted(down):
        if outside(nid) and (hn.get(nid) or {}).get("lane") == "data":
            reaches[_kind_outside(nid)].append(nid.split(":", 1)[1])
    costs = sorted({f"{c.get('kind') or 'paid call'}{' (' + str(c['provider']) + ')' if c.get('provider') else ''}"
                    for nid in down | set(live) for c in paid.get(nid, ())})

    def fn(i, nodes, all_nodes):
        n = nodes[i]
        owner = all_nodes.get(n.get("parent")) or {}
        name = n.get("name") or n.get("qualname") or i
        return {"node": i, "name": f"{owner['name']}.{name}" if owner.get("kind") == "class" and owner.get("name") else name,
                "file": n.get("file"), "line": n.get("start_line")}
    files = sorted({n.get("file") for i in changed + added for n in (now[i],) if n.get("file")}
                   | {was[i].get("file") for i in removed if was[i].get("file")})
    by_text = sorted({BY_TEXT[i.split(":", 1)[0]] for i in changed if i.split(":", 1)[0] in BY_TEXT})
    return {"changed": [fn(i, now, hn) for i in changed], "added": [fn(i, now, hn) for i in added],
            "removed": [fn(i, was, bn) for i in removed], "files": files,
            "in_tests": sum(1 for i in changed + added if _is_test(now[i].get("file"))),
            "doors": hmap.doors(up), "reaches": reaches, "paid": costs, "cut_short": hmap.cut, "by_text": by_text}


# ------------------------------------------------------------------------------------------- the release decision
def _decision(side: dict) -> dict:
    rel = side["readiness"].get("release") if isinstance(side["readiness"].get("release"), dict) else {}
    crit = {c.get("id"): c.get("state") for c in rel.get("criteria") or [] if isinstance(c, dict)}
    counts = side["security"].get("counts") if isinstance(side["security"].get("counts"), dict) else {}
    return {"decision": rel.get("decision"), "words": rel.get("words"), "criteria": crit,
            "score": side["readiness"].get("score"), "grade": side["readiness"].get("grade"),
            "counts": {k: counts.get(k) for k in RANKS}}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _compare_release(base: dict, head: dict, findings: dict) -> dict:
    was, now = _decision(base), _decision(head)
    moved = [{"id": k, "before": was["criteria"].get(k), "after": now["criteria"].get(k)}
             for k in sorted(set(was["criteria"]) | set(now["criteria"]), key=str)
             if was["criteria"].get(k) != now["criteria"].get(k)]
    why = []
    serious_new =[f for f in findings["new"] if f.get("rank") in SERIOUS]
    serious_reached = [f for f in findings["now_reached"] if f.get("rank") in SERIOUS]
    serious_raised = [f for f in findings["rank_changed"] if f.get("raised") and f.get("rank") in SERIOUS
                      and f.get("rank_before") not in SERIOUS]
    serious_fixed = [f for f in findings["fixed"] if f.get("rank") in SERIOUS]
    for rows, one in ((serious_new, "new critical or high finding"),
                      (serious_reached, "critical or high finding a door reaches now"),
                      (serious_raised, "finding now ranked critical or high"),
                      (serious_fixed, "critical or high finding fixed")):
        if rows:
            why.append(_plural(len(rows), one))
    for m in moved:
        if m["id"] != "findings":
            why.append(f"{m['id']}: {m['before'] or 'not there'} → {m['after'] or 'not there'}")
    changed = was["decision"] != now["decision"]
    words = f"{was['decision'] or 'no decision'} → {now['decision'] or 'no decision'}"
    if why:
        words += f" ({'; '.join(why)})"
    return {"before": was, "after": now, "changed": changed, "criteria": moved, "why": why, "words": words}


# ------------------------------------------------------------------------------------------------- the receipt
def _limits(base: dict, head: dict, touches: dict) -> list[str]:
    out = []
    for name, side in (("before", base), ("after", head)):
        sec = side["security"]
        if not isinstance(sec.get("route_logins"), list):
            out.append(f"The check of the code {name} the change was made by a Lantern that does not write down what "
                       "each route shows about a login, so new and removed routes are listed without it and a login "
                       "check that changed is not said.")
    unfinished = [sorted({str(t.get("tool")) for t in side["security"].get("incomplete") or []
                          if isinstance(t, dict) and t.get("tool")}) for side in (base, head)]
    sides = [("both checks", unfinished[0])] if unfinished[0] == unfinished[1] else [
        ("the check of the code before the change", unfinished[0]), ("the check of the code after the change", unfinished[1])]
    for name, inc in sides:
        if inc:
            out.append(f"In {name} {_plural(len(inc), 'scanner')} did not finish or did not cover everything "
                       f"({', '.join(inc[:6])}): a finding listed as new or fixed may be one that such a scanner would "
                       "have listed on both sides.")
    tests = [(_decision(s)["criteria"].get("tests")) for s in (base, head)]
    if all(t in (None, "missing") for t in tests):
        out.append("The project's tests were run on neither side: this receipt is made from reading the code.")
    out.append("A door, a link or a way to a finding is what Lantern's map shows. A call Lantern could not follow is "
               "on neither side, so a change behind such a call is not said here.")
    if touches.get("by_text"):
        out.append(f"In {', '.join(touches['by_text'])} a function counts as changed when any character of it changed, a "
                   "comment or the spacing included: Lantern's readers of those languages compare a function's text as "
                   "it is written.")
    out.append("Code that stands outside every function (a setting at the top of a file, the fields of a class) is not "
               "listed among what the change touches. A door, a link or a finding it changes is listed.")
    for side in (base, head):
        out += [x for x in side.get("notes") or () if x not in out]
    return out


def _by_words(touch: dict) -> str:
    if not touch.get("by_text"):
        return BY_CODE_WORDS
    return f"{BY_CODE_WORDS}, except in {', '.join(touch['by_text'])}, where a function's text is compared as it is written"


def compare(base: dict, head: dict) -> dict:
    """The change receipt of two checks (`load`). Rows of one kind over `MOST` are counted in `more`."""
    bn, hn = _nodes(base), _nodes(head)
    bmap, hmap = _Map(base, bn), _Map(head, hn)
    doors = _compare_doors(base, head, bn, hn)
    links = _compare_links(base, head, bn, hn)
    findings = _compare_findings(base, head, bn, hn)
    paid = _compare_paid(base, head, bmap, hmap)
    touches = _compare_touch(base, head, bn, hn, bmap, hmap)
    release = _compare_release(base, head, findings)
    more = {}
    for name, part in (("doors", doors), ("links", links), ("findings", findings), ("touches", touches)):
        for key, rows in part.items():
            if isinstance(rows, list) and len(rows) > MOST:
                part[key], more[f"{name}.{key}"] = _cut(rows)
    paid, cut = _cut(paid)
    if cut:
        more["paid"] = cut
    counts = {"doors_added": len(doors["added"]) + more.get("doors.added", 0),
              "doors_removed": len(doors["removed"]) + more.get("doors.removed", 0),
              "doors_moved": len(doors["moved"]), "logins_changed": len(doors["login_changed"]),
              "logins_weaker": sum(1 for d in doors["login_changed"] if d["weaker"]),
              "doors_added_open": sum(1 for d in doors["added"] if _open_door(d)),
              "links_broken": len(links["broken"]), "links_unanswered": len(links["unanswered"]),
              "findings_new": len(findings["new"]), "findings_fixed": len(findings["fixed"]),
              "findings_now_reached": len(findings["now_reached"]),
              "findings_accepted": len(findings["accepted"]), "paid_new": len(paid),
              "functions_changed": len(touches["changed"]) + more.get("touches.changed", 0),
              "functions_added": len(touches["added"]) + more.get("touches.added", 0),
              "functions_removed": len(touches["removed"]) + more.get("touches.removed", 0)}
    quiet = not any(v for k, v in counts.items()) and not release["changed"] and not links["mended"] \
        and not links["unasked"] and not findings["still_open"] and not findings["rank_changed"] \
        and not findings["reopened"]
    from . import __version__
    return {"schema": SCHEMA, "lantern": __version__,
            "base": _about(base), "head": _about(head),
            "same": quiet, "counts": counts, "release": release, "doors": doors, "links": links,
            "findings": findings, "paid": paid, "touches": touches, "more": more, "limits": _limits(base, head, touches)}


def _open_door(d: dict) -> bool:
    """A new route that changes data, is not one made to be open, and shows no login check."""
    login = d.get("login") or {}
    return d.get("kind") == "route" and login.get("state") in ("none", "lookup") and login.get("changes") \
        and not login.get("public")


def _about(side: dict) -> dict:
    rel = side["readiness"].get("release") if isinstance(side["readiness"].get("release"), dict) else {}
    bound = rel.get("bound_to") if isinstance(rel.get("bound_to"), dict) else {}
    code = bound.get("code") if isinstance(bound.get("code"), dict) else {}
    return {"label": side.get("label"), "commit": side.get("commit") or bound.get("commit"),
            "code_sha256": code.get("sha256"), "files": code.get("files"),
            "uncommitted_changes": bound.get("uncommitted_changes") if not side.get("commit") else False}


# --------------------------------------------------------------------------------------------------- as text
def _name(about: dict) -> str:
    commit = about.get("commit")
    short = commit[:10] if isinstance(commit, str) else None
    label = about.get("label")
    if label and short and about.get("uncommitted_changes"):
        return f"{label} ({short} with changes that are not committed)"
    if label and short and label != commit and not str(commit).startswith(str(label)):
        return f"{label} ({short})"
    return str(label or short or "a folder with no commit")


def _login_words(login: dict | None, recorded: bool = True) -> str:
    if not login:
        return "" if not recorded else "login not looked at"
    state = login.get("state")
    words = LOGIN_WORDS.get(state, "login not known")
    if state == "shown" and login.get("why"):
        words += f" ({login['why']})"
    if state == "lookup" and login.get("why"):
        words = f"{login['why']}, which finds a record and not the caller"
    if login.get("public") and state != "shown":
        words += "; its path is one made to be open (a sign-in, a webhook)"
    return words


def _at(row: dict) -> str:
    if not row.get("file"):
        return ""
    return f"{row['file']}:{row['line']}" if row.get("line") else str(row["file"])


def _md(text) -> str:
    """Text of a project inside Markdown: no line break, no backtick that ends a code span, no HTML, bounded."""
    s = "".join(c if c.isprintable() else " " for c in str(text if text is not None else ""))[:300]
    return s.replace("`", "'").replace("<", "‹").replace(">", "›").replace("|", "¦")


def _code(text) -> str:
    return f"`{_md(text)}`" if _md(text) else ""


def _door_line(d: dict) -> str:
    at = f" ({_md(_at(d))})" if _at(d) else ""
    return f"{_code(d['words'])}{at}"


def _became_words(row: dict) -> str:
    parts = []
    for old, b in zip(row.get("answered_by") or [], row.get("became") or []):
        was = f"{_code(old['words'])}" + (f" ({_md(_at(old))})" if _at(old) else "")
        if b["what"] == "gone":
            parts.append(f"{was} answered it before and is gone")
        elif b["what"] == "same":
            parts.append(f"{was} answered it before and no longer matches it")
        else:
            what = {"verb": "answers another verb now", "path": "has another path now",
                    "address": "has another address now"}[b["what"]]
            parts.append(f"{was} answered it before and {what}: {_code(b.get('now_words'))}")
    return "; ".join(parts)


def _finding_line(f: dict) -> str:
    heur = ", heuristic" if f.get("heuristic") else ""
    door = f.get("door") or {}
    reach = f" Reached from {_code(door.get('words'))}." if f.get("reached") and door.get("words") else ""
    return (f"**{_md(f.get('rank'))}{heur}**: {_md(f.get('title'))} ({_code(f.get('rule'))}, {_md(_at(f))}).{reach}")


def _rows(lines: list[str], rows: list, fmt, more: int = 0, most: int = MOST_SHOWN) -> None:
    for r in rows[:most]:
        lines.append(f"- {fmt(r)}")
    rest = len(rows) - most + more
    if rest > 0:
        lines.append(f"- and {rest} more (all of them are in the receipt's data file)")


def summary_line(receipt: dict) -> str:
    """One line for a log or a check's title."""
    if receipt.get("same"):
        return "no change in doors, links, findings or the release decision"
    c = receipt["counts"]
    parts = []
    for key, one in (("doors_added", "new door"), ("doors_removed", "door removed"),
                     ("logins_weaker", "login check weaker or gone"), ("links_broken", "broken link"),
                     ("findings_new", "new finding"), ("findings_now_reached", "finding reached now"),
                     ("findings_fixed", "finding fixed"), ("paid_new", "new way to a paid call")):
        if c.get(key):
            parts.append(_plural(c[key], one, {"door removed": "doors removed", "finding fixed": "findings fixed",
                                               "login check weaker or gone": "login checks weaker or gone",
                                               "finding reached now": "findings reached now",
                                               "new way to a paid call": "new ways to a paid call"}.get(one)))
    return f"release decision {receipt['release']['words']}" + (": " + ", ".join(parts) if parts else "")


def markdown(receipt: dict, short: bool = False) -> str:
    """The receipt as text for a pull request (GitHub's Markdown). Everything of the project is written as text
    (`_md`): a route, a title or a file name cannot add a link, a picture or a heading. `short`: without the
    list of changed functions."""
    r, more = receipt, receipt.get("more") or {}
    doors, links, fi, touch = r["doors"], r["links"], r["findings"], r["touches"]
    out = [MARK, "## Lantern: what this change does", ""]
    out.append(f"Compared {_code(_name(r['base']))} (before) with {_code(_name(r['head']))} (after).")
    out.append("")
    rel = r["release"]
    out.append(f"**Release decision: {_md(rel['words'])}**")
    out.append("")
    if r.get("same"):
        out.append("No door was added or removed, no login check changed, no link between page and server broke, "
                   "no finding is new or fixed, and no function's code changed.")
        out.append("")
    if doors["added"] or doors["removed"] or doors["moved"] or doors["login_changed"]:
        out.append("### Doors (pages, routes, commands)")
        _rows(out, [d for d in doors["login_changed"] if d["weaker"]], lambda d: (
            f"**Login check weaker** on {_door_line(d)}: before, {_md(_login_words(d['before']))}; now, "
            f"**{_md(_login_words(d['after']))}**."))
        _rows(out, doors["added"], lambda d: (
            f"**Added** {_door_line(d)}" + (
                f": **{_md(_login_words(d['login']))}**" + (", and it changes data." if (d['login'] or {}).get('changes') else ".")
                if _open_door(d) else
                (f": {_md(_login_words(d['login'], d['login_recorded']))}." if d["kind"] == "route" and _login_words(d["login"], d["login_recorded"]) else "."))),
            more.get("doors.added", 0))
        _rows(out, doors["moved"], lambda d: f"**Address changed**: {_code(d['before_words'])} is now {_code(d['after_words'])}"
              + (f" ({_md(_at(d))})." if _at(d) else "."))
        _rows(out, [d for d in doors["login_changed"] if not d["weaker"]], lambda d: (
            f"Login check stronger on {_door_line(d)}: before, {_md(_login_words(d['before']))}; now, "
            f"{_md(_login_words(d['after']))}."))
        _rows(out, doors["removed"], lambda d: f"Removed {_door_line(d)}.", more.get("doors.removed", 0))
        out.append("")
    if links["broken"] or links["unanswered"] or links["mended"] or links["unasked"]:
        out.append("### Links between page and server")
        _rows(out, links["broken"], lambda x: (
            f"**Broken**: {_md(_at(x))} still asks {_code(x['words'])}, and no route answers it now. {_became_words(x)}."))
        _rows(out, links["unanswered"], lambda x: (
            f"**New request with no route**: {_md(_at(x))} asks {_code(x['words'])}, and no route of this project answers it."))
        _rows(out, links["mended"], lambda x: (
            f"Mended: {_md(_at(x))} asks {_code(x['words'])}, which "
            f"{', '.join(_code(a['words']) for a in x['answered_by'])} answers now."))
        _rows(out, links["unasked"], lambda x: f"No page asks {_door_line(x)} any more; the route is still there.")
        out.append("")
    if any(fi[k] for k in ("new", "now_reached", "rank_changed", "accepted", "reopened", "still_open", "fixed")):
        out.append("### Findings")
        _rows(out, fi["new"], lambda f: f"**New** · {_finding_line(f)}", more.get("findings.new", 0))
        _rows(out, fi["now_reached"], lambda f: (
            f"**Reached now** (it was in the code before, and no door reached it) · {_finding_line(f)}"))
        _rows(out, [f for f in fi["rank_changed"] if f.get("raised")], lambda f: (
            f"**Ranked higher** (was {_md(f.get('rank_before'))}) · {_finding_line(f)}"))
        _rows(out, fi["accepted"], lambda f: (
            f"**Accepted in this change** ({'a `# nosec` comment' if f.get('how') == 'nosec' else 'lantern accept'}"
            + (f": “{_md(f.get('reason'))}”" if f.get("reason") else "") + f") · {_finding_line(f)}"))
        _rows(out, fi["reopened"], lambda f: f"Open again (it was accepted before) · {_finding_line(f)}")
        _rows(out, fi["still_open"], lambda f: f"Changed and still open · {_finding_line(f)}")
        _rows(out, [f for f in fi["rank_changed"] if not f.get("raised")], lambda f: (
            f"Ranked lower (was {_md(f.get('rank_before'))}) · {_finding_line(f)}"))
        _rows(out, fi["fixed"], lambda f: f"Fixed · {_finding_line(f)}", more.get("findings.fixed", 0))
        out.append("")
    if r["paid"]:
        out.append("### Calls that cost money")
        _rows(out, r["paid"], lambda p: (
            f"{_door_line(p)} now reaches a paid call ("
            + ", ".join(sorted({_md(str(c.get('kind') or 'paid') + (' · ' + str(c['provider']) if c.get('provider') else ''))
                                for c in p['calls']}))
            + f", in {_md(_at(p['in']))})" + (f"; on the route: {_md(LOGIN_WORDS.get(p.get('login'), 'login not looked at'))}." if p.get("login") else ".")))
        out.append("")
    n_changed = r["counts"]["functions_changed"] + r["counts"]["functions_added"]
    if n_changed or touch["removed"]:
        out.append("### What the change touches")
        bits = [_plural(r["counts"]["functions_changed"], "function") + " changed" if r["counts"]["functions_changed"] else "",
                _plural(r["counts"]["functions_added"], "function") + " added" if r["counts"]["functions_added"] else "",
                _plural(r["counts"]["functions_removed"], "function") + " removed" if r["counts"]["functions_removed"] else ""]
        out.append(f"{', '.join(b for b in bits if b)}, in {_plural(len(touch['files']), 'file')} "
                   f"({_by_words(touch)})."
                   + (f" {_plural(touch['in_tests'], 'of them is', 'of them are')} test code." if touch["in_tests"] else ""))
        if touch["doors"]:
            out.append("")
            out.append(f"{_plural(len(touch['doors']), 'door')} reach the changed code:")
            _rows(out, touch["doors"], _door_line, more.get("touches.doors", 0))
        reach = touch["reaches"]
        said = []
        for key, word in (("table", "database tables"), ("shell", "the shell"), ("service", "other services"),
                          ("outside", "libraries that keep data or reach another service")):
            if reach.get(key):
                names = ", ".join(_code(x) for x in reach[key][:8]) + (f" and {len(reach[key]) - 8} more" if len(reach[key]) > 8 else "")
                said.append(f"{word}: {names}")
        if touch["paid"]:
            said.append("calls that cost money: " + ", ".join(_md(x) for x in touch["paid"][:8]))
        if said:
            out.append("")
            out.append("From the changed code the map leads to " + "; ".join(said) + ".")
        if touch.get("cut_short"):
            out.append("")
            out.append("The walk over the map was stopped at its limit: there may be more doors and more reached than listed.")
        if not short and (touch["changed"] or touch["added"] or touch["removed"]):
            out += ["", "<details><summary>The functions</summary>", ""]
            for key, word in (("changed", "changed"), ("added", "added"), ("removed", "removed")):
                _rows(out, touch[key], lambda f, word=word: f"{word}: {_code(f['name'])} ({_md(_at(f))})",
                      more.get(f"touches.{key}", 0), most=40)
            out += ["", "</details>"]
        out.append("")
    out += ["<details><summary>What this receipt does not say</summary>", ""]
    out += [f"- {_md(x) if len(x) <= 300 else x}" for x in r["limits"]]
    out += ["", "</details>", "",
            f"<sub>Made by Lantern {_md(r.get('lantern'))} from two checks of the code. Facts from the map and the "
            "scanners; no model wrote or ranked any line.</sub>", ""]
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------- as a page
def E(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


PAGE_STYLE = """
main{max-width:960px} .rows{list-style:none;padding:0;margin:0} .rows li{padding:10px 0;border-top:1px solid var(--line);margin:0}
.rows li:first-child{border-top:0} .what{display:inline-block;font:700 10px var(--mono);letter-spacing:.06em;text-transform:uppercase;
padding:2px 7px;border-radius:5px;background:var(--hover);color:var(--body);margin-right:8px}
.what.bad{background:var(--critical-soft);color:var(--crit-ink)} .what.warn{background:var(--warning-soft);color:var(--warn-ink)}
.what.good{background:var(--good-soft);color:var(--good-ink)} .sub{display:block;color:var(--muted);font-size:12.5px;margin-top:3px}
.arrow{font:400 26px/1.3 var(--serif);color:var(--ink);margin:6px 0 2px} .arrow .to{color:var(--muted);padding:0 10px}
"""


def page(receipt: dict) -> str:
    """The receipt as one page that holds everything it shows: no script at all, and a Content-Security-Policy
    that allows none, so a page opened from disk cannot run anything planted in its data. Every value is escaped
    (`E`). The look is the Evidence Report's (`evidence.STYLE`: one set of design tokens)."""
    from .evidence import DECISION_LOOK, STYLE
    r, more = receipt, receipt.get("more") or {}
    doors, links, fi, touch, rel = r["doors"], r["links"], r["findings"], r["touches"], r["release"]

    def li(kind: str, tone: str, body: str, sub: str = "") -> str:
        return (f"<li><span class='what {tone}'>{E(kind)}</span>{body}"
                + (f"<span class='sub'>{sub}</span>" if sub else "") + "</li>")

    def door(d) -> str:
        return f"<code>{E(d.get('words'))}</code>" + (f" <span class='muted'>{E(_at(d))}</span>" if _at(d) else "")

    def rest(key: str, rows: list) -> str:
        n = more.get(key, 0)
        return f"<li class='muted'>and {E(n)} more, in the data file</li>" if n else ""

    def finding(kind: str, tone: str, f: dict, extra: str = "") -> str:
        heur = " <span class='tag'>heuristic</span>" if f.get("heuristic") else ""
        d = f.get("door") or {}
        reach = f"reached from <code>{E(d.get('words'))}</code> · " if f.get("reached") and d.get("words") else ""
        return li(kind, tone, f"<span class='sev {E(f.get('rank'))}'>{E(f.get('rank'))}</span> <b>{E(f.get('title'))}</b>{heur}",
                  f"{reach}{E(f.get('rule'))} · {E(_at(f))}{extra}")

    sections = []
    look = DECISION_LOOK.get(rel["after"].get("decision"), ("•", ""))
    head = (f"<section><div class='eyebrow'><span>Change receipt</span><span>Lantern {E(r.get('lantern'))}</span></div>"
            f"<h1 class='memo'>What this change does</h1>"
            f"<p class='lead'>Compared <code>{E(_name(r['base']))}</code> (before) with <code>{E(_name(r['head']))}</code> "
            f"(after), from two checks of the code.</p>"
            f"<div class='rel {E(look[1])}'><div class='arrow'><b>{E(rel['before'].get('decision') or 'no decision')}</b>"
            f"<span class='to'>→</span><b>{E(look[0])} {E(rel['after'].get('decision') or 'no decision')}</b></div>"
            + (f"<div>{E('; '.join(rel['why']))}</div>" if rel["why"] else "")
            + (f"<div class='muted'>{E(rel['after'].get('words'))}</div>" if rel["after"].get("words") else "")
            + "</div>"
            + ("<p>No door was added or removed, no login check changed, no link between page and server broke, no "
               "finding is new or fixed, and no function's code changed.</p>" if r.get("same") else "")
            + "</section>")
    sections.append(head)
    rows = []
    for d in doors["login_changed"]:
        if d["weaker"]:
            rows.append(li("login weaker", "bad", door(d), f"before: {E(_login_words(d['before']))} · now: {E(_login_words(d['after']))}"))
    for d in doors["added"]:
        words = _login_words(d["login"], d["login_recorded"]) if d["kind"] == "route" else ""
        tone = "bad" if _open_door(d) else "warn"
        rows.append(li("added", tone, door(d), E(words) + (" · it changes data" if _open_door(d) else "")))
    rows.append(rest("doors.added", doors["added"]))
    for d in doors["moved"]:
        rows.append(li("address changed", "warn", f"<code>{E(d['before_words'])}</code> is now <code>{E(d['after_words'])}</code>", E(_at(d))))
    for d in doors["login_changed"]:
        if not d["weaker"]:
            rows.append(li("login stronger", "good", door(d), f"before: {E(_login_words(d['before']))} · now: {E(_login_words(d['after']))}"))
    for d in doors["removed"]:
        rows.append(li("removed", "", door(d)))
    rows.append(rest("doors.removed", doors["removed"]))
    if any(rows):
        sections.append("<section><h2>Doors <small>pages, routes, commands</small></h2><ul class='rows'>" + "".join(rows) + "</ul></section>")
    rows = []
    for x in links["broken"]:
        rows.append(li("broken", "bad", f"<span class='muted'>{E(_at(x))}</span> still asks <code>{E(x['words'])}</code>, and no route answers it now",
                       E(_became_words(x).replace("`", ""))))
    for x in links["unanswered"]:
        rows.append(li("no route", "warn", f"<span class='muted'>{E(_at(x))}</span> asks <code>{E(x['words'])}</code>, and no route of this project answers it"))
    for x in links["mended"]:
        rows.append(li("mended", "good", f"<span class='muted'>{E(_at(x))}</span> asks <code>{E(x['words'])}</code>",
                       "answered now by " + ", ".join(f"<code>{E(a['words'])}</code>" for a in x["answered_by"])))
    for x in links["unasked"]:
        rows.append(li("not asked", "", door(x), "no page asks it any more; the route is still there"))
    if rows:
        sections.append("<section><h2>Links between page and server</h2><ul class='rows'>" + "".join(rows) + "</ul></section>")
    rows = [finding("new", "bad", f) for f in fi["new"]] + [rest("findings.new", fi["new"])]
    rows += [finding("reached now", "bad", f, " · in the code before, and no door reached it") for f in fi["now_reached"]]
    rows += [finding("ranked higher", "warn", f, f" · was {E(f.get('rank_before'))}") for f in fi["rank_changed"] if f.get("raised")]
    rows += [finding("accepted here", "warn", f, " · " + E("a # nosec comment" if f.get("how") == "nosec" else "lantern accept")
                     + (f": “{E(f.get('reason'))}”" if f.get("reason") else "")) for f in fi["accepted"]]
    rows += [finding("open again", "warn", f, " · it was accepted before") for f in fi["reopened"]]
    rows += [finding("still open", "", f, " · changed in this change") for f in fi["still_open"]]
    rows += [finding("ranked lower", "", f, f" · was {E(f.get('rank_before'))}") for f in fi["rank_changed"] if not f.get("raised")]
    rows += [finding("fixed", "good", f) for f in fi["fixed"]] + [rest("findings.fixed", fi["fixed"])]
    if any(rows):
        sections.append("<section><h2>Findings</h2><ul class='rows'>" + "".join(rows) + "</ul></section>")
    if r["paid"]:
        rows = [li("paid call", "warn", door(p) + " now reaches a call that costs money",
                   E(", ".join(sorted({str(c.get("kind") or "paid") + (" · " + str(c["provider"]) if c.get("provider") else "")
                                       for c in p["calls"]}))) + f" · in {E(_at(p['in']))}"
                   + (f" · on the route: {E(LOGIN_WORDS.get(p.get('login'), 'login not looked at'))}" if p.get("login") else ""))
                for p in r["paid"]]
        sections.append("<section><h2>Calls that cost money</h2><ul class='rows'>" + "".join(rows) + "</ul></section>")
    c = r["counts"]
    if c["functions_changed"] or c["functions_added"] or c["functions_removed"]:
        tiles = "".join(f"<div><div class='v'>{E(v)}</div><div class='k'>{E(k)}</div></div>" for v, k in (
            (c["functions_changed"], "functions changed"), (c["functions_added"], "functions added"),
            (c["functions_removed"], "functions removed"), (len(touch["doors"]) + more.get("touches.doors", 0), "doors that reach them")))
        body = f"<div class='tiles'>{tiles}</div><p class='muted'>{E(_by_words(touch)[:1].upper() + _by_words(touch)[1:])}.</p>"
        if touch["doors"]:
            body += "<h4>Doors that reach the changed code</h4><ul class='rows'>" + "".join(
                li(d["kind"], "", door(d)) for d in touch["doors"][:60]) + rest("touches.doors", touch["doors"]) + "</ul>"
        reach = []
        for key, word in (("table", "Database tables"), ("shell", "The shell"), ("service", "Other services"),
                          ("outside", "Libraries that keep data or reach another service")):
            if touch["reaches"].get(key):
                reach.append(f"<div>{E(word)}</div><div>" + " ".join(f"<code>{E(x)}</code>" for x in touch["reaches"][key][:40]) + "</div>")
        if touch["paid"]:
            reach.append("<div>Calls that cost money</div><div>" + E(", ".join(touch["paid"][:20])) + "</div>")
        if reach:
            body += "<h4>What the changed code reaches</h4><div class='kv'>" + "".join(reach) + "</div>"
        if touch.get("cut_short"):
            body += "<p class='warn'>The walk over the map was stopped at its limit: there may be more than listed.</p>"
        fns = "".join(f"<li><span class='what'>{E(word)}</span><code>{E(f['name'])}</code> <span class='muted'>{E(_at(f))}</span></li>"
                      for key, word in (("changed", "changed"), ("added", "added"), ("removed", "removed")) for f in touch[key][:300])
        body += f"<details class='tied'><summary>The functions</summary><ul class='rows'>{fns}</ul></details>"
        sections.append(f"<section><h2>What the change touches</h2>{body}</section>")
    sections.append("<section><h2>What this receipt does not say</h2><ul>" + "".join(f"<li>{E(x)}</li>" for x in r["limits"])
                    + "</ul><p class='muted'>Facts from Lantern's map and scanners on two checks of the code. No model wrote "
                    "or ranked any line of this page.</p></section>")
    style = STYLE + PAGE_STYLE
    digest = base64.b64encode(hashlib.sha256(style.encode("utf-8")).digest()).decode("ascii")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'sha256-{digest}'; "
            "base-uri 'none'; form-action 'none'\">"
            f"<title>Change receipt · {E(_name(r['head']))}</title>\n<style>{style}</style></head>"
            "<body data-mode=\"simple\"><main>" + "".join(sections) + "</main></body></html>\n")


NAMES = {"json": "change.json", "md": "change.md", "html": "change.html"}


def write(out, receipt: dict) -> dict[str, Path]:
    """The receipt as its three files in `out`, each written the way a result file is (`results.write`)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    paths = {k: out / v for k, v in NAMES.items()}
    results.write(paths["json"], json.dumps(receipt, indent=1))
    results.write(paths["md"], markdown(receipt))
    results.write(paths["html"], page(receipt))
    return paths
