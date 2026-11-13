"""Behaviour checks: what a running app really does when the wrong person asks (directive point 5, 2026-11-11:
"Test full-stack behavior, not just source patterns ... A rejected request that already changed the database is a
failure. Test the side effects, not just the response code. Keep these tests away from production.").

The project says what must hold in `lantern-behaviour.json` (the plan): how its app is loaded, the people (how each
signs in), and checks. `run(repo)` starts the app inside the test sandbox (`sandbox.run_inside`: a read-only copy,
no network, a temp folder for its data), never at an address: a plan has paths only, so nothing here can be pointed
at a live site. Inside, `lantern._behave_inside` sends each request and writes down the answer and what changed in
the database and on disk. Out here `judge` reads that record. One outcome per case:

* `held`         the app did what the plan says must hold, and the control beside it worked;
* `broken`       with codes (`CODES`): let in, refused but changed, leaked, accepted, took effect, sent elsewhere,
                 outside address, outside file, unlimited, forgotten, raced, repeated, partial, carried over, stuck,
                 crashed;
* `inconclusive` the control failed (the rightful person was refused too, or nothing changed for them), so a
                 refusal proves nothing;
* `not-run`      with the reason.

A refusal counts only when the same request from the person who may make it worked. Asking where a name leads is
not reaching it: the runner answers such questions itself (the plan's `names` says which names lead inside), and
only what the app then sets out for counts (`may_reach` lists what it may). Nothing here creates, closes
or lowers a finding: the outcomes are a record of their own (`behaviour.json`), made by running the project's code.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import platform
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

from . import __version__, gitfacts, manifest, release, results, sandbox, seal
from .python_frontend import project_text

PLAN_NAME = "lantern-behaviour.json"
RESULT_NAME = "behaviour.json"
KINDS = ("refuse", "hide", "tokens", "input", "keeps", "contain", "redirect", "address", "limit", "once", "retry",
         "faults")
TOKEN_VARIANTS = ("none", "empty", "garbage", "truncated", "altered", "unsigned", "other-key", "expired")
CODES = {
    "let-in": "was let in",
    "refused-but-changed": "was refused, and something had changed all the same",
    "leaked": "the answer holds what this person must not see",
    "accepted": "a request that must be refused was accepted",
    "took-effect": "what must stay as it was did not",
    "sent-elsewhere": "the redirect leads to another site",
    "outside-address": "the app tried to reach an address it must not",
    "outside-file": "the app wrote, or tried to write, outside the folders it keeps its files in",
    "unlimited": "the tries were not limited",
    "forgotten": "the limit was forgotten",
    "raced": "two requests at the same moment did what one after the other does not",
    "repeated": "the same request sent again was done again",
    "partial": "a request that failed half-way left half of its work behind",
    "carried-over": "the half of a failed request was saved by the next request",
    "stuck": "after the failure the next ordinary request failed too",
    "crashed": "the app answered with a server error",
}
MAX_CHECKS = 2000
HOST = re.compile(r"""['"]([^'"]{1,200})['"]""")


class PlanError(ValueError):
    """The plan cannot be used; the message says why, in Lantern's words."""


# ------------------------------------------------------------------------------------------------ the plan
def load(repo: Path) -> dict | None:
    """The project's plan, None when it has none. PlanError when the file is there and cannot be used."""
    try:
        text = project_text(Path(repo) / PLAN_NAME, Path(repo))
    except OSError:
        return None
    plan = manifest.parse_json(text)
    if not isinstance(plan, dict):
        raise PlanError(f"{PLAN_NAME} is not a JSON table")
    return check(plan)


def _request_ok(req, where: str) -> None:
    if not isinstance(req, dict) or not isinstance(req.get("path", "/"), str):
        raise PlanError(f"{where}: a request is a table with a path")
    path = req.get("path", "/")
    if not path.startswith("/") or path.startswith("//") or "://" in path.split("?", 1)[0]:
        raise PlanError(f"{where}: a request names a path of the app (it starts with one slash), never an address")
    if any(str(k).lower() == "host" for k in (req.get("headers") or {})):
        raise PlanError(f"{where}: a request cannot name a host")


def check(plan: dict) -> dict:
    """The plan when it has the shape this version reads; PlanError otherwise."""
    app = plan.get("app")
    if not isinstance(app, dict) or not re.fullmatch(r"[A-Za-z_][\w.]*(:[A-Za-z_]\w*)?", str(app.get("asgi") or "")):
        raise PlanError('the plan needs "app": {"asgi": "package.module:name"}, the way the app is loaded')
    if "factory" in app and not isinstance(app["factory"], bool):
        raise PlanError('"factory" is true where "asgi" names a function that makes the app (create_app), else left out')
    if not isinstance(plan.get("checks"), list) or not plan["checks"]:
        raise PlanError("the plan has no checks")
    if not _stays_inside(app.get("cwd", "")):
        raise PlanError('"cwd" is a folder of the project (backend/api), where the app is started')
    state = plan.get("state") or {}
    if not isinstance(state, dict) or not all(isinstance(p, str) and p.startswith("{data}/") and _stays_inside(p[7:])
                                              for key in ("sqlite", "folders") for p in _list(state.get(key))):
        raise PlanError('"state" names the app\'s database files and folders inside the folder the sandbox gives it: '
                        '{data}/app.db (the plan hands {data} to the app through "env")')
    names = plan.get("names") or {}
    if not isinstance(names, dict) or len(names) > 200 or not all(isinstance(k, str) and k.strip() and _is_address(v)
                                                                 for k, v in names.items()):
        raise PlanError('"names" is a table from a name to the address it leads to, written out (10.0.0.5, fd00::5)')
    if not _names_ok(plan.get("may_reach")) or not all(_names_ok(c.get("may_reach")) for c in plan["checks"]
                                                       if isinstance(c, dict)):
        raise PlanError('"may_reach" is a list of the names or addresses the app may try')
    people = plan.get("people") or {}
    if not isinstance(people, dict) or not all(isinstance(p, dict) for p in people.values()):
        raise PlanError('"people" is a table of tables')
    for i, step in enumerate(plan.get("seed") or []):
        if not isinstance(step, dict):
            raise PlanError(f"seed step {i + 1} is not a table")
        if "request" in step:
            _request_ok(step["request"], f"seed step {i + 1}")
        if "sql" in step and (not isinstance(step["sql"], dict)
                              or step["sql"].get("db") not in ((plan.get("state") or {}).get("sqlite") or [])):
            raise PlanError(f'seed step {i + 1}: its SQL is for a database the plan does not name under "state"')
    seen = set()
    for i, c in enumerate(plan["checks"]):
        where = f"check {i + 1}"
        if not isinstance(c, dict) or c.get("kind") not in KINDS or not isinstance(c.get("id"), str):
            raise PlanError(f"{where}: a check is a table with an id and a kind ({', '.join(KINDS)})")
        if c["id"] in seen or "/" in c["id"]:
            raise PlanError(f"{where}: its id is used twice, or holds a slash")
        seen.add(c["id"])
        _request_ok(c.get("request"), where)
        for key in ("good", "then", "after"):
            if key in c:
                _request_ok((c[key] or {}).get("request", c[key]) if isinstance(c[key], dict) else c[key], where)
        for who in _list(c.get("who")) + _list(c.get("allowed")) + _list(c.get("shown_to")):
            if who != "nobody" and who not in people:
                raise PlanError(f"{where}: the plan names nobody called {str(who)[:40]}")
        if "variants" in c and (not isinstance(c["variants"], list) or not c["variants"]
                                or any(v not in TOKEN_VARIANTS for v in c["variants"])):
            raise PlanError(f'{where}: "variants" is a list of ways to send a token: {", ".join(TOKEN_VARIANTS)}')
    return plan


def _list(x) -> list:
    return [] if x is None else list(x) if isinstance(x, (list, tuple)) else [x]


def _stays_inside(path) -> bool:
    """A relative path that names nothing above where it starts, on any system."""
    return isinstance(path, str) and "\\" not in path and not path.startswith("~") \
        and not PurePosixPath(path).is_absolute() and not PureWindowsPath(path).is_absolute() \
        and ".." not in PurePosixPath(path).parts


def _is_address(value) -> bool:
    try:
        return isinstance(value, str) and bool(ipaddress.ip_address(value))
    except ValueError:
        return False


def _names_ok(value) -> bool:
    return value is None or (isinstance(value, list) and all(isinstance(v, str) for v in value))


def _step(request: dict, who=None, **more) -> dict:
    step = {"request": request, **more}
    if who and who != "nobody":
        step["as"] = who
    return step


ACROSS = {"same": "straight after", "restart": "after a restart", "other-worker": "on another worker"}


def scene(plan: dict) -> tuple[dict, list]:
    """What goes into the sandbox (the app, the seed, one probe per case) and, for the judge, what each probe is.
    A probe is the check's own set-up steps (`arrange`) and then its steps, or one request to be made to fail in
    every place it can (`sweep`); `fresh` has the seed's state put back after it whatever it left."""
    probes, cases = [], []

    def add(c: dict, case: str, steps: list, role: str = "case", fresh: bool = False, **more) -> None:
        probes.append({"id": f"{c['id']}/{case}", "arrange": list(c.get("arrange") or []), "steps": steps, "fresh": fresh})
        cases.append({"check": c["id"], "case": case, "role": role, **more})

    for c in plan["checks"]:
        kind, req = c["kind"], c["request"]
        who = (_list(c.get("who")) or [None])[0]
        if kind in ("refuse", "hide"):
            for person in _list(c.get("allowed") if kind == "refuse" else c.get("shown_to")):
                add(c, f"{person} (may)", [_step(req, person)], role="control")
            for person in _list(c.get("who")):
                add(c, person, [_step(req, person)])
        elif kind == "tokens":
            add(c, "valid", [_step(req, who)], role="control")
            for variant in c.get("variants") or TOKEN_VARIANTS:
                add(c, variant, [_step(req, who, token={"variant": variant, "claims": c.get("claims")})])
        elif kind == "input":
            if c.get("good"):
                add(c, "the ordinary request", [_step(c["good"], who)], role="control")
            add(c, "the bad request", [_step(req, who)])
        elif kind in ("keeps", "contain"):
            steps = [_step(req, who, save=c.get("save") or {})]
            if c.get("after"):
                after = c["after"]
                steps.append(_step(after.get("request", after), after.get("as", who)))
            add(c, "the request", steps)
        elif kind in ("redirect", "address"):
            if c.get("good"):
                add(c, "the ordinary request", [_step(c["good"], who)], role="control")
            add(c, "the request", [_step(req, who)])
        elif kind == "limit":
            tries = [_step(req, who) for _ in range(int(c.get("times", 5)))]
            last = _step(c.get("then") or req, who)
            for across in c.get("across") or list(ACROSS):
                more = {"same": [last], "restart": [{"restart": True}, last], "other-worker": [dict(last, worker=1)]}[across]
                add(c, ACROSS[across], tries + more, fresh=True, across=across)
        elif kind == "once":
            one, two = _step(req, who), _step(req, who, worker=1)
            for n in (1, 2):
                add(c, f"one after the other ({n})", [one, two], role="control", fresh=True)
            add(c, "at the same moment", [dict(one, fault={"kind": "pause", "on": "write", "at": 1}), two,
                                          {"resume": {"worker": 0}}], fresh=True)
        elif kind == "retry":
            add(c, "once", [_step(req, who)], role="control", fresh=True)
            add(c, "sent again", [_step(req, who), _step(req, who)], fresh=True)
            add(c, "sent again after the answer was lost",
                [_step(req, who, fault={"kind": "kill", "on": "answer", "at": 1}), _step(req, who)], fresh=True)
        elif kind == "faults":
            then = c.get("then")
            probes.append({"id": f"{c['id']}/failures", "arrange": list(c.get("arrange") or []),
                           "sweep": {"step": _step(req, who),
                                     "then": [_step(then.get("request", then), then.get("as", who))] if then else []}})
            cases.append({"check": c["id"], "case": "failures", "role": "case"})
    if len(probes) > MAX_CHECKS:
        raise PlanError(f"the plan asks for {len(probes)} cases; this version runs at most {MAX_CHECKS}")
    inside = {k: copy.deepcopy(plan.get(k)) for k in ("app", "state", "people", "tokens", "seed", "quiet_tables", "names")
              if plan.get(k) is not None}
    inside["probes"] = probes
    return inside, cases


# ------------------------------------------------------------------------------------------------ the judge
def _loud(changes: dict | None, quiet) -> dict:
    """What changed, without the tables the plan says may change when a request is refused."""
    changes = changes or {}
    out = {name: counts for name, counts in (changes.get("tables") or {}).items() if name not in quiet}
    if (changes.get("files") or {}).get("count"):
        out["(files)"] = [len(changes["files"]["added"]), len(changes["files"]["removed"]), len(changes["files"]["changed"])]
    return out


def _set_out_for(steps: list) -> list:
    """Each address the app set out for, with the names it had asked about that lead there. The guard's line
    for a refused connection holds the address; where the computer has no IPv6 the app copy kept what the app
    had begun (`began`). A question about a name that went past the runner's own answers and was refused by the
    guard (a program the app started) is kept under the name."""
    names: dict = {}
    for s in steps:
        for name, address, *_ in s.get("asked") or []:
            names.setdefault(str(address), set()).add(str(name).lower())
    out = []
    for s in steps:
        for line in s.get("blocked") or []:
            if line.startswith("network"):
                where = (HOST.search(line) or [None, ""])[1].rstrip(".").lower()
                out.append((where, names.get(where, set()) | {where}))
        for address, *_ in s.get("began") or []:
            out.append((str(address), names.get(str(address), set()) | {str(address)}))
    return out


def _everywhere(steps: list, may_reach=()) -> list:
    """What no case may do, whatever it is about: write outside its folders, or set out for an address the plan
    does not say it may try. Asking where a name leads is not setting out for it."""
    codes = []
    allowed = {str(name).rstrip(".").lower() for name in may_reach}
    for _where, known_as in _set_out_for(steps):
        if not known_as & allowed:
            codes.append("outside-address")
    for s in steps:
        if any(not line.startswith("network") for line in s.get("blocked") or []) or (s.get("changes") or {}).get("outside"):
            codes.append("outside-file")
    return list(dict.fromkeys(codes))


def _status(step: dict) -> int | None:
    return step.get("status") if isinstance(step.get("status"), int) else None


def _matches(step: dict, expect: dict) -> bool:
    for where, want in (expect or {}).items():
        if where == "status":
            got = step.get("status")
        elif where.startswith("header:"):
            got = (step.get("headers") or {}).get(where[7:].lower())
        elif where.startswith("json:"):
            try:
                got = json.loads(step.get("body") or "")
                for key in where[5:].split("."):
                    got = got[int(key)] if isinstance(got, list) else got[key]
            except (ValueError, KeyError, IndexError, TypeError):
                got = None
        else:
            got = None
        if isinstance(want, dict) and "starts" in want:
            ok = isinstance(got, str) and got.startswith(want["starts"])
        elif isinstance(want, dict) and "holds" in want:
            ok = isinstance(got, str) and want["holds"] in got
        else:
            ok = got == want
        if not ok:
            return False
    return True


def _same_site(location: str, own=("app.test",)) -> bool:
    if location.startswith("/"):
        return not location.startswith(("//", "/\\"))
    m = re.match(r"(?i)^[a-z][a-z0-9+.-]*:[/\\]*([^/\\?#]*)", location)
    return bool(m) and m.group(1).rsplit("@", 1)[-1].split(":")[0].lower() in own


def _saw(steps: list, quiet) -> dict:
    last = next((s for s in reversed(steps) if "status" in s or s.get("died") or s.get("paused")), steps[-1] if steps else {})
    saw = {"status": _status(last)}
    loud = _loud((steps[-1] if steps else {}).get("changes"), quiet)
    if loud:
        saw["changed"] = loud
    tried = [line for s in steps for line in s.get("blocked") or []]
    tried += [f"network connect {tuple(b)!r} (this computer has no IPv6, so it ended one step earlier)"
              for s in steps for b in s.get("began") or []]
    if tried:
        saw["tried"] = tried[:5]
    outside = [str(name)[:200] for s in steps for zone in ("added", "removed", "changed")
               for name in ((s.get("changes") or {}).get("outside") or {}).get(zone) or []]
    if outside:                 # files outside the app's folders that were made, removed or changed (from the sandbox's temp folder)
        saw["outside"] = list(dict.fromkeys(outside))[:5]
    asked = [[name, address] for s in steps for name, address, *_ in s.get("asked") or []]
    if asked:
        saw["asked"] = [pair for i, pair in enumerate(asked) if pair not in asked[:i]][:10]
    if last.get("died"):
        saw["died"] = True
    return saw


def _outcome(case: dict, check: dict, outcome: str, codes=(), why: str = "", saw: dict | None = None) -> dict:
    out = {"check": case["check"], "case": case["case"], "kind": check["kind"], "outcome": outcome}
    if check.get("about"):
        out["about"] = str(check["about"])[:200]
    if codes:
        out["codes"] = list(codes)
        out["said"] = "; ".join(CODES[c] for c in codes)
    if why:
        out["why"] = why
    if saw:
        out["saw"] = saw
    return out


def judge(plan: dict, cases: list, observed: dict) -> list:
    """One outcome per case that is not a control, read from what the recorder wrote down."""
    quiet = set(plan.get("quiet_tables") or [])
    may_reach = tuple(plan.get("may_reach") or ())
    by_id = {p.get("id"): p for p in observed.get("probes") or [] if isinstance(p, dict)}
    checks = {c["id"]: c for c in plan["checks"]}
    controls: dict = {}
    for case in cases:
        if case["role"] == "control":
            controls.setdefault(case["check"], []).append(by_id.get(f"{case['check']}/{case['case']}"))
    outcomes = []
    for case in cases:
        if case["role"] == "control":
            continue
        check = checks[case["check"]]
        probe = by_id.get(f"{case['check']}/{case['case']}")
        if probe is None:
            outcomes.append(_outcome(case, check, "not-run", why="the run ended before this case"))
            continue
        if "sweep" in probe:
            outcomes.extend(_faults(case, check, probe, quiet, may_reach + tuple(check.get("may_reach") or ())))
            continue
        steps = probe.get("steps") or []
        skipped = next((s["not_run"] for s in steps if s.get("not_run")), None)
        if skipped or not steps:
            outcomes.append(_outcome(case, check, "not-run", why=str(skipped or "no step was run")[:300]))
            continue
        kind = check["kind"]
        codes = _everywhere(steps, may_reach + tuple(check.get("may_reach") or ()))
        last = steps[-1]
        status = _status(last)
        why = ""
        ctl = [c for c in controls.get(case["check"], [])]
        ctl_steps = [(c or {}).get("steps") or [] for c in ctl]
        if kind in ("refuse", "tokens", "input"):
            for cs in ctl_steps:
                st = _status(cs[-1]) if cs else None
                if st is None or st >= 400:
                    why = f"the request was refused for the one who may make it too (status {st}), so a refusal here proves nothing"
                elif check["request"].get("method", "GET").upper() not in ("GET", "HEAD") and kind != "input" \
                        and not _loud(cs[-1].get("changes"), quiet):
                    why = "nothing changed when the one who may make the request made it, so there is nothing to protect here"
            if status is None:
                codes.append("crashed")
            elif status >= 500:
                codes.append("crashed")
            elif status < 400:
                codes.append("accepted" if kind == "input" else "let-in")
            elif _loud(last.get("changes"), quiet):
                codes.append("refused-but-changed")
            if any(text and text in (last.get("body") or "") for text in check.get("must_not_say") or []):
                codes.append("leaked")
        elif kind == "hide":
            for cs in ctl_steps:
                body = (cs[-1].get("body") or "") if cs else ""
                if not all(text in body for text in check.get("must_not_say") or []):
                    why = "the text is not in the answer of the one who may see it either, so its absence proves nothing"
            if any(text and text in (last.get("body") or "") for text in check.get("must_not_say") or []):
                codes.append("leaked")
            if status is None or status >= 500:
                codes.append("crashed")
        elif kind in ("keeps", "contain"):
            if status is None or status >= 500:
                codes.append("crashed")
            if kind == "keeps":
                if check.get("expect") and not _matches(last, check["expect"]):
                    codes.append("took-effect")
                if check.get("expect_not") and _matches(last, check["expect_not"]):
                    codes.append("took-effect")
        elif kind == "redirect":
            own = tuple(check.get("own_hosts") or ("app.test",))
            for cs in ctl_steps:
                st, to = (_status(cs[-1]), (cs[-1].get("headers") or {}).get("location")) if cs else (None, None)
                if st is None or not 300 <= st < 400 or to is None or not _same_site(to, own):
                    why = "the app does not redirect to a page of its own either, so nothing is shown here"
            where = (last.get("headers") or {}).get("location")
            if status is not None and 300 <= status < 400 and where is not None and not _same_site(where, own):
                codes.append("sent-elsewhere")
            if status is None or status >= 500:
                codes.append("crashed")
        elif kind == "address":
            pass                                 # `_everywhere` read what the app tried to reach
        elif kind == "limit":
            limited = tuple(check.get("limited") or (429, 423))
            tries = [s for s in steps if "status" in s]
            if len(tries) < 2 or any(_status(s) in limited for s in tries[:1]):
                why = "the first try was refused as too many already"
            elif status not in limited:
                at_once = (by_id.get(f"{case['check']}/{ACROSS['same']}") or {}).get("steps") or [{}]
                kept_at_once = case.get("across") != "same" and _status(at_once[-1]) in limited
                codes.append("forgotten" if kept_at_once else "unlimited")
        elif kind == "once":
            ends = [cs[-1]["state"]["loud"] for cs in ctl_steps if cs and "state" in cs[-1]]
            if not steps[0].get("paused"):
                outcomes.append(_outcome(case, check, "not-run", why="the request writes nothing, so two cannot cross"))
                continue
            if len(ends) < 2 or ends[0] != ends[1]:
                why = "the request does not end the same way twice, so two at the same moment cannot be compared"
            elif last["state"]["loud"] != ends[0]:
                codes.append("raced")
        elif kind == "retry":
            once = next((cs for cs in ctl_steps if cs), [])
            first = _status(steps[0])
            alone = _status(once[-1]) if once else None
            if case["case"] == "sent again":
                if first is None or first >= 400:
                    why = f"the request did not work the first time (status {first})"
                elif steps[1]["state"]["loud"] != steps[0]["state"]["loud"]:
                    codes.append("repeated")
            elif alone is None or alone >= 400:
                why = f"the request did not work when it was sent once (status {alone})"
            elif _loud(once[-1].get("changes"), quiet) != _loud(last.get("changes"), quiet):
                codes.append("repeated")            # more rows, or other rows, than the one request leaves
            elif once[-1]["state"]["loud"] != last["state"]["loud"]:
                why = "as many rows changed as when the request is sent once, but not to the same content"
        codes = list(dict.fromkeys(codes))
        if codes:
            outcomes.append(_outcome(case, check, "broken", codes, saw=_saw(steps, quiet)))
        elif why:
            outcomes.append(_outcome(case, check, "inconclusive", why=why, saw=_saw(steps, quiet)))
        else:
            outcomes.append(_outcome(case, check, "held", saw=_saw(steps, quiet)))
    return outcomes


def _counts(step: dict, quiet=()) -> dict:
    changes = step.get("changes") or {}
    return {"tables": {name: n for name, n in (changes.get("tables") or {}).items() if name not in quiet},
            "files": (changes.get("files") or {}).get("count", 0)}


def _sum(a: dict, b: dict) -> dict:
    tables = {name: [x + y for x, y in zip(a["tables"].get(name, [0, 0, 0]), b["tables"].get(name, [0, 0, 0]))]
              for name in set(a["tables"]) | set(b["tables"])}
    return {"tables": tables, "files": a["files"] + b["files"]}


def _faults(case: dict, check: dict, probe: dict, quiet, may_reach=()) -> list:
    """A request that is made to fail at each of its writes, and to be cut off before each write, each commit and
    the answer: afterwards everything it does is there or nothing is, and the next ordinary request works."""
    sweep = probe["sweep"]
    plain = sweep.get("plain") or []
    if not plain or plain[-1].get("not_run") or _status(plain[-1]) is None or _status(plain[-1]) >= 400:
        why = plain[-1].get("not_run") if plain and plain[-1].get("not_run") else \
            f"the request did not work without a failure (status {_status(plain[-1]) if plain else None})"
        return [_outcome(case, check, "inconclusive" if plain else "not-run", why=str(why)[:300])]
    whole = _counts(plain[-1], quiet)
    nothing = {"tables": {}, "files": 0}
    alone = _counts(sweep["then_alone"][-1], quiet) if sweep.get("then_alone") else None
    out = []
    for run in sweep.get("runs") or []:
        fault, steps = run["fault"], run.get("steps") or []
        name = "the app is cut off before the answer leaves" if fault["on"] == "answer" else \
            f"the database fails at {fault['on']} {fault['at']}" if fault["kind"] == "error" else \
            f"the app is cut off before {fault['on']} {fault['at']}"
        this = dict(case, case=name)
        if not steps or steps[0].get("not_run"):
            out.append(_outcome(this, check, "not-run", why=str((steps[0] if steps else {}).get("not_run", "not run"))[:300]))
            continue
        codes = _everywhere(steps, may_reach)
        after = _counts(steps[0], quiet)
        if after not in (nothing, whole):
            codes.append("partial")
        if len(steps) > 1 and alone is not None:        # then somebody else's ordinary request, on other rows
            st = _status(steps[-1])
            if st is None or st >= 500:
                codes.append("stuck")
            elif _counts(steps[-1], quiet) != _sum(after, alone):
                codes.append("carried-over")            # more of the failed request was saved with theirs
        codes = list(dict.fromkeys(codes))
        out.append(_outcome(this, check, "broken" if codes else "held", codes, saw=_saw(steps, quiet)))
    return out


# ------------------------------------------------------------------------------------------------ the run
def plan_sha256(plan: dict) -> str:
    """The SHA-256 a checked plan is known by, in the record of its run and in the release decision."""
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def summary(outcomes: list) -> dict:
    count = {"held": 0, "broken": 0, "inconclusive": 0, "not-run": 0}
    for o in outcomes:
        count[o["outcome"]] += 1
    return count


def run(repo: Path, out: Path | None = None, log=print, timeout: float = sandbox.WALL_CLOCK, cancel=None,
        plan: dict | None = None) -> dict:
    """Run the project's behaviour plan in the sandbox and judge it. Returns the record (`ran`, `why_not`,
    `summary`, `outcomes`, and `of`: what was run) and, with `out` (a folder that is there), writes it as
    `behaviour.json`. Never raises for what the project or its app does, nor when the sandbox cannot be set up
    (the app is then not started and `why_not` says so); PlanError for a plan that cannot be used."""
    repo = Path(repo).resolve()
    plan = check(plan) if plan is not None else load(repo)
    git = gitfacts.info(repo)
    record: dict = {"version": 1, "from": "running the project's code in Lantern's test sandbox, with no network",
                    "of": {"plan_sha256": None, "commit": git.get("commit"), "dirty": git.get("dirty"),
                           "lantern": __version__, "python": platform.python_version(), "system": platform.system()},
                    "ran": False, "why_not": None, "summary": summary([]), "outcomes": []}
    if plan is None:
        record["why_not"] = f"the project has no {PLAN_NAME}"
        record["no_plan"] = True
    else:
        record["of"]["plan_sha256"] = plan_sha256(plan)
        # the code the app is started from, as the release decision names it (`release.code_digest`), taken before
        # the run: a record counts only for exactly this code
        record["of"]["code_sha256"] = release.code_digest(repo, leave_out=out)["sha256"]
        inside, cases = scene(plan)
        log(f"behave: {len(cases)} cases of {len(plan['checks'])} checks, in the sandbox")
        try:
            res = sandbox.run_inside(repo, "lantern._behave_inside", inside, log=log, timeout=timeout, cancel=cancel)
        except sandbox.Unavailable as e:
            res = {"unavailable": str(e)[:300]}
        observed = res.get("observed") or {}
        seed = observed.get("seed") or {}
        if "unavailable" in res:
            record["why_not"] = f"the sandbox the app runs in could not be set up, so the app was not started ({res['unavailable']})"
        elif not observed:
            record["why_not"] = "the run in the sandbox left no record" + (" (stopped at the time limit)" if res.get("timed_out") else "")
        elif not seed.get("ok"):
            at = seed.get("failed_at")
            step = (seed.get("steps") or [{}])[at] if isinstance(at, int) and at < len(seed.get("steps") or []) else {}
            record["why_not"] = (f"the plan's set-up failed at step {at + 1 if isinstance(at, int) else '?'}"
                                 + (f": {step['not_run']}" if step.get("not_run") else f" (status {step.get('status')})"))
        else:
            record["ran"] = True
            record["outcomes"] = judge(plan, cases, observed)
            record["summary"] = summary(record["outcomes"])
            record["seconds"] = observed.get("seconds")
            record["app_starts"] = observed.get("workers_started")
        if res.get("not_ended"):
            record["not_ended"] = res["not_ended"]
        log("behave: " + (", ".join(f"{n} {word}" for word, n in record["summary"].items()) if record["ran"]
                          else "not run: " + str(record["why_not"])))
    # This computer's seal (seal.py): the release decision counts a record only when it carries it, because the
    # results folder usually lies in the project, and a project can bring a record of its own.
    made = seal.sign(record)
    if made is None:
        log("behave: this record carries no seal (LANTERN_HOME cannot be written), so a release decision will not count it")
    else:
        record["seal"] = made
    if out is not None:
        results.write(Path(out) / RESULT_NAME, json.dumps(record, indent=2) + "\n")
    return record
