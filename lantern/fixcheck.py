"""The fix contract (roadmap of 2026-11-14, stage 3: the guarded fix loop).

What a change has to show before Lantern calls a finding fixed. A finding stops showing for many reasons that are no
fix: a comment excuses it, an entry is written into the list of accepted risks, the code is moved to a place Lantern
reads differently or not at all, the call is put together at run time, the file is broken so that no scanner reads
it, the route that led to it is taken away, the test that would have failed is deleted. Until this stage the recheck
(`mcp_server.tool_recheck`) and "Fix this for me" (`agents.run_fix`) looked only for the finding's id, and called
several of those "fixed".

`judge(before, after, finding_id)` compares two checks of the project, the one made before the fix and the one made
after it (`load`), and answers for each part of the contract (`ITEMS`) with `held`, `broken` or `not-shown`, and the
facts it read, as sentences. The verdict is `passed` only when every part held, `refused` when one is broken, and
`incomplete` when none is broken and one is not shown (the tests were not run, a list of calls is missing).

Everything is read from the two checks' result files (`diff.load`, `diff.compare`, `calls.json`). One thing is asked
of the disk, and only when the caller names the project's folder: whether a call that is newly read as a library's
names a file of the project in a folder Lantern leaves out. Nothing of the project is run, and nothing here creates,
accepts, closes or re-ranks a finding: the contract only refuses to call one fixed.

`keep(home, repo, finding_id, out)` keeps a check as the one a later fix is judged against (under LANTERN_HOME and
so outside the project a coding agent works in), `kept` reads it back and `forget` removes it. `before(home, repo,
out, finding)` is the one place that says which check a fix is compared with: the one kept for that finding (when a
fix brief was asked for, or when the fix was first checked), else the project's last check, which it then keeps. A
fix made in several steps, with a check after each, is so compared with the code as it was before the first step,
and a "fix" that was refused cannot be made to pass by checking it a second time.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from pathlib import Path

from . import diff, manifest, results

SCHEMA = 1
ITEMS = ("gone", "no-suppression", "still-read", "links", "calls", "nothing-new", "tests")
HELD, BROKEN, NOT_SHOWN = "held", "broken", "not-shown"
PASSED, REFUSED, INCOMPLETE = "passed", "refused", "incomplete"
NEED = {
    "gone": "The finding is gone: its rule is no longer found on that code, in that file or at a place the code was "
            "moved to.",
    "no-suppression": "Nothing was hushed: no new `# nosec` comment and no new entry in the list of accepted risks "
                      "came with the fix.",
    "still-read": "Lantern still reads what it read before: every scanner that finished before finished again, and "
                  "no code was put where Lantern does not read it.",
    "links": "Every door of the app is still there under its address, and every request of a page still finds the "
             "route that answered it.",
    "calls": "Every call Lantern could follow before can still be followed: none was put together at run time or "
             "sent into code Lantern does not read.",
    "nothing-new": "Nothing got worse elsewhere: no new finding ranked medium or higher, no finding reached or "
                   "ranked higher than before, no login check weaker.",
    "tests": "The project's tests are all still there, and they were run on the fixed code and passed.",
}
MOST_FACTS = 12         # sentences one part carries; the rest are counted
MOST_LOOKED = 200       # calls newly read as a library's that are looked for on the disk
MOST_PARTS = 12         # parts of a dotted name that is tried as a path
# a call that is unresolved for one of these reasons cannot be followed by design: one more of them than before
# breaks the part; one more for any other reason leaves it not shown (Lantern cannot say what the call runs)
OPAQUE = {"computed": "a function chosen at run time, which Lantern cannot follow",
          "dynamic-require": "code loaded by a path built at run time, which Lantern cannot follow",
          "missing-module": "something from a file the code imports that Lantern cannot find in the project"}
DIFFERENT_NAMES = ("The two checks name their findings in different ways (they were made by different versions of "
                   "Lantern), so no finding of one can be looked for in the other.")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
SCAN_ORDER = {"ok": 0, "partial": 1, "failed": 2}
BRIEFS = "fix-briefs"    # under LANTERN_HOME: <project>/<finding>/ holds the check kept for one fix
KEPT = diff.FILES + ("calls.json", "run.json")
MOST_KEPT = 40          # checks kept for one project; the oldest go first
OWN = "Lantern's own folder"


def contract() -> list[dict]:
    """The parts of the contract in order, each with the sentence that says what it needs."""
    return [{"id": i, "need": NEED[i]} for i in ITEMS]


def load(out, label: str | None = None) -> dict:
    """The results of one check as `judge` takes them: what `diff.load` reads (strictly: a damaged file is an error),
    and the list of calls where the check wrote one (`calls`: None for results an older Lantern made)."""
    side = diff.load(out, label)
    said = manifest.parse_json(results.plain(Path(out) / "calls.json")[0] or "")
    side["calls"] = said if isinstance(said, dict) and isinstance(said.get("sites"), list) else None
    return side


# ------------------------------------------------------------------------------------------------- small helpers
def _short(value, most: int = 160) -> str:
    """A value of the results as one printable line of a sentence."""
    text = "".join(c if c.isprintable() else " " for c in str(value if value is not None else ""))
    text = " ".join(text.split())
    return text if len(text) <= most else text[:most - 1] + "…"


def _at(f: dict) -> str:
    file, line = f.get("file"), f.get("line")
    if not isinstance(file, str) or not file:
        return "a place with no file"
    return f"{_short(file)}:{line}" if isinstance(line, int) else _short(file)


def _named(f: dict) -> str:
    return f"{_short(f.get('rule') or 'a finding', 60)} at {_at(f)}"


def _all(side: dict) -> list[dict]:
    """Every finding of one check, test code and accepted ones included."""
    return [f for f in manifest.tables(side["security"].get("findings")) if isinstance(f.get("id"), str)]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _kept(facts: list[str]) -> list[str]:
    if len(facts) <= MOST_FACTS:
        return facts
    return facts[:MOST_FACTS] + [f"And {len(facts) - MOST_FACTS} more of the kind."]


# ------------------------------------------------------------------------------------------------ 1. it is gone
def _gone(target: dict, before: dict, after: dict, alike: bool) -> tuple[str, list[str]]:
    """A finding's id is made from its line's text, so an edited line carries its finding under another id. Gone is
    said only where the id is gone, the rule does not show under a new id in the same file, and it does not show
    under a new id anywhere else either (test code included: code moved, not fixed)."""
    if not alike:
        return NOT_SHOWN, [DIFFERENT_NAMES]
    rule, file = target.get("rule"), target.get("file")
    known = {f["id"] for f in _all(before)}
    facts = []
    for f in _all(after):
        if f["id"] == target["id"]:
            facts.append(f"The finding is still there: {_named(f)}"
                         + (", accepted now and not fixed." if diff._accepted(f) else "."))
        elif f["id"] in known or f.get("rule") != rule:
            continue
        elif f.get("file") == file:
            facts.append(f"{_short(rule, 60)} shows again in {_at(f)}: the line was changed and the same problem is "
                         "still found there.")
        else:
            facts.append(f"{_short(rule, 60)} is now found at {_at(f)}"
                         + (" (test code)" if f.get("in_tests") else "")
                         + ", where it was not before: the code was moved, not fixed.")
    if facts:
        return BROKEN, facts
    tool = target.get("tool")
    state = _scanners(after).get(tool) if isinstance(tool, str) else None
    if state is not None and _scan_state(state) != "ok" and _scan_state(_scanners(before).get(tool) or {}) == "ok":
        return NOT_SHOWN, [f"{_named(target)} does not show any more, but {_short(tool, 40)}, which found it, did "
                           "not read everything this time. That it does not show proves nothing."]
    return HELD, [f"{_named(target)} is no longer found, there or at any place it was not before."]


# -------------------------------------------------------------------------------------------- 2. nothing hushed
def _hushed(f: dict) -> tuple | None:
    """How a finding is spoken for, if it is: (accepted or not, the state of a `# nosec` comment on its line)."""
    ns = f.get("nosec") if isinstance(f.get("nosec"), dict) else None
    if not diff._accepted(f) and ns is None:
        return None
    return diff._accepted(f), (ns or {}).get("state")


def _hush_words(f: dict) -> str:
    ns = f.get("nosec") if isinstance(f.get("nosec"), dict) else None
    acc = f.get("accepted") if isinstance(f.get("accepted"), dict) else {}
    if ns is not None:
        reason = _short(ns.get("reason") or "", 160)
        if ns.get("state") == "accepted":
            return (f"A `# nosec` comment now answers for {_named(f)} (its reason: “{reason}”). A comment accepts a "
                    "risk; it fixes nothing.")
        if ns.get("state") == "overruled":
            return (f"A `# nosec` comment was put on {_named(f)}, a line request data reaches: Lantern does not take "
                    "it there, and it fixes nothing.")
        return f"A `# nosec` comment with no reason was put on {_named(f)}: it accepts nothing and fixes nothing."
    reason = _short(acc.get("reason") or "", 160)
    return (f"{_named(f)} is now on the project's list of accepted risks (lantern-accepted.json"
            + (f"; its reason: “{reason}”" if reason else "") + "). An entry there is a person's decision "
            "(`lantern accept`) and nothing a fix may write.")


def _no_suppression(before: dict, after: dict, alike: bool) -> tuple[str, list[str]]:
    if not alike:
        return NOT_SHOWN, [DIFFERENT_NAMES]
    was = {f["id"]: f for f in _all(before)}
    place = lambda f: (f.get("rule"), f.get("file"))        # noqa: E731
    had = Counter(place(f) for f in was.values() if _hushed(f))
    now = [f for f in _all(after) if _hushed(f)]
    have = Counter(place(f) for f in now)
    facts = []
    for f in now:
        old = was.get(f["id"])
        if old is not None and _hushed(old) == _hushed(f):
            continue                    # spoken for before the fix, in the same way
        if old is None and have[place(f)] <= had[place(f)]:
            continue                    # an edited line that carried its comment before
        facts.append(_hush_words(f))
    if facts:
        return BROKEN, facts
    return HELD, ["No finding is accepted or commented away that was not before."]


# ----------------------------------------------------------------------------------- 3. what was read is read
def _scanners(side: dict) -> dict[str, dict]:
    return {t["tool"]: t for t in manifest.tables(side["security"].get("tools")) if isinstance(t.get("tool"), str)}


def _scan_state(t: dict) -> str:
    state = t.get("state")
    if not isinstance(state, str):
        state = re.split(r"[:( ]", manifest.text(t.get("status")).strip(), maxsplit=1)[0]
    return state


def _scan_gaps(t: dict) -> int:
    """How much one scanner's record says it did not read or could not look up."""
    n = len(manifest.rows(t.get("errors")))
    for key in ("not_read", "unpinned", "unlocked"):
        v = t.get(key)
        n += v if isinstance(v, int) and not isinstance(v, bool) else len(v) if isinstance(v, list) else 0
    return n


def _scan_said(t: dict) -> str:
    said = _short(t.get("status") or t.get("why") or _scan_state(t), 120)
    errors = [_short(e, 160) for e in manifest.texts(t.get("errors"))[:3]]
    return f"“{said}”" + (f" ({'; '.join(errors)})" if errors else "")


def _still_read(before: dict, after: dict) -> tuple[str, list[str]]:
    was, now = _scanners(before), _scanners(after)
    broken, unknown = [], []
    for name in sorted(was):
        old, new = was[name], now.get(name)
        a = _scan_state(old)
        if a not in SCAN_ORDER:
            continue                    # it did not run before either: nothing to hold it to
        if new is None:
            unknown.append(f"{_short(name, 40)} ran in the check before the fix and is not in the check after it.")
            continue
        b = _scan_state(new)
        if b not in SCAN_ORDER:
            if a == "ok":
                unknown.append(f"{_short(name, 40)} finished before the fix and did not run after it: "
                               f"{_scan_said(new)}.")
        elif SCAN_ORDER[b] > SCAN_ORDER[a]:
            broken.append(f"{_short(name, 40)} read everything it was given before the fix and now says "
                          f"{_scan_said(new)}.")
        elif b != "ok" and _scan_gaps(new) > _scan_gaps(old):
            broken.append(f"{_short(name, 40)} left out more than before the fix: {_scan_said(new)}.")
    nr0 = manifest.table(before["security"].get("not_read"))
    nr1 = manifest.table(after["security"].get("not_read"))
    r0, r1 = manifest.table(nr0.get("renamed")), manifest.table(nr1.get("renamed"))
    n0, n1 = _count(r0.get("files")), _count(r1.get("files"))
    if n1 > n0:
        new = [x for x in manifest.texts(r1.get("examples")) if x not in manifest.texts(r0.get("examples"))]
        broken.append(f"{_plural(n1 - n0, 'more file')} of code kept under another name, which Lantern's map does "
                      f"not read{_examples(new)}.")
    c0, c1 = manifest.table(nr0.get("copied")), manifest.table(nr1.get("copied"))
    n0 = _count(c0.get("unnamed")) + _count(c0.get("copies"))
    n1 = _count(c1.get("unnamed")) + _count(c1.get("copies"))
    if n1 > n0:
        new = [x for key in ("unnamed_examples", "named") for x in manifest.texts(c1.get(key))
               if x not in manifest.texts(c0.get(key))]
        broken.append(f"{_plural(n1 - n0, 'more file')} of copied code under a folder Lantern leaves out"
                      f"{_examples(new)}.")
    if broken:
        return BROKEN, broken + unknown
    if unknown:
        return NOT_SHOWN, unknown
    return HELD, ["Every scanner that finished before the fix finished after it, and no more code is kept where "
                  "Lantern does not read it."]


def _count(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0


def _examples(names: list[str]) -> str:
    return ": " + ", ".join(_short(x, 120) for x in names[:3]) if names else ""


# ------------------------------------------------------------------------------------------ 4. doors and links
def _door(d: dict, key: str = "words", detail: str = "detail") -> str:
    return _short(d.get(key) or d.get(detail) or "a door", 120)


def _where(d: dict) -> str:
    return f" ({_at(d)})" if isinstance(d.get("file"), str) and d.get("file") else ""


def _links(receipt: dict) -> tuple[str, list[str]]:
    doors, links, more = receipt["doors"], receipt["links"], receipt.get("more") or {}
    broken, notes = [], []
    for d in doors["removed"]:
        broken.append(f"The door {_door(d)}{_where(d)} is gone.")
    for d in doors["moved"]:
        broken.append(f"The door {_door(d, 'before_words', 'before')} is now {_door(d, 'after_words', 'after')}"
                      f"{_where(d)}: whoever asks the old address gets no answer.")
    for row in links["broken"]:
        by = ", ".join(_door(r) for r in row.get("answered_by") or []) or "a route"
        broken.append(f"The request {_short(row.get('words'), 120)}{_where(row)} was answered by {by} before the "
                      "fix and finds no route now.")
    for row in links["unanswered"]:
        notes.append(f"A request that came with the fix finds no route: {_short(row.get('words'), 120)}"
                     f"{_where(row)}.")
    cut = sum(v for k, v in more.items() if k in ("doors.removed", "links.broken") and isinstance(v, int))
    if cut and broken:
        broken.append(f"And {cut} more of the kind.")
    if broken:
        return BROKEN, broken + notes
    return HELD, ["Every door is where it was, and every request that found a route finds it still."] + notes


# ----------------------------------------------------------------------------------------------------- 5. calls
def _sites(side: dict) -> list[dict]:
    return [s for s in manifest.tables((side.get("calls") or {}).get("sites"))
            if not s.get("test") and isinstance(s.get("file"), str)]


def _own_file(repo: Path, name: str, caller_file: str, on_map: set) -> str | None:
    """The file of the project a dotted name leads to when it is read as a path, where that file is none Lantern's
    map holds: `build.helpers.backup` -> `build/helpers.py`. Tried from the project's top and from each folder
    above the calling file (a project whose packages lie under `src/`)."""
    from .python_frontend import inside_repo
    parts = name.split(".")
    if len(parts) > MOST_PARTS or not all(NAME.fullmatch(p) for p in parts):
        return None
    above = Path(caller_file).parent.parts
    roots = [""] + ["/".join(above[:i]) + "/" for i in range(1, len(above) + 1)]
    for i in range(len(parts), 0, -1):
        for root in roots:
            for cand in (root + "/".join(parts[:i]) + ".py", root + "/".join(parts[:i]) + "/__init__.py"):
                if cand not in on_map and inside_repo(repo / cand, repo):
                    return cand
    return None


def _calls(before: dict, after: dict, hn: dict, repo) -> tuple[str, list[str]]:
    missing = [w for w, side in (("before", before), ("after", after)) if side.get("calls") is None]
    if missing:
        return NOT_SHOWN, [f"The check made {' and the one made '.join(missing)} the fix holds no list of calls "
                           "(calls.json), so what became of each call is not shown."]
    was, now = _sites(before), _sites(after)
    stuck = lambda sites: [s for s in sites if s.get("outcome") == "unresolved"]        # noqa: E731
    had = Counter((s["file"], s.get("reason")) for s in stuck(was))
    have = Counter((s["file"], s.get("reason")) for s in stuck(now))
    seen = Counter((s["file"], s.get("reason"), s.get("caller"), s.get("callee")) for s in stuck(was))
    broken, unknown = [], []
    for (file, reason), n in sorted(have.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        if n <= had[(file, reason)]:
            continue
        fresh = []
        for s in stuck(now):
            if s["file"] != file or s.get("reason") != reason:
                continue
            key = (file, reason, s.get("caller"), s.get("callee"))
            if seen[key] > 0:
                seen[key] -= 1
            else:
                fresh.append(s)
        one = (fresh or [s for s in stuck(now) if s["file"] == file and s.get("reason") == reason])[0]
        at = f"{_short(file)}:{one.get('line')}" if isinstance(one.get("line"), int) else _short(file)
        count = f"{_plural(n, 'such call')} in this file now, {had[(file, reason)]} before the fix"
        if reason in OPAQUE:
            broken.append(f"{at} calls `{_short(one.get('callee'), 100)}`: {OPAQUE[reason]} ({count}).")
        else:
            unknown.append(f"{at} calls `{_short(one.get('callee'), 100)}`, which Lantern could not follow"
                           + (f": {_short(one.get('why'), 200)}" if one.get("why") else "")
                           + f" ({count}). What such a call runs is not on the map.")
    # a call newly read as a library's that is the project's own code in a folder Lantern leaves out
    if repo is not None:
        outside = lambda sites: [(s, t) for s in sites if s.get("outcome") == "external"      # noqa: E731
                                 for t in manifest.texts(s.get("to")) if t.startswith("ext:")]
        known = {t for _, t in outside(was)}
        on_map = {n.get("file") for n in hn.values() if isinstance(n.get("file"), str)}
        told = set()
        for s, t in [(s, t) for s, t in outside(now) if t not in known][:MOST_LOOKED]:
            rel = _own_file(Path(repo), t[4:], s["file"], on_map)
            if rel and t not in told:
                told.add(t)
                at = f"{_short(s['file'])}:{s.get('line')}" if isinstance(s.get("line"), int) else _short(s["file"])
                broken.append(f"{at} calls `{_short(s.get('callee'), 100)}`, which Lantern takes for a library's "
                              f"({_short(t[4:], 120)}). It is this project's own {_short(rel)}, in a folder Lantern "
                              "does not read.")
    if broken:
        return BROKEN, broken + unknown
    if unknown:
        return NOT_SHOWN, unknown
    return HELD, ["No more calls than before are ones Lantern cannot follow, and none leads into code of the project "
                  "that Lantern does not read."]


# ----------------------------------------------------------------------------------------- 6. nothing got worse
def _nothing_new(receipt: dict, alike: bool) -> tuple[str, list[str]]:
    f, doors, more = receipt["findings"], receipt["doors"], receipt.get("more") or {}
    broken, notes, unknown = [], [], []
    if not alike:
        unknown.append(DIFFERENT_NAMES)
    for x in f["new"]:
        title = f" ({_short(x.get('title'), 100)})" if x.get("title") else ""
        if x.get("rank") == "low":
            notes.append(f"Came with the fix and breaks nothing: {_named(x)}, ranked low{title}.")
        else:
            broken.append(f"A new finding ranked {_short(x.get('rank') or 'higher than low', 20)}: {_named(x)}{title}.")
    for x in f["now_reached"]:
        broken.append(f"{_named(x)} is reached by a door now and was not before the fix (ranked "
                      f"{_short(x.get('rank'), 20)}).")
    for x in f["rank_changed"]:
        if x.get("raised"):
            broken.append(f"{_named(x)} is ranked {_short(x.get('rank'), 20)} now, "
                          f"{_short(x.get('rank_before'), 20)} before the fix.")
    for x in f["reopened"]:
        broken.append(f"{_named(x)} was accepted before the fix and is open again.")
    for d in doors["login_changed"]:
        if d.get("weaker"):
            broken.append(f"{_door(d)}{_where(d)}: the login check on this door is weaker ("
                          f"{diff._login_words(d.get('before'))} before the fix, {diff._login_words(d.get('after'))} "
                          "now).")
    for d in doors["added"]:
        if diff._open_door(d):
            notes.append(f"A door that came with the fix changes data and shows no login check: {_door(d)}{_where(d)}.")
    rel = receipt.get("release") or {}
    was, now = (rel.get("before") or {}).get("decision"), (rel.get("after") or {}).get("decision")
    if now == "Blocked" and was not in (None, "Blocked"):
        broken.append(f"The release decision was {_short(was, 20)} before the fix and is Blocked now"
                      + (f" ({_short('; '.join(manifest.texts(rel.get('why'))), 200)})." if rel.get("why") else "."))
    cut = sum(v for k, v in more.items() if k.startswith("findings.") and isinstance(v, int))
    if cut:
        (broken if broken else unknown).append(f"{_plural(cut, 'more finding')} changed than one receipt lists.")
    if broken:
        return BROKEN, broken + notes
    if unknown:
        return NOT_SHOWN, unknown + notes
    return HELD, ["No new finding ranked medium or higher, none reached or ranked higher, no login check weaker."] + notes


# ------------------------------------------------------------------------------------------------- 7. the tests
def _test_nodes(nodes: dict) -> dict[str, dict]:
    return {i: n for i, n in nodes.items() if isinstance(n.get("entry"), dict) and n["entry"].get("kind") == "test"}


def _test_name(n: dict) -> str:
    return _short((n.get("entry") or {}).get("detail") or n.get("name") or n.get("id"), 100)


def _tests(bn: dict, hn: dict, tests) -> tuple[str, list[str]]:
    """The tests are read from the two maps (which are there, by name); whether they pass is read from a test run's
    record of the shape `run.json` keeps under `trace`, judged the way the release decision judges it
    (`release._tests`). Lantern starts no test here: with no record the part is not shown."""
    from . import release
    was, now = _test_nodes(bn), _test_nodes(hn)
    had = Counter(n.get("file") for n in was.values())
    have = Counter(n.get("file") for n in now.values())
    lost: dict = {}
    for i, n in was.items():
        if i not in now:
            lost.setdefault(n.get("file"), []).append(_test_name(n))
    broken, unknown = [], []
    for file in sorted(lost, key=str):
        names = ", ".join(sorted(lost[file])[:5]) + (f" and {len(lost[file]) - 5} more" if len(lost[file]) > 5 else "")
        if have[file] == 0:
            broken.append(f"The test file {_short(file)} is gone, with {_plural(had[file], 'test')}: {names}.")
        elif have[file] < had[file]:
            broken.append(f"{_short(file)} holds {_plural(have[file], 'test')} now, {had[file]} before the fix: "
                          f"{names} {'is' if len(lost[file]) == 1 else 'are'} gone.")
        else:
            unknown.append(f"{_short(file)}: {names} {'is' if len(lost[file]) == 1 else 'are'} gone and as many "
                           "tests came in their place. Whether a new test asks what the old one asked is not "
                           "something Lantern can read.")
    ran = release._tests(bool(was or now), {"trace": tests} if isinstance(tests, dict) else {})
    said = _short(ran.get("why"), 400)
    if ran.get("state") == "failed":
        broken.append(said)
    elif ran.get("state") != "passed":
        unknown.append(said)
    if broken:
        return BROKEN, broken + unknown
    if unknown:
        return NOT_SHOWN, unknown
    return HELD, [f"Every test that was there before the fix is there ({_plural(len(now), 'test')} now). {said}"]


# --------------------------------------------------------------------------------------------------- the verdict
def judge(before: dict, after: dict, finding_id: str, repo=None, tests=None) -> dict:
    """The contract, part by part, for the fix of one finding. `before` and `after`: the check made before the fix
    and the one made after it (`load`). `finding_id`: a finding that was open, outside test code, in `before`
    (ValueError otherwise: only an open finding can be fixed). `repo`: the folder the `after` check was made of,
    for the one question asked of the disk. `tests`: the record of a test run on the fixed code (`run.json`
    `trace`), or None when no test was run."""
    target = diff._open(before).get(finding_id) if isinstance(finding_id, str) else None
    if target is None or diff._accepted(target):
        raise ValueError(f"{_short(finding_id, 80)} is not an open finding of the check made before the fix"
                         + (" (it was accepted there)." if target is not None else "."))
    alike = diff._named_alike(before, after)
    receipt = diff.compare(before, after)
    bn, hn = diff._nodes(before), diff._nodes(after)
    got = {"gone": _gone(target, before, after, alike),
           "no-suppression": _no_suppression(before, after, alike),
           "still-read": _still_read(before, after),
           "links": _links(receipt),
           "calls": _calls(before, after, hn, repo),
           "nothing-new": _nothing_new(receipt, alike),
           "tests": _tests(bn, hn, tests)}
    items = [{"id": i, "state": got[i][0], "need": NEED[i], "facts": _kept(got[i][1])} for i in ITEMS]
    bad = [i["id"] for i in items if i["state"] == BROKEN]
    open_ = [i["id"] for i in items if i["state"] == NOT_SHOWN]
    if bad:
        verdict = REFUSED
        words = (f"The fix is refused: {_plural(len(bad), 'part')} of the contract's {len(ITEMS)} "
                 f"{'is' if len(bad) == 1 else 'are'} broken ({', '.join(bad)}).")
    elif open_:
        verdict = INCOMPLETE
        words = (f"Nothing is broken, but {_plural(len(open_), 'part')} of the contract's {len(ITEMS)} "
                 f"{'is' if len(open_) == 1 else 'are'} not shown ({', '.join(open_)}), so the fix has not passed yet.")
    else:
        verdict = PASSED
        words = f"The fix passed: all {len(ITEMS)} parts of the contract held."
    return {"schema": SCHEMA, "verdict": verdict, "words": words, "finding": diff._brief(target), "items": items,
            "broken": bad, "not_shown": open_}


def text(result: dict) -> str:
    """The result as plain text: the verdict first, then every part with its state and its facts, and for a part
    that did not hold the sentence that says what it needs."""
    finding = result.get("finding") or {}
    lines = [f"{str(result.get('verdict') or '').capitalize()}: the fix of {_named(finding)}", result.get("words") or "", ""]
    for item in result.get("items") or []:
        facts = list(item.get("facts") or []) or [item["need"]]
        lines.append(f"[{item['state']}] {item['id']}: {facts[0]}")
        lines += [f"    {fact}" for fact in facts[1:]]
        if item["state"] != HELD:
            lines.append(f"    What this part needs: {item['need']}")
    return "\n".join(lines).rstrip() + "\n"


# -------------------------------------------------------------------------------- the check a fix is judged against
def _kept_dir(home, repo, finding_id) -> Path:
    def short(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:20]
    return Path(home) / BRIEFS / short(os.path.realpath(repo)) / short(str(finding_id))


def opened(side: dict, finding: str) -> dict | None:
    """The open finding outside test code that `finding` names in one check: by its id, or as the only one whose id
    begins with it. None when there is none (an accepted finding is a person's decision and no finding to fix)."""
    rows = {k: f for k, f in diff._open(side).items() if not diff._accepted(f)}
    if finding in rows:
        return rows[finding]
    hits = [f for k, f in rows.items() if finding and k.startswith(finding)]
    return hits[0] if len(hits) == 1 else None


def before(home, repo, out, finding: str, keep_first: bool = True) -> tuple[dict, dict, dict | None] | None:
    """The check the fix of `finding` is compared with, the finding in it, and the note of the kept check (None when
    the project's last check is used as it is). A check kept for this finding wins; with none, the last check in
    `out` is the one, and with `keep_first` it is kept before anything analyzes the project again. None when
    `finding` names no open finding there. `diff.NotResults` when `out` holds no check."""
    finding = str(finding or "").strip()
    held = kept(home, repo, finding)
    if held is None:
        was = load(out, "before the fix")
        target = opened(was, finding)
        if target is None:
            return None
        held = kept(home, repo, target["id"])       # asked for by the beginning of an id, kept under the whole one
        if held is None:
            return was, target, keep(home, repo, target["id"], out, how="first-check") if keep_first else None
    was, note = held
    target = opened(was, note["finding"])
    return (was, target, note) if target is not None else None


def since(note: dict | None) -> str:
    """Which check a fix was compared with, in words."""
    if note is None:
        return "the project's last check"
    when = _short(note.get("kept_at"), 40)
    if note.get("how") == "first-check":
        return f"the check from before the fix, kept when the fix was first checked ({when})"
    return f"the check kept when the fix brief was asked for ({when})"


def keep(home, repo, finding_id: str, out, how: str = "brief") -> dict:
    """Keep the check in `out` as the one the fix of this finding is judged against: copies of its result files in
    a folder of Lantern's own under `home`, read and written the way every result file is (`results.plain`,
    `results.write`). A check kept earlier for the same finding is replaced. `how`: `brief` (a fix brief was asked
    for) or `first-check` (a fix was checked with none kept). `diff.NotResults` when `out` holds no whole check."""
    from . import removal
    d = _kept_dir(home, repo, finding_id)
    texts = {}
    for name in KEPT:
        got, why = results.plain(Path(out) / name)
        if got is None and name in diff.FILES:
            raise diff.NotResults(f"{out} does not hold the results of a check: {name} is "
                                  f"{'not a plain file Lantern reads' if why else 'missing'}. Run `lantern analyze` "
                                  "first.")
        texts[name] = got
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, got in texts.items():
        if got is None:
            removal.remove(d / name)        # an older check's file must not stand in for one this check has not
        else:
            results.write(d / name, got, where=OWN)
    note = {"schema": SCHEMA, "finding": finding_id, "kept_at": time.strftime("%Y-%m-%d %H:%M"), "how": how,
            "files": [n for n, got in texts.items() if got is not None]}
    results.write(d / "brief.json", json.dumps(note), where=OWN)
    _cap(d.parent, d)
    return note


def _cap(project: Path, newest: Path) -> None:
    from . import removal
    try:
        rows = [(e.stat(follow_symlinks=False).st_mtime, e.path) for e in os.scandir(project)
                if e.is_dir(follow_symlinks=False) and e.path != str(newest)]
    except OSError:
        return
    for _, path in sorted(rows)[:max(0, len(rows) + 1 - MOST_KEPT)]:
        removal.remove(path)


def kept(home, repo, finding_id: str) -> tuple[dict, dict] | None:
    """The check kept for the fix of this finding, as `judge` takes it, with its note (`kept_at`); None when none
    is kept or what is there is no whole check."""
    d = _kept_dir(home, repo, finding_id)
    note = manifest.table(manifest.parse_json(results.plain(d / "brief.json")[0] or ""))
    if note.get("finding") != finding_id:
        return None
    try:
        return load(d, "before the fix"), note
    except diff.NotResults:
        return None


def forget(home, repo, finding_id: str) -> None:
    from . import removal
    removal.remove(_kept_dir(home, repo, finding_id))
