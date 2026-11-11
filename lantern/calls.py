"""Call-site inventory (2026-11-09 directive, stage 3): every call written in Python or JavaScript/TypeScript code,
once, with what Lantern knows about its target and, when it knows nothing, why.

`Graph.call_sites()` counts edge lines: an edge with three call lines counts three, one call with three possible
targets also counts three, and two calls on one line that reach the same function count once. It is kept unchanged,
so results before and after a change are compared on the same count. This inventory is the per-place count beside it:

* one record per call, identified by its file and the line and column (bytes, counted from 1) of the call's opening
  parenthesis, or of the callee for a call written without one (a decorator, a JSX element), so two calls on one line
  are two records and one call with several possible targets is one record that lists them all;
* one outcome per record, so the outcomes add up to the calls found: `resolved`, `likely`, `possible`, `name-only`,
  `external`, `builtin` or `unresolved`; an unresolved record carries a `reason` code and a sentence (`REASONS`);
* records come in three groups. `written`: calls written in the code (the main count). `handed`: functions handed to
  code that calls them (FastAPI `Depends(fn)`, Express route handlers and middleware, callbacks passed by name), which
  are counted only where the code says they are functions. `implicit`: calls the language makes on the code's behalf
  (context managers, properties, decorator closures), counted only when they reach repo code;
* code in test files is counted apart (`in_tests`), so it cannot hide in the totals.

The inventory describes the code as written: runtime tracing adds observed edges to the map, not to these records.
Languages other than Python and JavaScript/TypeScript keep only the edge-line count for now; `not_inventoried`
names them, so a total never looks complete when it is not.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import results

INVENTORIED = ("python", "typescript/javascript")
GROUPS = ("written", "handed", "implicit")
OUTCOMES = ("resolved", "likely", "possible", "name-only", "external", "builtin", "unresolved")
NAME_ONLY_VIA = ("unique-method-name", "method-name")
MAX_SITES = 250_000   # calls.json keeps at most this many records; the summary always counts them all

OUTCOME_WORDS = {
    "resolved": "linked to one function in the repo",
    "likely": "linked to one function in the repo through a type Lantern worked out (not one written at the call)",
    "possible": "one of several functions in the repo; which one runs depends on the object at run time",
    "name-only": "guessed from the method name alone, because the object's type is unknown; can be wrong",
    "external": "a library function",
    "builtin": "a built-in of the language, Node or the browser",
    "unresolved": "not traced; the reason says why",
}

REASONS = {
    "parameter": "`{head}` is a parameter whose type Lantern cannot follow (none is written, or one it cannot see into)",
    "callback-parameter": "calls `{head}`, a function passed in as a parameter",
    "local-unknown": "`{head}` holds a value whose type Lantern does not know",
    "call-result": "called on the result of another call whose type Lantern does not know",
    "self-attribute": "`{base}` holds a value whose type Lantern does not know",
    "not-in-class": "neither the class nor a repo class it inherits from defines `{member}`, and it has no other base "
                    "class that could",
    "unknown-base": "the class has a base class Lantern cannot look into (a library class, a library's star import, "
                    "a computed base, or a file it cannot find), so `{member}` may be defined there",
    "this-outside-class": "`this` outside a class method",
    "repo-variable": "`{head}` is a variable in the repo whose value Lantern does not know",
    "missing-member": "`{base}` has no `{member}` that Lantern can find in the repo",
    "missing-module": "`{head}` comes from a file the code imports or requires that Lantern cannot find in the "
                      "repository",
    "missing-export": "`{head}` is imported from a file in the repo that does not export it in a way Lantern can read",
    "not-defined": "`{head}` is not defined in this file or its imports (a global of the environment, a star import "
                   "Lantern cannot read, or code outside the repo)",
    "computed": "the function is chosen at run time (an index, getattr or another computed expression)",
    "dynamic-require": "`{head}` is loaded by require() or import() of a path built at run time",
    "function-member": "`{member}` is a property of a function, not a function Lantern can follow",
    "global-property": "`{member}` is reached through the global object (`{head}`), which any script can add to, "
                       "and Lantern does not know it as one of the browser's or Node's own names",
    "library-or-repo": "`{base}` holds a value from a library or the language itself, but the project has its own "
                       "`{member}` (a method of one of its classes, or a function it puts on an object), so Lantern "
                       "cannot tell which one this call reaches",
    "not-read": "Lantern's reader skipped this call (a gap in the reader, counted so the total stays complete)",
}


def _names(callee: str) -> dict:
    text = re.sub(r"\([^()]*\)", "()", callee or "")
    parts = [p for p in re.split(r"\.(?![^\[]*\])", text) if p]
    head = re.split(r"[.(\[]", text.strip(), maxsplit=1)[0] or text
    member = parts[-1].rstrip("()") if parts else head
    base = ".".join(parts[:-1]) if len(parts) > 1 else head
    return {"head": head[:60], "member": member[:60], "base": base[:80]}


def why(reason: str | None, site: dict) -> str | None:
    """The sentence for a reason code, about this record's callee."""
    if not reason:
        return None
    names = _names(site.get("callee", ""))
    if reason == "self-attribute" and names["base"] in ("self", "this", "cls"):   # self.cb(): the attribute itself
        names["base"] = f"{names['base']}.{names['member']}"
    return REASONS.get(reason, reason).format(**names)


def classify(targets: list[tuple[str, str, str | None]]) -> tuple[str, list[str], str | None, str | None]:
    """[(target id, confidence, via)] -> (outcome, targets, via, confidence). Built-ins are `builtin:<name>` or
    Python's `ext:builtins.<name>`; other `ext:` ids are libraries; everything else is a node in the repo."""
    if not targets:
        return "unresolved", [], None, None
    internal = [t for t in targets if not t[0].startswith(("ext:", "builtin:"))]
    builtin = [t for t in targets if t[0].startswith(("builtin:", "ext:builtins."))]
    if internal:
        pick = internal
        if any(v in NAME_ONLY_VIA for _, _, v in internal):
            outcome = "name-only"
        elif len(internal) > 1 or any(c == "possible" for _, c, _ in internal):
            outcome = "possible"
        elif internal[0][1] == "inferred":
            outcome = "likely"
        else:
            outcome = "resolved"
    elif builtin:
        outcome, pick = "builtin", builtin
    else:
        outcome, pick = "external", targets
    to: list[str] = []
    for t, _, _ in pick:
        t = "builtin:" + t[len("ext:builtins."):] if t.startswith("ext:builtins.") else t
        if t not in to:
            to.append(t)
    conf = "possible" if outcome == "possible" else pick[0][1]
    return outcome, to, pick[0][2], conf


def record(sites: list, *, file: str, line: int, col: int, callee: str, caller: str, lang: str, group: str,
           test: bool, targets=None, reason: str | None = None, via: str | None = None) -> dict:
    """Add one record; `targets` as for classify(). An unresolved record must give a reason."""
    outcome, to, tvia, conf = classify(list(targets or []))
    s = {"at": f"{file}:{line}:{col}", "file": file, "line": line, "col": col,
         "callee": re.sub(r"\s+", " ", callee or "")[:120], "caller": caller, "lang": lang, "group": group,
         "outcome": outcome, "to": to, "via": via or tvia, "confidence": conf,
         "reason": None, "why": None, "test": bool(test)}
    if outcome == "unresolved":
        s["reason"] = reason or "computed"
        s["why"] = why(s["reason"], s)
    sites.append(s)
    return s


def _part(items: list[dict]) -> dict:
    outcomes = {o: 0 for o in OUTCOMES}
    reasons: dict[str, int] = {}
    by_via: dict[str, int] = {}
    lines: dict[tuple, int] = {}
    several = 0
    for s in items:
        outcomes[s["outcome"]] += 1
        if s["reason"]:
            reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
        if s["via"]:
            by_via[s["via"]] = by_via.get(s["via"], 0) + 1
        several += len([t for t in s["to"] if not t.startswith(("ext:", "builtin:"))]) > 1
        k = (s["file"], s["line"])
        lines[k] = lines.get(k, 0) + 1
    return {"total": len(items), "outcomes": outcomes,
            "reasons": dict(sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_via": dict(sorted(by_via.items(), key=lambda kv: (-kv[1], kv[0]))),
            "with_several_targets": several, "lines_with_several_calls": sum(1 for n in lines.values() if n > 1)}


def summarize(sites: list[dict], languages: dict | None = None) -> dict:
    present = list(languages or {})
    out = {"version": 1, "languages": [lang for lang in INVENTORIED if lang in present],
           "not_inventoried": [lang for lang in present if lang not in INVENTORIED]}
    for grp in GROUPS:
        out[grp] = _part([s for s in sites if s["group"] == grp and not s["test"]])
    out["in_tests"] = _part([s for s in sites if s["group"] == "written" and s["test"]])
    return out


def finish(g) -> dict:
    """Deduplicate by place (the first record of a place wins), sort, and put the summary in the graph's meta."""
    seen: set[tuple[str, str]] = set()
    keep = []
    for s in g.sites:
        k = (s["group"], s["at"])
        if k in seen:
            continue
        seen.add(k)
        keep.append(s)
    keep.sort(key=lambda s: (s["file"], s["line"], s["col"], s["group"]))
    g.sites = keep
    g.meta["calls"] = summarize(keep, g.meta.get("languages"))
    return g.meta["calls"]


def write(path: Path, g) -> Path:
    sites = getattr(g, "sites", []) or []
    data = {"version": 1, "summary": g.meta.get("calls") or summarize(sites, g.meta.get("languages")),
            "outcomes": OUTCOME_WORDS, "reasons": REASONS, "sites": sites[:MAX_SITES]}
    if len(sites) > MAX_SITES:
        data["truncated"] = {"kept": MAX_SITES, "total": len(sites)}
    results.write(path, json.dumps(data, indent=0))
    return path


def line_words(c: dict | None) -> str | None:
    """One line for the console: the written calls and what Lantern knows about them."""
    if not c or not c.get("written", {}).get("total"):
        return None
    w = c["written"]
    o = w["outcomes"]
    return (f"{w['total']} call sites ({', '.join(c.get('languages') or [])}): "
            f"{o['resolved'] + o['likely']} into the repo, {o['possible']} with several possible targets, "
            f"{o['name-only']} by method name only, {o['external']} library, {o['builtin']} built-in, "
            f"{o['unresolved']} unresolved")
