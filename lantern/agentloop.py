"""An agent loop with no cap on its paid calls (roadmap of 2026-11-14, stage 5: `LA-UNBOUNDED-AGENT-LOOP`).

An agent loop asks a paid model, does what the model asks for (runs a tool), and asks again until the model says it is
done. Where nothing but the model's answer ends it, a model that keeps asking, or words put into what it reads that
tell it to, keep it going, and every round is billed. Read from the program the data-flow step built
(`lantern/flow.py`, after `Engine.run`), so nothing of the project is run:

* a paid call: a model call the flow step knows by the library's own name (`flow_rules.MODEL_CALL`) that is paid for
  each time (not `UNPAID_MODEL`, a model run on this computer), where the step met it (`Engine.paid`); or a call of a
  function of the project that makes one, directly or through others (`_Look.pays`, `MAX_DEPTH` deep);
* a round: a `while` loop, `for (;;)`, `do … while`, a `for` over an endless iterator (`flow_rules.ENDLESS`), or a
  function that calls itself. A `for` over a list or a `range` has as many rounds as items, and is no such loop;
* the model's answer decides: the loop's own test, or a condition under which the loop is left (`break`, `return`,
  `raise`/`throw`, an exit of the program) or goes round again (`continue`, where the loop has a way out), reads a name
  that holds the model's answer: a name the flow step saw given text the model wrote (`Engine.model_names`), or one the
  function sets from such a name (`done = choice.finish_reason == "stop"`). For a function that calls itself: a
  condition before the call under which it returns, or one the call stands under;
* a cap, read where the loop decides: a counter the loop changes (`x += 1`, `x = x + 1`, `i++`, the length of a list it
  adds to), a clock (`flow_rules.CLOCK`) or a name set from one, or a name made of a budget's words
  (`flow_rules.BUDGET_WORDS`: `spent`, `total_tokens`); for a function that calls itself, also a parameter read in a
  condition and handed to the next call changed (`depth + 1`). A person asked in each round (`flow_rules.ASKS`) bounds
  it too.

A library's own agent loop whose limit is a setting (`flow_rules.AGENT_RUNNER`, `_setting_off`): LangChain's
`AgentExecutor(max_iterations=None)` with no `max_execution_time`, and the AI SDK's `stopWhen` made only of
`hasToolCall(...)` or `maxSteps: Infinity`, on a call that hands the model tools.

Not judged (docs/ai-apps.md says so): a loop that ends when reading the model's text stops failing (an exception), the
model's answer kept on an object (`self.last`), functions that call each other in turn, and a cap kept outside the
code (a spend limit on the provider's dashboard, which the finding asks for anyway). `aiapp.from_agent_loops` makes the
findings; this module only reads.
"""
from __future__ import annotations

import re

from . import flow_rules as R
from .flow import Fn, all_nodes, every_node, names_in, text_of

MAX_DEPTH = 5       # how many functions of the project deep a paid call is looked for
MOST_SAID = 4       # paid calls and conditions named on one finding
WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
GROWS = frozenset({"append", "push", "extend", "add", "insert", "unshift"})     # a list the loop adds to
STOPS = re.compile(r"^(?:sys\.exit|os\._exit|exit|quit|process\.exit)$")         # the program ends


def find(eng) -> tuple[list[dict], dict]:
    """The agent loops of the project whose program the flow step's engine `eng` read, each `{"kind": "loop" |
    "itself" | "setting", "file", "line", "paid": [{file, line, what[, through]}], "ends": [{line, what}]}` (a setting
    also `"setting"`: its words, and `"what"`: the call), and the record's counts: `paid_calls`, `loops` (rounds that
    make a paid call and end on the model's answer), `capped` (of those, a count, a clock or a budget ends), `asked` (a
    person says yes to each round), `settings_off`, `findings`."""
    paid = getattr(eng, "paid", None) or {}
    runners = getattr(eng, "agent_calls", None) or {}
    rec = {"paid_calls": len(paid), "loops": 0, "capped": 0, "asked": 0, "settings_off": 0, "findings": 0}
    out: list[dict] = []
    look = _Look(eng)
    for fn in look.functions() if paid else ():
        for loop in (n for n in every_node(fn.body) if n.k == "loop"):
            got = look.loop(fn, loop)
            if got is None:
                continue
            rec["loops"] += 1
            if got == "capped" or got == "asked":
                rec[got] += 1
            else:
                out.append(got)
        got = look.itself(fn)
        if got is not None:
            rec["loops"] += 1
            if got == "capped" or got == "asked":
                rec[got] += 1
            else:
                out.append(got)
    seen: set = set()
    for fn, e, name in runners.values():
        words = _setting_off(e, name)
        if words and (fn.file, e.line) not in seen:
            seen.add((fn.file, e.line))
            out.append({"kind": "setting", "file": fn.file, "line": e.line, "paid": [], "ends": [], "setting": words,
                        "what": text_of(e)})
            rec["settings_off"] += 1
    out.sort(key=lambda x: (x["file"], x["line"]))
    rec["findings"] = len(out)
    return out, rec


class _Look:
    def __init__(self, eng):
        self.eng = eng
        self._pays: dict = {}
        self._model: dict = {}
        self._clocked: dict = {}

    def functions(self):
        """Every function of the project once: the files' own code, functions and methods, and those written inside
        them."""
        seen: set = set()
        for unit in list(self.eng.units):
            inner = [n.a for n in all_nodes(unit.body) if n.k in ("def", "fn") and isinstance(n.a, Fn)]
            for fn in [unit] + inner:
                if id(fn) not in seen and fn.body is not None and fn.file:
                    seen.add(id(fn))
                    yield fn

    def targets(self, fn: Fn, c) -> list:
        site = self.eng.sites.get((fn.file, c.line, c.col))
        return self.eng.targets(site)[0] if site else []

    def pays(self, fn: Fn, depth: int = 0):
        """(file, line) of a paid call `fn` makes, itself or through functions of the project it calls, or None."""
        key = id(fn)
        if key in self._pays:
            return self._pays[key]
        self._pays[key] = None      # a function that leads back to itself pays only through another call
        calls = [n for n in all_nodes(fn.body) if n.k == "call"]
        found = next(((fn.file, c.line) for c in calls if (fn.file, c.line, c.col) in self.eng.paid), None)
        if found is None and depth < MAX_DEPTH:
            for c in calls:
                found = next((got for t in self.targets(fn, c) if (got := self.pays(t, depth + 1))), None)
                if found:
                    break
        self._pays[key] = found
        return found

    def paid_in(self, fn: Fn, nodes, skip=frozenset()) -> list[dict]:
        """The paid calls among `nodes` (a function's own lines, not those of functions written inside them)."""
        said: list[dict] = []
        for c in every_node(nodes):
            if c.k != "call" or id(c) in skip:
                continue
            if (fn.file, c.line, c.col) in self.eng.paid:
                said.append({"file": fn.file, "line": c.line, "what": text_of(c)})
                continue
            through = next((got for t in self.targets(fn, c) if (got := self.pays(t))), None)
            if through:
                said.append({"file": fn.file, "line": c.line, "what": text_of(c),
                             "through": f"{through[0]}:{through[1]}"})
        return said

    def model(self, fn: Fn) -> set:
        """The names `fn` gives a value that holds the model's answer: those the flow step saw given text the model
        wrote, and those set from them in `fn`'s own lines."""
        key = id(fn)
        if key in self._model:
            return self._model[key]
        names = set(self.eng.model_names.get(key, ()))
        sets = []
        for n in every_node(fn.body):
            if n.k == "assign" and n.a is not None:
                got = [x for t in n.items or () for x in names_in(t)]
                if got:
                    sets.append((got, n.a))
            elif n.k == "walrus" and n.a is not None:
                sets.append(([n.name], n.a))
            elif n.k == "loop" and n.items and n.items[0] is not None and n.items[1] is not None:
                sets.append((names_in(n.items[0]), n.items[1]))
        changed = bool(names)
        while changed:
            changed = False
            for got, value in sets:
                if not names.issuperset(got) and _reads(value, names):
                    names.update(got)
                    changed = True
        self._model[key] = names
        return names

    def clocked(self, fn: Fn) -> set:
        """The names `fn` sets from a clock (`deadline = time.monotonic() + 60`)."""
        key = id(fn)
        if key not in self._clocked:
            self._clocked[key] = {x for n in every_node(fn.body) if n.k == "assign" and n.a is not None and
                                  any(c.k == "call" and R.CLOCK.search(text_of(c.a)) for c in every_node(n.a))
                                  for t in n.items or () for x in names_in(t)}
        return self._clocked[key]

    def asked(self, fn: Fn, nodes, lo: int, hi: int) -> bool:
        """Whether a person is asked in each round: a question among `nodes`, or one the flow step saw there."""
        if any(c.k == "call" and R.ASKS.search(text_of(c.a)) for c in every_node(nodes)):
            return True
        return any(first == fn.first and lo <= line <= hi for first, _end, line in self.eng.asks.get(fn.file, ()))

    def capped(self, fn: Fn, deciding: list, counted: set, grown: set) -> bool:
        """Whether a count, a clock or a budget is read where the loop decides to go on."""
        clocked = self.clocked(fn)
        for cond in deciding:
            for n in every_node(cond):
                k = n.k
                if k in ("name", "attr"):
                    if text_of(n) in counted or (k == "name" and n.name in clocked) or _budget(n.name):
                        return True
                    if k == "attr" and n.name in ("length", "size") and text_of(n.a) in grown:
                        return True
                elif k == "call":
                    callee = text_of(n.a)
                    if R.CLOCK.search(callee) or (callee == "len" and n.items and text_of(n.items[0]) in grown):
                        return True
        return False

    def loop(self, fn: Fn, loop):
        """A loop of `fn` that makes a paid call in each round and ends on the model's answer: "capped", "asked", or
        what the finding needs; None for any other loop."""
        _target, it, test = loop.items
        if it is not None and not self.endless(fn, it):
            return None         # a `for` over items: as many rounds as there are items
        paid = self.paid_in(fn, [loop.b, test])
        if not paid:
            return None
        always = test is None or (test.k == "const" and bool(test.a))
        exits, goes = _ways(loop.b)
        model = self.model(fn)
        ends = [test] if not always and _reads(test, model) else []
        ends += [g for gs, _s in exits for g in gs if g is not None and _reads(g, model)]
        if exits or not always:
            ends += [g for gs, _s in goes for g in gs if g is not None and _reads(g, model)]
        if not ends:
            return None
        deciding = ([test] if not always else []) + [g for gs, _s in exits + goes for g in gs if g is not None]
        counted, grown = _counted(loop)
        if self.capped(fn, deciding, counted, grown):
            return "capped"
        if self.asked(fn, [loop.b, test], loop.line, max((n.line for n in every_node(loop)), default=loop.line)):
            return "asked"
        return {"kind": "loop", "file": fn.file, "line": loop.line, "paid": _unique(paid),
                "ends": _unique([{"line": c.line, "what": _what(c, model)} for c in ends])}

    def itself(self, fn: Fn):
        """`fn` calls itself again, with a paid call in each round, unless the model's answer ends it: "capped",
        "asked", or what the finding needs; None otherwise."""
        calls = [c for c in every_node(fn.body) if c.k == "call" and any(t is fn for t in self.targets(fn, c))]
        if not calls:
            return None
        mine = {id(c) for c in calls}
        paid = self.paid_in(fn, fn.body, skip=mine)
        if not paid:
            return None
        first = min(c.line for c in calls)
        model = self.model(fn)
        exits, _goes = _ways(fn.body, brk=False, cont=False)
        before = [g for gs, s in exits if s.line < first and not any(id(n) in mine for n in every_node(s))
                  for g in gs if g is not None]
        over = [g for gs in _guards_of(fn.body, mine) for g in gs if g is not None]
        ends = [g for g in before + over if _reads(g, model)]
        if not ends:
            return None
        params = {p.name for p in fn.params if p.name and p.name not in ("self", "cls")}
        tested = {n.name for s in every_node(fn.body) if s.k in ("if", "loop", "cond")
                  for n in every_node(s.a if s.k != "loop" else s.items[2]) if n.k == "name"} & params
        changed = any(a is not None and a.k in ("bin", "arith") and
                      any(n.k == "name" and n.name in tested for n in every_node(a))
                      for c in calls for a in list(c.items or ()) + list((c.kw or {}).values()))
        if changed or self.capped(fn, before + over, set(), set()):
            return "capped"
        if self.asked(fn, fn.body, fn.first, fn.end):
            return "asked"
        return {"kind": "itself", "file": fn.file, "line": first, "paid": _unique(paid),
                "ends": _unique([{"line": c.line, "what": _what(c, model)} for c in ends])}

    @staticmethod
    def endless(fn: Fn, it) -> bool:
        """`itertools.count()`, `count()` taken from itertools: a `for` over it never runs out of items."""
        if it.k != "call" or it.a is None:
            return False
        name = text_of(it.a)
        head, _, rest = name.partition(".")
        origin = (fn.mod.imports.get(head) if fn.mod is not None else None) or head
        return bool(R.ENDLESS.match(origin + ("." + rest if rest else "")))


def _reads(e, names: set) -> bool:
    """Whether `e` reads one of `names` (functions written inside it left out)."""
    return e is not None and bool(names) and any(n.k == "name" and n.name in names for n in every_node(e))


def _what(cond, names: set, depth: int = 0) -> str:
    """The part of a condition that reads the model's answer, as written: `resp.stop_reason`, `done`."""
    if depth > 10:
        return text_of(cond)[:80]
    k = cond.k
    if k == "not" and cond.a is not None:
        return _what(cond.a, names, depth + 1)
    if k in ("bool", "cmp"):
        for x in (cond.items or ()) if k == "bool" else (cond.a, cond.b):
            if x is not None and _reads(x, names):
                return _what(x, names, depth + 1)
    return text_of(cond)[:80]


def _budget(name) -> bool:
    return bool(name) and any(w.lower() in R.BUDGET_WORDS for w in WORDS.findall(str(name)))


def _mentions(e, key: str) -> bool:
    return any(n.k in ("name", "attr") and text_of(n) == key for n in every_node(e))


def _counted(loop) -> tuple[set, set]:
    """What the loop counts (`x += 1`, `x = x - 1`, `i++`, `self.turns += 1`) and the lists it adds to."""
    counted, grown = set(), set()
    for n in every_node([loop.b, loop.items[2]]):
        k = n.k
        if k == "assign":
            for t in n.items or ():
                if t.k in ("name", "attr") and (n.name in ("+", "-") or (
                        n.a is not None and n.a.k in ("bin", "arith") and _mentions(n.a, text_of(t)))):
                    counted.add(text_of(t))
        elif k == "walrus" and n.a is not None and n.a.k in ("bin", "arith") and _mentions(n.a, n.name):
            counted.add(n.name)
        elif k == "arith" and len(n.items or ()) == 1 and n.items[0] is not None and n.items[0].k in ("name", "attr"):
            counted.add(text_of(n.items[0]))        # `i++`, `--left`
        elif k == "call" and n.a is not None and n.a.k == "attr" and n.a.name in GROWS:
            grown.add(text_of(n.a.a))
    return counted, grown


def _ways(stmts, guards=(), brk=True, cont=True, depth=0) -> tuple[list, list]:
    """Each way out of the loop whose body is `stmts` (`break`, `return`, `raise`, an exit of the program), and each
    `continue` of it, with the conditions it is taken under, in order: [(guards, statement)]. A condition that is
    not a value (an exception caught) is None. `brk`/`cont`: whether a `break` / `continue` here belongs to the loop
    (not inside a loop written in it, and a `break` not inside a JavaScript `switch`)."""
    exits: list = []
    goes: list = []
    if depth > 40:
        return exits, goes
    for s in stmts or ():
        k = s.k
        parts: list = []
        if k == "jump":
            if s.name == "break" and brk:
                exits.append((guards, s))
            elif s.name == "continue" and cont:
                goes.append((guards, s))
        elif k in ("return", "raise"):
            exits.append((guards, s))
        elif k == "expr" and s.a is not None and s.a.k == "call" and STOPS.match(text_of(s.a.a)):
            exits.append((guards, s))
        elif k == "if":
            parts = [(s.b, guards + (s.a,), brk, cont), (s.c, guards + (s.a,), brk, cont)]
        elif k == "try":
            parts = [(s.b, guards, brk, cont), (s.c, guards, brk, cont)] + \
                [(h, guards + (None,), brk, cont) for _n, h in s.items or ()]
        elif k == "with":
            parts = [(s.b, guards, brk, cont)]
        elif k == "match":
            switch = bool(s.kw) and "labels" in s.kw        # JavaScript: a `break` leaves the switch
            parts = [(case, guards + (s.a,), brk and not switch, cont) for case in s.items or ()]
        elif k == "loop":
            _t, it, test = s.items
            parts = [(s.b, guards + (test if test is not None else it,), False, False)]
        for body, g, b, c in parts:
            e2, g2 = _ways(body, g, b, c, depth + 1)
            exits += e2
            goes += g2
    return exits, goes


def _guards_of(stmts, want: set, guards=(), depth=0) -> list:
    """The conditions each statement holding one of the calls `want` (by id) stands under."""
    out: list = []
    if depth > 40:
        return out
    for s in stmts or ():
        k = s.k
        if k == "if":
            if any(id(n) in want for n in every_node(s.a)):
                out.append(guards)
            out += _guards_of(s.b, want, guards + (s.a,), depth + 1) + _guards_of(s.c, want, guards + (s.a,), depth + 1)
        elif k == "try":
            out += _guards_of(s.b, want, guards, depth + 1) + _guards_of(s.c, want, guards, depth + 1)
            for _n, h in s.items or ():
                out += _guards_of(h, want, guards + (None,), depth + 1)
        elif k == "with":
            if any(id(n) in want for n in every_node(s.items)):
                out.append(guards)
            out += _guards_of(s.b, want, guards, depth + 1)
        elif k == "match":
            if any(id(n) in want for n in every_node(s.a)):
                out.append(guards)
            for case in s.items or ():
                out += _guards_of(case, want, guards + (s.a,), depth + 1)
        elif k == "loop":
            _t, it, test = s.items
            if any(id(n) in want for n in every_node(s.items)):
                out.append(guards)
            out += _guards_of(s.b, want, guards + (test if test is not None else it,), depth + 1)
        elif any(id(n) in want for n in every_node(s)):
            out.append(guards)
    return out


def _none(e) -> bool:
    return e is not None and e.k == "const" and e.a is None


def _setting_off(e, name: str) -> str | None:
    """The words for a library's agent loop whose limit on rounds is switched off by this call, or None."""
    if "AgentExecutor" in name:
        kw = e.kw or {}
        most, clock = kw.get("max_iterations"), kw.get("max_execution_time")
        if _none(most) and (clock is None or _none(clock)):
            return "`max_iterations=None` with no `max_execution_time`"
        return None
    opts = e.items[0] if e.items and e.items[0] is not None and e.items[0].k == "map" else None
    if opts is None:
        return None
    keys = {k.a: v for k, v in opts.items or () if k is not None and k.k == "const" and isinstance(k.a, str)}
    if "tools" not in keys:
        return None
    steps, stop = keys.get("maxSteps"), keys.get("stopWhen")
    if steps is not None and ((steps.k == "name" and steps.name == "Infinity") or
                              (steps.k == "attr" and text_of(steps) in ("Number.POSITIVE_INFINITY",
                                                                        "Number.MAX_SAFE_INTEGER",
                                                                        "Number.MAX_VALUE"))):
        return f"`maxSteps: {text_of(steps)}`"
    if stop is not None:
        conds = (stop.items or []) if stop.k == "seq" else [stop]
        if conds and all(c is not None and c.k == "call" and text_of(c.a).rsplit(".", 1)[-1] == "hasToolCall"
                         for c in conds):
            return "`stopWhen` made only of `hasToolCall(...)`"
    return None


def _unique(rows: list) -> list:
    out: list = []
    for r in rows:
        if r not in out:
            out.append(r)
    return out[:MOST_SAID]
