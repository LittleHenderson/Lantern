"""Type-aware call resolution, opt-in (roadmap of 2026-11-14, stage 1; `lantern/typecheck.py`).

Where Lantern's own reading leaves a call unresolved, `lantern analyze --typecheck` asks the type checkers this
computer has (the TypeScript compiler, pyright) where it goes. The checkers read a stranger's project, so the tests
come in pairs: what a checker says is used only where it has the shape of an answer and names a function Lantern
itself read (an odd or wrong answer changes nothing, beside the answer that links); and a checker, a settings file,
a program named `python`, a copy of the compiler or a link that come with the project decide nothing (beside the
same project without them, which reads the same).

Three parts. The first runs on every system: the checkers' answers are written by the test and nothing is started.
The second starts a stand-in program in the checker's place (POSIX: a shell script). The third starts the real
checkers, only where LANTERN_TESTS_TYPECHECK is set (`1`, or `required`: there a checker that is not found fails the
test instead of skipping it); they are found the way Lantern finds them (LANTERN_NODE, LANTERN_TYPESCRIPT,
LANTERN_PYRIGHT, else PATH), and the run names them under "programs these tests started".

These tests were written after the first version of the code they test (2026-11-15), which is said here because
the rule is the other way round: on the commit before it the module does not exist and every one of them fails."""

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lantern import security, typecheck
from lantern.cli import main
from lantern.engine import build_graph
from lantern.graph import INFERRED, RESOLVED

WANTED = os.environ.get("LANTERN_TESTS_TYPECHECK", "").strip().lower()
posix_only = pytest.mark.skipif(os.name != "posix", reason="a shell script stands in for the program: POSIX")
needs_checkers = pytest.mark.skipif(
    not WANTED, reason="the real type checkers are started only where LANTERN_TESTS_TYPECHECK is set")

TS_APP = {
    "package.json": '{"name": "notes", "private": true}\n',
    "app/store.ts": (
        "export interface Notes { save(text: string): void }\n"
        "export class MemoryNotes implements Notes {\n"
        "  save(text: string) { console.log(text) }\n"
        "}\n"
        "export function useNotes() {\n"
        "  const save = (n: string) => n.trim()\n"
        "  function drop(n: string) { return n }\n"
        "  return { save, drop }\n"
        "}\n"
        "export const tools = { shout: (s: string) => s.toUpperCase() }\n"),
    "app/page.ts": (
        "import { useNotes, MemoryNotes, tools } from './store'\n"
        "import type { Notes } from './store'\n"
        "import * as store from './store'\n"
        "export function page(notes: Notes, mk: () => MemoryNotes, pick: (t: typeof tools) => typeof tools.shout) {\n"
        "  const { save, drop } = useNotes()\n"
        "  save('a')\n"
        "  drop('b')\n"
        "  notes.save('y')\n"
        "  mk().save('z')\n"
        "  const list = [new MemoryNotes()]\n"
        "  list[0].save('q')\n"
        "  list.map((m) => m.save('w'))\n"
        "  const shout = pick(tools)\n"
        "  shout('s')\n"
        "  const { useNotes: again } = store\n"
        "  again()\n"
        "}\n"),
}
SAVE, DROP, KEPT, HOOK = ("js:app/store::useNotes.save", "js:app/store::useNotes.drop", "js:app/store::MemoryNotes.save",
                          "js:app/store::useNotes")

PY_APP = {
    "app/__init__.py": "",
    "app/models.py": (
        "class Note:\n"
        "    def __init__(self, text: str):\n"
        "        self.text = text\n"
        "\n"
        "    def shout(self) -> str:\n"
        "        return self.text.upper()\n"
        "\n\n"
        "class Draft:\n"
        "    def shout(self) -> str:\n"
        "        return 'draft'\n"
        "\n\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.notes: list[Note] = []\n"
        "\n"
        "    def first(self) -> Note:\n"
        "        return self.notes[0]\n"
        "\n\n"
        "def make_store() -> Store:\n"
        "    return Store()\n"),
    "app/tools.py": (
        "__all__ = ['tidy'] + ['sort_notes']\n"
        "\n\n"
        "def tidy(text: str) -> str:\n"
        "    return text.strip()\n"
        "\n\n"
        "def sort_notes(notes):\n"
        "    return sorted(notes)\n"),
    "app/main.py": (
        "from app.models import Note, make_store\n"
        "from app.tools import *\n"
        "\n\n"
        "def run(cb=None, names: list[str] = ()):\n"
        "    items = [Note('x')]\n"
        "    items[0].shout()\n"
        "    cb()\n"
        "    for name in names:\n"
        "        name.strip()\n"
        "    tidy('a')\n"
        "    again = make_store\n"
        "    again()\n"
        "    return make_store().first().shout()\n"),
}
SHOUT, TIDY, MADE, NOTE = "py:app.models.Note.shout", "py:app.tools.tidy", "py:app.models.make_store", "py:app.models.Note"
SORT = "py:app.tools.sort_notes"

# calls for which Lantern's own reading withholds a library label: the function may be the project's own
MAYBE_OWN = {
    "app/checks.py": (
        "import unittest\n"
        "\n\n"
        "class Shelf:\n"
        "    def get(self, key):\n"
        "        return key\n"
        "\n\n"
        "class Checks(unittest.TestCase):\n"
        "    def go(self):\n"
        "        return self.client.get('/')\n"),
    "srv/package.json": '{"name": "srv", "dependencies": {"express": "4"}}\n',
    "srv/app.js": (
        "const express = require('express')\n"
        "const app = express()\n"
        "class Guard { can(x) { return !!x } }\n"
        "app.get('/a', function (req, res) {\n"
        "  req.user.can('read')\n"
        "  res.json({})\n"
        "})\n"
        "module.exports = { app, Guard }\n"),
}

TOOLS = {"node": "/nowhere/node", "typescript": "/nowhere/typescript", "typescript_version": "9.9.9",
         "pyright": "/nowhere/pyright/langserver.index.js", "pyright_version": "8.8.8", "passed": [],
         "notes": {"typescript": None, "python": None}}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _never(*a, **k):
    raise AssertionError("nothing may be asked or started here")


def _site(g, callee, ending=""):
    hits = [s for s in g.sites if s["group"] == "written" and s["callee"] == callee and s["file"].endswith(ending)]
    assert len(hits) == 1, (callee, [(s["at"], s["callee"]) for s in g.sites])
    return hits[0]


def _shape(g):
    """Everything the pass may change, to hold a run beside one that did not ask."""
    return {"sites": [(s["at"], s["group"], s["outcome"], s["to"], s["via"], s["confidence"], s["reason"]) for s in g.sites],
            "edges": sorted((e.src, e.dst, e.kind, e.confidence, e.via or "", tuple(e.lines)) for e in g.edges),
            "nodes": sorted(g.nodes), "unresolved": dict(g.unresolved), "in_tests": dict(g.unresolved_tests),
            "builtin": g.builtin_calls, "calls": g.meta["calls"]}


def _by_checker(g):
    """What the pass changed: {the call as written: (outcome, where to)}."""
    return {s["callee"]: (s["outcome"], s["to"]) for s in g.sites if s["via"] == "typecheck"}


def _open(g, endings):
    """The calls the pass asks about (it asks in the order the readers wrote them down; this is the finished list's)."""
    first = {}
    for s in g.sites:
        first.setdefault((s["group"], s["at"]), s)
    return [s for (group, _), s in first.items()
            if group == "written" and s["outcome"] == "unresolved" and s["caller"] in g.nodes and s["file"].endswith(endings)]


def _stand_in(monkeypatch, ts=None, py=None, stopped=None):
    """The checkers' answers come from the test, by the call as written; nothing is found and nothing is started."""
    asked = {"typescript": [], "python": []}

    def answering(lang, table, version):
        def ask(tools, root, g, sites, limit):
            asked[lang] += [s["callee"] for s in sites]
            return {"version": version, "answers": [(table or {}).get(s["callee"]) for s in sites], "stopped": stopped}
        return ask
    monkeypatch.setattr(typecheck, "find", lambda root: json.loads(json.dumps(TOOLS)))
    monkeypatch.setattr(typecheck, "ask_typescript", answering("typescript", ts, "9.9.9"))
    monkeypatch.setattr(typecheck, "ask_python", answering("python", py, "8.8.8"))
    monkeypatch.setattr(typecheck, "_start", _never)
    return asked


def _ts(g, node, direct=False, **other):
    n = g.nodes[node]
    return {"where": "project", "file": n.file, "lines": [n.start_line], "name": re.split(r"[.:]", node)[-1],
            "what": "function", "direct": direct} | other


def _py(g, node, direct=False, **other):
    n = g.nodes[node]
    return {"where": "project", "file": n.file, "line": n.start_line, "name": node.rsplit(".", 1)[-1],
            "what": "function", "direct": direct} | other


# ---- the first part: answers written by the test, on every system ----

def test_nothing_is_asked_unless_the_person_asks_for_it(tmp_path, monkeypatch):
    """Off by default. The caller's word or LANTERN_TYPECHECK turn it on; nothing in the project does."""
    repo = _write(tmp_path, TS_APP | PY_APP | {
        ".env": "LANTERN_TYPECHECK=1\n", "lantern.json": '{"typecheck": true}\n',
        "pyproject.toml": "[tool.lantern]\ntypecheck = true\n", ".lantern/settings.json": '{"typecheck": true}\n'})
    monkeypatch.delenv("LANTERN_TYPECHECK", raising=False)
    monkeypatch.setattr(typecheck, "find", _never)
    monkeypatch.setattr(typecheck, "_start", _never)
    plain = build_graph(repo)
    assert "typecheck" not in plain.meta and not _by_checker(plain) and plain.unresolved_at
    monkeypatch.setenv("LANTERN_TYPECHECK", "1")
    assert "typecheck" not in build_graph(repo, typecheck=False).meta      # the caller's no stands over the variable
    for word in ("", "0", "no", "off", "maybe"):
        monkeypatch.setenv("LANTERN_TYPECHECK", word)
        assert "typecheck" not in build_graph(repo).meta, word
    asked = _stand_in(monkeypatch)
    for word in ("1", "true", "YES", " on "):
        monkeypatch.setenv("LANTERN_TYPECHECK", word)
        assert build_graph(repo).meta["typecheck"]["asked"] is True, word
    monkeypatch.delenv("LANTERN_TYPECHECK")
    assert build_graph(repo, typecheck=True).meta["typecheck"]["asked"] is True
    assert asked["typescript"] and asked["python"]


def test_what_a_checker_says_becomes_one_link_and_the_call_is_still_one_call(tmp_path, monkeypatch):
    repo = _write(tmp_path, TS_APP | PY_APP)
    before = build_graph(repo)
    for callee in ("save", "cb"):
        assert _site(before, callee)["outcome"] == "unresolved"
    asked = _stand_in(monkeypatch, ts={"save": _ts(before, SAVE)},
                      py={"cb": _py(before, SORT, direct=True), "again": _py(before, MADE, direct=True)})
    g = build_graph(repo, typecheck=True)
    s, c, a = _site(g, "save"), _site(g, "cb"), _site(g, "again", ".py")
    # through a value's type: likely, as Lantern's own links through a written type. By the name itself: confirmed
    assert (s["outcome"], s["to"], s["via"], s["confidence"], s["reason"], s["why"]) == \
        ("likely", [SAVE], "typecheck", INFERRED, None, None)
    assert (c["outcome"], c["to"], c["via"], c["confidence"], c["reason"], c["why"]) == \
        ("resolved", [SORT], "typecheck", RESOLVED, None, None)
    for site, target, confidence in ((s, SAVE, INFERRED), (c, SORT, RESOLVED)):
        edges = [e for e in g.edges if e.src == site["caller"] and e.dst == target and e.kind == "calls"]
        assert len(edges) == 1 and (edges[0].via, edges[0].confidence) == ("typecheck", confidence), edges
        assert site["line"] in edges[0].lines
    # a link Lantern had already made by itself (`make_store()` two lines further on) is one link still: it keeps
    # saying how Lantern found it and gets the call's line; the call's own record says who placed that call
    had = [e for e in before.edges if e.src == a["caller"] and e.dst == MADE and e.kind == "calls"]
    has = [e for e in g.edges if e.src == a["caller"] and e.dst == MADE and e.kind == "calls"]
    assert len(had) == len(has) == 1 and (has[0].via, has[0].confidence) == (had[0].via, had[0].confidence) == ("name", RESOLVED)
    assert sorted(has[0].lines) == sorted(had[0].lines + [a["line"]]) and a["line"] not in had[0].lines
    assert (a["outcome"], a["to"], a["via"]) == ("resolved", [MADE], "typecheck")
    # one call before and one call after, in the inventory and in the older count
    was, now = before.meta["calls"]["written"], g.meta["calls"]["written"]
    assert now["total"] == was["total"] and sum(now["outcomes"].values()) == now["total"]
    assert now["outcomes"]["unresolved"] == was["outcomes"]["unresolved"] - 3
    assert now["outcomes"]["likely"] == was["outcomes"]["likely"] + 1
    assert now["outcomes"]["resolved"] == was["outcomes"]["resolved"] + 2
    assert (before.unresolved["save"], before.unresolved["cb"], before.unresolved["again"]) == (1, 1, 2)
    assert "save" not in g.unresolved and "cb" not in g.unresolved and g.unresolved["again"] == 1
    assert sum(g.unresolved.values()) == sum(before.unresolved.values()) - 3
    # only what Lantern's own reading left unresolved was asked, each call once
    assert sorted(asked["typescript"]) == sorted(x["callee"] for x in _open(before, typecheck.JS_ENDINGS))
    assert sorted(asked["python"]) == sorted(x["callee"] for x in _open(before, ".py"))
    assert not {"console.log", "make_store", "Note"} & set(asked["typescript"] + asked["python"])
    meta = g.meta["typecheck"]
    assert (meta["typescript"]["ran"], meta["typescript"]["version"], meta["typescript"]["likely"],
            meta["typescript"]["linked"]) == (True, "9.9.9", 1, 0)
    assert (meta["python"]["ran"], meta["python"]["version"], meta["python"]["likely"], meta["python"]["linked"]) == \
        (True, "8.8.8", 0, 2)
    for part, n in ((meta["typescript"], len(asked["typescript"])), (meta["python"], len(asked["python"]))):
        assert part["asked"] == n == sum(part[k] for k in typecheck.COUNTS) and part["not_asked"] == 0


def test_a_class_that_is_called_is_its_own_init_and_nothing_where_it_writes_none(tmp_path, monkeypatch):
    repo = _write(tmp_path, PY_APP)
    before = build_graph(repo)
    cls = {"where": "project", "file": "app/models.py", "name": "Note", "what": "class", "direct": True,
           "line": before.nodes[NOTE].start_line}
    _stand_in(monkeypatch, py={"cb": cls})
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {"cb": ("resolved", [NOTE + ".__init__"])}
    none = cls | {"name": "Draft", "line": before.nodes["py:app.models.Draft"].start_line}     # it writes no __init__
    _stand_in(monkeypatch, py={"cb": none})
    g = build_graph(repo, typecheck=True)
    assert _shape(g) == _shape(before) and g.meta["typecheck"]["python"]["declared"] == 1


MADE_TS = {
    "package.json": '{"name": "made", "private": true}\n',
    "app/errors.ts": (
        "export class Refused extends Error {\n"
        "  constructor(message = 'no') { super(message) }\n"
        "}\n"
        "export class Plain {}\n"),
    "app/use.ts": (
        "export function use(make: any) {\n"
        "  make('a')\n"
        "}\n"),
}


def test_a_class_that_is_made_is_its_own_constructor_where_it_writes_one_typescript(tmp_path, monkeypatch):
    """As the JS/TS reader links `new Refused()` itself: to the constructor the class writes, else to the class.
    (Seen on a public project: the checker's answer and Lantern's own link for one `new X()` named two nodes.)"""
    repo = _write(tmp_path, MADE_TS)
    before = build_graph(repo)
    assert _site(before, "make")["outcome"] == "unresolved"
    refused, plain = "js:app/errors::Refused", "js:app/errors::Plain"
    assert refused + ".constructor" in before.nodes and plain + ".constructor" not in before.nodes
    for cls, target in ((refused, refused + ".constructor"), (plain, plain)):
        _stand_in(monkeypatch, ts={"make": _ts(before, cls, direct=True, what="class")})
        g = build_graph(repo, typecheck=True)
        assert _by_checker(g) == {"make": ("resolved", [target])}


ODD_TS = {
    "a file outside the project": lambda g, repo: _ts(g, SAVE, file="../outside/store.ts"),
    "a library's file": lambda g, repo: _ts(g, SAVE, file="node_modules/notes/index.js"),
    "the file by its full path": lambda g, repo: _ts(g, SAVE, file=str(repo / "app/store.ts")),
    "a file that is no text": lambda g, repo: _ts(g, SAVE, file=["app/store.ts"]),
    "a line with no function": lambda g, repo: _ts(g, SAVE, lines=[1]),
    "another function's name": lambda g, repo: _ts(g, SAVE, name="drop"),
    "a class where a function stands": lambda g, repo: _ts(g, SAVE, what="class"),
    "a line written as text": lambda g, repo: _ts(g, SAVE, lines=[str(g.nodes[SAVE].start_line)]),
    "a line that is `true`": lambda g, repo: _ts(g, SAVE, lines=[True]),
    "lines that are no list": lambda g, repo: _ts(g, SAVE, lines=g.nodes[SAVE].start_line),
    "a place nobody knows": lambda g, repo: {"where": "elsewhere", "name": "save"},
    "a node's name and nothing else": lambda g, repo: SAVE,
    "a list": lambda g, repo: [_ts(g, SAVE)],
    "a number": lambda g, repo: 7,
    "true": lambda g, repo: True,
    "an empty table": lambda g, repo: {},
    "a built-in with a space in its name": lambda g, repo: {"where": "builtin", "name": "String trim"},
    "a library with a line break in its name": lambda g, repo: {"where": "library", "name": "left\npad.go"},
    "a library with no name": lambda g, repo: {"where": "library"},
    "a name that is a table": lambda g, repo: {"where": "builtin", "name": {"x": 1}},
    "a name of 500 letters": lambda g, repo: {"where": "builtin", "name": "a" * 500},
}


@pytest.mark.parametrize("odd", sorted(ODD_TS))
def test_an_answer_that_names_no_function_lantern_read_changes_nothing_typescript(tmp_path, monkeypatch, odd):
    """The safe twins of the test above: the same call, and an answer that is none."""
    repo = _write(tmp_path, TS_APP)
    before = build_graph(repo)
    _stand_in(monkeypatch, ts={"save": ODD_TS[odd](before, repo)})
    g = build_graph(repo, typecheck=True)
    assert _shape(g) == _shape(before)
    part = g.meta["typecheck"]["typescript"]
    assert part["ran"] is True and part["linked"] + part["likely"] + part["builtin"] + part["library"] == 0
    assert _site(g, "save")["reason"] == _site(before, "save")["reason"] == "local-unknown"


ODD_PY = {
    "a file outside the project": lambda g: _py(g, MADE, file="../outside.py"),
    "a file Lantern did not read": lambda g: _py(g, MADE, file="app/missing.py"),
    "a line inside another function": lambda g: _py(g, MADE, line=g.nodes[NOTE + ".__init__"].start_line),
    "a name that is no function": lambda g: _py(g, MADE, name="nothing"),
    "a class where a function stands": lambda g: _py(g, MADE, what="class"),
    "a line written as text": lambda g: _py(g, MADE, line=str(g.nodes[MADE].start_line)),
    "a line that is `true`": lambda g: _py(g, MADE, line=True),
    "no name": lambda g: _py(g, MADE, name=None),
    "lines, the other checker's word": lambda g: {k: v for k, v in _py(g, MADE).items() if k != "line"} | {"lines": [1]},
}


@pytest.mark.parametrize("odd", sorted(ODD_PY))
def test_an_answer_that_names_no_function_lantern_read_changes_nothing_python(tmp_path, monkeypatch, odd):
    repo = _write(tmp_path, PY_APP)
    before = build_graph(repo)
    _stand_in(monkeypatch, py={"cb": ODD_PY[odd](before)})
    g = build_graph(repo, typecheck=True)
    assert _shape(g) == _shape(before)
    assert _site(g, "cb")["reason"] == "callback-parameter"


def test_a_call_into_the_language_or_a_library_is_said_so_but_not_where_it_may_be_the_projects_own(tmp_path, monkeypatch):
    repo = _write(tmp_path, TS_APP | PY_APP | MAYBE_OWN)
    before = build_graph(repo)
    for callee in ("self.client.get", "req.user.can"):
        assert _site(before, callee)["reason"] == "library-or-repo"
    _stand_in(monkeypatch,
              ts={"n.trim": {"where": "builtin", "name": "String.trim"},
                  "list[0].save": {"where": "library", "name": "notes-kit.Notes.save"},
                  "drop": {"where": "library", "name": "react.useState"},
                  "req.user.can": {"where": "library", "name": "passport.User.can"}},
              py={"name.strip": {"where": "builtin", "name": "str.strip"},
                  "cb": {"where": "library", "name": "requests.api.get"},
                  "self.client.get": {"where": "builtin", "name": "dict.get"}})
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {
        "n.trim": ("builtin", ["builtin:String.trim"]), "name.strip": ("builtin", ["builtin:str.strip"]),
        "list[0].save": ("external", ["ext:notes-kit.Notes.save"]), "cb": ("external", ["ext:requests.api.get"]),
        "drop": ("external", ["ext:react.useState"])}
    assert g.builtin_calls == before.builtin_calls + 2
    assert "n.trim" not in g.unresolved and "name.strip" not in g.unresolved
    for callee, lib in (("list[0].save", "ext:notes-kit.Notes.save"), ("cb", "ext:requests.api.get")):
        edges = [e for e in g.edges if e.src == _site(g, callee)["caller"] and e.dst == lib]
        assert len(edges) == 1 and (edges[0].via, edges[0].confidence) == ("typecheck", INFERRED), (callee, edges)
    assert not [e for e in g.edges if e.dst == "ext:react.useState"]      # React's own are named and not drawn
    # where Lantern's own reading said "this may be the project's function", no checker makes it a library's
    for callee in ("self.client.get", "req.user.can"):
        s, b = _site(g, callee), _site(before, callee)
        assert (s["outcome"], s["to"], s["via"], s["reason"]) == ("unresolved", [], b["via"], "library-or-repo")
        assert g.unresolved[callee] == before.unresolved[callee] == 1
    assert not [n for n in g.nodes if "passport" in n or n == "ext:builtins.dict.get"]
    assert g.meta["typecheck"]["typescript"]["left"] >= 1 and g.meta["typecheck"]["python"]["left"] >= 1
    assert g.meta["calls"]["written"]["total"] == before.meta["calls"]["written"]["total"]


def test_a_guess_by_method_name_that_a_checker_confirms_is_no_longer_called_a_guess(tmp_path, monkeypatch):
    """`items[0].shout()` is linked to the function the last line's guess by name already points at: one edge, and
    it now says who said so. Its twin: the guess nobody confirmed stays a guess."""
    repo = _write(tmp_path, {k: v for k, v in PY_APP.items() if k != "app/models.py"} | {
        "app/models.py": PY_APP["app/models.py"].replace("class Draft:\n    def shout(self) -> str:\n        return 'draft'\n", "")})
    before = build_graph(repo)
    guess = [e for e in before.edges if e.dst == SHOUT and e.kind == "calls"]
    assert len(guess) == 1 and guess[0].via == "unique-method-name", guess
    _stand_in(monkeypatch, py={"items[0].shout": _py(before, SHOUT)})
    g = build_graph(repo, typecheck=True)
    edges = [e for e in g.edges if e.dst == SHOUT and e.kind == "calls"]
    assert len(edges) == 1 and edges[0].via == "typecheck" and len(edges[0].lines) == len(guess[0].lines) + 1
    _stand_in(monkeypatch)
    g = build_graph(repo, typecheck=True)
    assert [e.via for e in g.edges if e.dst == SHOUT and e.kind == "calls"] == ["unique-method-name"]


# A value's type names a method. Whether that method is the code that runs is another matter: a method that only
# declares ("a subclass writes this") never is, and one a subclass replaces need not be.
TYPED_APP = {
    "app/__init__.py": "",
    "app/shapes.py": (
        "from abc import ABC, abstractmethod\n"
        "from typing import Protocol\n"
        "\n\n"
        "class Theme(ABC):\n"
        "    @abstractmethod\n"
        "    def paint(self, text: str) -> str:\n"
        "        \"\"\"What a theme does with a text.\"\"\"\n"
        "\n"
        "    def name(self) -> str:\n"
        "        return 'theme'\n"
        "\n"
        "    def width(self) -> int:\n"
        "        return 80\n"
        "\n\n"
        "class Dark(Theme):\n"
        "    def paint(self, text: str) -> str:\n"
        "        return 'dark ' + text\n"
        "\n\n"
        "class Light(Theme):\n"
        "    def paint(self, text: str) -> str:\n"
        "        return 'light ' + text\n"
        "\n"
        "    def name(self) -> str:\n"
        "        return 'light'\n"
        "\n\n"
        "class Later(Light):\n"
        "    def paint(self, text: str) -> str: ...\n"
        "\n\n"
        "class Message:\n"
        "    def body(self) -> bytes:\n"
        "        \"\"\"The bytes of the message.\"\"\"\n"
        "        raise NotImplementedError()\n"
        "\n\n"
        "class Shown(Protocol):\n"
        "    def show(self) -> str: ...\n"
        "\n\n"
        "class Card:\n"
        "    def show(self) -> str:\n"
        "        return 'card'\n"
        "\n\n"
        "def todo(text: str) -> str:\n"
        "    raise NotImplementedError\n"),
    "app/use.py": (
        "from app.shapes import Message, Shown, Theme\n"
        "\n\n"
        "def run(themes: list[Theme], messages: list[Message], shown: list[Shown], cb=None):\n"
        "    themes[0].paint('a')\n"
        "    themes[0].name()\n"
        "    themes[0].width()\n"
        "    messages[0].body()\n"
        "    shown[0].show()\n"
        "    cb('a')\n"),
}
T_PAINT, T_NAME, T_WIDTH = "py:app.shapes.Theme.paint", "py:app.shapes.Theme.name", "py:app.shapes.Theme.width"
DARK_PAINT, LIGHT_PAINT, LATER_PAINT = "py:app.shapes.Dark.paint", "py:app.shapes.Light.paint", "py:app.shapes.Later.paint"
LIGHT_NAME, BODY, SHOW, TODO = "py:app.shapes.Light.name", "py:app.shapes.Message.body", "py:app.shapes.Shown.show", "py:app.shapes.todo"
TYPED_SAYS = {
    # only declared in the class the type names: the methods that replace it, each one possible, and not the
    # placeholder itself nor a subclass's that is a placeholder again
    "themes[0].paint": ("possible", [DARK_PAINT, LIGHT_PAINT]),
    # written in the class the type names and replaced by a subclass: either may run
    "themes[0].name": ("possible", [T_NAME, LIGHT_NAME]),
    # written there and replaced by nobody
    "themes[0].width": ("likely", [T_WIDTH]),
}
TYPED_LEFT = ("messages[0].body", "shown[0].show")      # only declared, and no class of the project writes it beneath


def _typed_edges(g):
    return sorted((e.dst, e.confidence, e.via) for e in g.edges if e.src == "py:app.use.run" and e.kind == "calls")


def test_a_method_that_only_declares_is_never_the_likely_one_and_what_replaces_it_is_possible(tmp_path, monkeypatch):
    """Measured on five public Python projects: of 60 links through a value's type read by hand, 12 led to a
    method that only declares (abstract, a body of `...`, `raise NotImplementedError`) and 1 to one that the
    project's default subclass replaces. The checker is right about the type; the code that runs is beneath it."""
    repo = _write(tmp_path, TYPED_APP)
    before = build_graph(repo)
    for callee in (*TYPED_SAYS, *TYPED_LEFT, "cb"):
        assert _site(before, callee)["outcome"] == "unresolved", callee
    _stand_in(monkeypatch, py={"themes[0].paint": _py(before, T_PAINT), "themes[0].name": _py(before, T_NAME),
                               "themes[0].width": _py(before, T_WIDTH), "messages[0].body": _py(before, BODY),
                               "shown[0].show": _py(before, SHOW), "cb": _py(before, TODO, direct=True)})
    g = build_graph(repo, typecheck=True)
    # the name written at the call names the function itself: it is what runs, whatever its body says
    assert _by_checker(g) == TYPED_SAYS | {"cb": ("resolved", [TODO])}
    # the method the checker named is the checker's word; one that replaces it is Lantern's own addition, a guess
    # among several, under the name such a link has when Lantern's own reading makes it (`self.method()`)
    assert _typed_edges(g) == sorted([(DARK_PAINT, "possible", "override"), (LIGHT_PAINT, "possible", "override"),
                                      (T_NAME, INFERRED, "typecheck"), (LIGHT_NAME, "possible", "override"),
                                      (T_WIDTH, INFERRED, "typecheck"), (TODO, RESOLVED, "typecheck")])
    for callee in TYPED_LEFT:
        was, now = _site(before, callee), _site(g, callee)
        assert (now["outcome"], now["reason"], now["to"], now["via"]) == ("unresolved", was["reason"], [], was["via"])
    part = g.meta["typecheck"]["python"]
    assert (part["linked"], part["likely"], part["possible"], part["declared"], part["left"]) == (1, 1, 2, 2, 0), part
    # one call is still one call, whatever number of functions it may lead to
    was, now = before.meta["calls"]["written"], g.meta["calls"]["written"]
    assert now["total"] == was["total"] and sum(now["outcomes"].values()) == now["total"]
    assert now["outcomes"]["unresolved"] == was["outcomes"]["unresolved"] - 4
    # the older count had counted one of these calls (the call on a parameter) and gives it up
    assert (dict(before.unresolved), dict(g.unresolved)) == ({"cb": 1}, {})
    # and the run says how many calls were given several possible functions, apart from the likely ones
    assert "4 linked into the project (1 confirmed, 1 likely, 2 to one of several that may run)" in \
        typecheck.line_words(g.meta["typecheck"])
    assert ("4 were linked into the project on its word (1 confirmed, 1 likely, 2 to each function that may run "
            "where the type's own method only declares or a class beneath it writes it anew)") in \
        typecheck.limits(g.meta["typecheck"])[0]


def test_a_stand_in_of_the_tests_that_replaces_a_method_does_not_make_its_file_the_apps_own(tmp_path, monkeypatch):
    """A test's stand-in has the methods of what it stands in for, and while the tests run the app calls it. A link
    to it is a guess among several, also once the run saw it: the test file stays test code (`security`,
    2026-11-13). The twin: the same link under the checker's own name would count as the app running the file."""
    fake = "py:tests.test_theme.Fake.paint"
    repo = _write(tmp_path, TYPED_APP | {
        "app/__main__.py": "from app.use import run\n\nrun([], [], [])\n",
        "tests/test_theme.py": ("from app.shapes import Theme\n\n\nclass Fake(Theme):\n    def paint(self, text):\n"
                                "        return text\n\n\ndef test_it():\n    assert Fake().paint('a') == 'a'\n")})
    before = build_graph(repo)
    _stand_in(monkeypatch, py={"themes[0].paint": _py(before, T_PAINT)})
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {"themes[0].paint": ("possible", [DARK_PAINT, LIGHT_PAINT, fake])}
    link = [e for e in g.edges if e.src == "py:app.use.run" and e.dst == fake]
    assert [(e.via, e.confidence) for e in link] == [("override", "possible")]

    def reached(via):
        link[0].confidence, link[0].via = "observed", via       # as the tests' own run marks a link it saw
        found = security.reachability(g, where=lambda n: not n.file.startswith("tests/"), worked_out=True,
                                      leave=lambda e: security.only_the_run_shows(e.via))
        assert "py:app.use.run" in found
        return fake in found
    assert reached("override+observed") is False
    assert reached("typecheck+observed") is True


DECLARES = {
    "abstract": "    @abstractmethod\n    def m(self):\n        return 1\n",
    "abstract-by-its-module": "    @abc.abstractmethod\n    def m(self):\n        \"\"\"Doc.\"\"\"\n",
    "three-dots": "    def m(self): ...\n",
    "three-dots-after-words": "    def m(self):\n        \"\"\"Doc.\"\"\"\n        ...\n",
    "not-implemented": "    def m(self):\n        raise NotImplementedError\n",
    "not-implemented-called": "    async def m(self):\n        \"\"\"Doc.\"\"\"\n        raise NotImplementedError('write me')\n",
    "one-of-several-signatures": "    @overload\n    def m(self): ...\n",
    # Python's own reader cannot read it, so what it does is not known: no link is made on a guess
    "not-read": "    def m(self):\n        print 'old'\n",
}
WRITTEN = {
    "words-only": "    def m(self):\n        \"\"\"A hook that does nothing unless a subclass writes it.\"\"\"\n",
    "pass": "    def m(self):\n        pass\n",
    "returns": "    def m(self):\n        return None\n",
    "another-error": "    def m(self):\n        raise ValueError('no')\n",
    "dots-then-code": "    def m(self):\n        ...\n        return 1\n",
    "not-implemented-on-one-way": "    def m(self):\n        if self.x:\n            raise NotImplementedError\n        return 1\n",
    "another-decorator": "    @property_like\n    def m(self):\n        return 1\n",
    "text-that-says-so": "    def m(self):\n        return '@abstractmethod ... raise NotImplementedError'\n",
}


@pytest.mark.parametrize("shape", sorted(DECLARES) + sorted(WRITTEN))
def test_which_methods_only_declare_is_read_from_their_own_lines(tmp_path, monkeypatch, shape):
    body = (DECLARES | WRITTEN)[shape]
    repo = _write(tmp_path, {"app/__init__.py": "",
                             "app/kinds.py": "import abc\nfrom abc import abstractmethod\nfrom typing import overload\n"
                                             "\n\nclass Kind:\n    x = 1\n\n" + body,
                             "app/use.py": "from app.kinds import Kind\n\n\ndef run(kinds: list[Kind]):\n    kinds[0].m()\n"})
    before = build_graph(repo)
    assert _site(before, "kinds[0].m")["outcome"] == "unresolved"
    _stand_in(monkeypatch, py={"kinds[0].m": _py(before, "py:app.kinds.Kind.m")})
    g = build_graph(repo, typecheck=True)
    if shape in WRITTEN:
        assert _by_checker(g) == {"kinds[0].m": ("likely", ["py:app.kinds.Kind.m"])}
    else:
        assert _by_checker(g) == {} and _shape(g) == _shape(before)
        assert g.meta["typecheck"]["python"]["declared"] == 1


def test_a_method_replaced_in_more_classes_than_are_drawn_leaves_the_call_as_it_was(tmp_path, monkeypatch):
    many = typecheck.MOST_REPLACING + 1
    kinds = "class Kind:\n    def m(self):\n        return 0\n" + "".join(
        f"\n\nclass K{i}(Kind):\n    def m(self):\n        return {i}\n" for i in range(many))
    use = "from app.kinds import Kind\n\n\ndef run(kinds: list[Kind]):\n    kinds[0].m()\n"
    repo = _write(tmp_path / "many", {"app/__init__.py": "", "app/kinds.py": kinds, "app/use.py": use})
    before = build_graph(repo)
    _stand_in(monkeypatch, py={"kinds[0].m": _py(before, "py:app.kinds.Kind.m")})
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {} and g.meta["typecheck"]["python"]["declared"] == 1
    # the twin: one class fewer, and every one of them is drawn
    fewer = kinds[:kinds.rindex("\n\nclass ")]
    repo = _write(tmp_path / "fewer", {"app/__init__.py": "", "app/kinds.py": fewer, "app/use.py": use})
    before = build_graph(repo)
    _stand_in(monkeypatch, py={"kinds[0].m": _py(before, "py:app.kinds.Kind.m")})
    g = build_graph(repo, typecheck=True)
    outcome, to = _by_checker(g)["kinds[0].m"]
    assert outcome == "possible" and len(to) == many and to[0] == "py:app.kinds.Kind.m"


def test_a_checker_that_cannot_be_asked_changes_nothing_and_the_run_says_why(tmp_path, monkeypatch):
    repo = _write(tmp_path, TS_APP | PY_APP)
    before = build_graph(repo)
    _stand_in(monkeypatch, py={"cb": _py(before, MADE, direct=True)})

    def fails(tools, root, g, sites, limit):
        raise typecheck.Failed("the TypeScript compiler ended with an error (result 3)")
    monkeypatch.setattr(typecheck, "ask_typescript", fails)
    g = build_graph(repo, typecheck=True)
    ts = g.meta["typecheck"]["typescript"]
    assert ts == {"ran": False, "why": "the TypeScript compiler ended with an error (result 3)", "asked": 0,
                  "unresolved": len(_open(before, typecheck.JS_ENDINGS))}
    assert _by_checker(g) == {"cb": ("resolved", [MADE])}                  # the other checker's part is not lost
    assert [x for x in _shape(g)["sites"] if ".ts:" in x[0]] == [x for x in _shape(before)["sites"] if ".ts:" in x[0]]
    words = typecheck.line_words(g.meta["typecheck"])
    assert "the TypeScript compiler not asked: the TypeScript compiler ended with an error (result 3)" in words
    assert "pyright 8.8.8: " in words and "1 linked into the project (1 confirmed, 0 likely, 0 to one of several that may run)" in words
    # a checker this computer does not have: said, with how many calls were not asked, and nothing started
    missing = json.loads(json.dumps(TOOLS))
    missing["pyright"], missing["notes"]["python"] = None, "pyright was not found on this computer (somewhere)"
    monkeypatch.setattr(typecheck, "find", lambda root: missing)
    monkeypatch.setattr(typecheck, "ask_python", _never)
    g = build_graph(repo, typecheck=True)
    assert g.meta["typecheck"]["python"] == {"ran": False, "why": "pyright was not found on this computer (somewhere)",
                                             "asked": 0, "unresolved": len(_open(before, ".py"))}
    assert _shape(g) == _shape(before)


def test_a_checker_that_stopped_at_its_time_and_calls_over_the_most_are_said(tmp_path, monkeypatch):
    repo = _write(tmp_path, TS_APP)
    before = build_graph(repo)
    _stand_in(monkeypatch, ts={"save": _ts(before, SAVE), "again": _ts(before, HOOK)}, stopped="time")
    monkeypatch.setattr(typecheck, "MOST_SITES", 3)
    g = build_graph(repo, typecheck=True)
    part = g.meta["typecheck"]["typescript"]
    n = len(_open(before, typecheck.JS_ENDINGS))
    assert n > 3 and (part["asked"], part["not_asked"], part["stopped"]) == (3, n - 3, "time")
    assert _by_checker(g) == {"save": ("likely", [SAVE])}                  # `again` is past the most: not asked
    assert "stopped at its time limit" in typecheck.line_words(g.meta["typecheck"])
    lines = typecheck.limits(g.meta["typecheck"])
    assert len(lines) == 1 and "stopped at its time limit" in lines[0] and f"{n - 3} calls over the most" in lines[0]


def test_asked_twice_the_answer_is_the_same_also_with_work_kept_between_runs(tmp_path, monkeypatch):
    repo = _write(tmp_path, TS_APP | PY_APP)
    before = build_graph(repo)
    table = {"ts": {"save": _ts(before, SAVE), "n.trim": {"where": "builtin", "name": "String.trim"}},
             "py": {"tidy": _py(before, TIDY, direct=True)}}
    _stand_in(monkeypatch, **table)
    first = build_graph(repo, typecheck=True)
    again = build_graph(repo, typecheck=True)
    assert _shape(first) == _shape(again) and len(_by_checker(first)) == 3
    assert _shape(build_graph(repo, typecheck=False)) == _shape(before)     # and a run that does not ask is as it was


def test_the_time_a_checker_gets_is_the_persons_setting_within_bounds(monkeypatch):
    for word, want in ((None, 120), ("", 120), ("x", 120), ("3", 5), ("60", 60), ("99999", 1800), ("-4", 5)):
        if word is None:
            monkeypatch.delenv("LANTERN_TYPECHECK_SECONDS", raising=False)
        else:
            monkeypatch.setenv("LANTERN_TYPECHECK_SECONDS", word)
        assert typecheck.seconds() == want, word


RAW = {"file": "app/store.ts", "lines": [6, 5], "name": "save", "container": None, "kind": "ArrowFunction",
       "what": "function", "body": True, "lib": None, "pkg": None}


@pytest.mark.parametrize("decl,direct,want", [
    (RAW, False, {"where": "project", "file": "app/store.ts", "lines": [6, 5], "name": "save", "what": "function",
                  "direct": False}),
    (RAW, True, {"where": "project", "file": "app/store.ts", "lines": [6, 5], "name": "save", "what": "function",
                 "direct": True}),
    (RAW, "yes", {"where": "project", "file": "app/store.ts", "lines": [6, 5], "name": "save", "what": "function",
                  "direct": False}),                                             # only `true` is the name itself
    (RAW | {"kind": "ClassDeclaration", "what": "class", "name": "MemoryNotes"}, False,
     {"where": "project", "file": "app/store.ts", "lines": [6, 5], "name": "MemoryNotes", "what": "class", "direct": False}),
    # a written type is no function: an interface's method, a parameter's function type, a declaration file's
    (RAW | {"kind": "MethodSignature", "body": False, "container": "Notes"}, False, {"where": "declared"}),
    (RAW | {"kind": "FunctionType", "name": None}, False, {"where": "declared"}),
    (RAW | {"body": False}, False, {"where": "declared"}),
    (RAW | {"lib": "declared", "file": "app/types.d.ts"}, False, {"where": "declared"}),
    (RAW | {"lib": "builtin", "container": "String", "name": "trim"}, False, {"where": "builtin", "name": "String.trim"}),
    (RAW | {"lib": "builtin", "container": None, "name": "parseInt"}, False, {"where": "builtin", "name": "parseInt"}),
    (RAW | {"lib": "builtin", "container": None, "name": None}, False, None),
    (RAW | {"lib": "library", "pkg": "express", "container": "Response", "name": "json"}, False,
     {"where": "library", "name": "express.Response.json"}),
    (RAW | {"lib": "library", "pkg": "../outside", "name": "json"}, False, None),
    (RAW | {"lib": "library", "pkg": "a b", "name": "json"}, False, None),
    (RAW | {"lib": "library", "pkg": None, "name": "json"}, False, None),
    (None, False, None), ("app/store.ts", False, None), ([RAW], False, None),
])
def test_what_the_compilers_program_wrote_is_taken_by_its_shape(decl, direct, want):
    assert typecheck._ts_answer({"decl": decl, "why": None, "direct": direct}) == want
    assert typecheck._ts_answer(decl) is None and typecheck._ts_answer([{"decl": decl}]) is None


# ---- which checkers: never one that comes with the project ----

def _a_compiler(folder, version="6.0.2", marker=None):
    """A folder shaped like the TypeScript package. Its program leaves `marker` behind when anything loads it."""
    body = f"require('fs').writeFileSync({json.dumps(str(marker))}, 'loaded')\n" if marker else ""
    return _write(folder, {"package.json": json.dumps({"name": "typescript", "version": version}),
                           "lib/typescript.js": body + "module.exports = {}\n", "bin/tsc": "#!/usr/bin/env node\n"})


def _a_pyright(folder, version="1.1.414", marker=None):
    body = f"require('fs').writeFileSync({json.dumps(str(marker))}, 'loaded')\n" if marker else ""
    _write(folder, {"package.json": json.dumps({"name": "pyright", "version": version}), "langserver.index.js": body})
    return folder / "langserver.index.js"


def _only(monkeypatch, tmp_path, node=None, ts=None, py=None):
    """This computer has the checkers the test names and no other."""
    monkeypatch.setenv("PATH", str(tmp_path / "no-programs"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "no-cache"))
    for name, value in (("LANTERN_NODE", node), ("LANTERN_TYPESCRIPT", ts), ("LANTERN_PYRIGHT", py)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, str(value))


def test_checkers_outside_the_project_are_found_and_ones_inside_it_are_passed_by(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", TS_APP | PY_APP)
    node = _write(tmp_path / "tools", {"bin/node": "a program\n"}) / "bin" / "node"
    ts, py = _a_compiler(tmp_path / "tools/typescript"), _a_pyright(tmp_path / "tools/pyright")
    _only(monkeypatch, tmp_path, node, ts, py)
    found = typecheck.find(repo)
    assert found == {"node": str(node.resolve()), "typescript": str(ts.resolve()), "typescript_version": "6.0.2",
                     "pyright": str(py.resolve()), "pyright_version": "1.1.414", "passed": [],
                     "notes": {"typescript": None, "python": None}}
    # the same three inside the analyzed folder: none is used, and the run says it passed them by
    marker = tmp_path / "loaded.txt"
    mine = _write(repo, {"tools/node": "a program\n"}) / "tools" / "node"
    _only(monkeypatch, tmp_path, mine, _a_compiler(repo / "node_modules/typescript", marker=marker),
          _a_pyright(repo / "node_modules/pyright", marker=marker))
    found = typecheck.find(repo)
    assert (found["node"], found["typescript"], found["pyright"]) == (None, None, None)
    assert found["passed"] == ["node", "the TypeScript compiler", "pyright"]
    for lang in ("typescript", "python"):
        assert found["notes"][lang].startswith("node was not found on this computer")
        assert found["notes"][lang].endswith("one inside the analyzed folder was passed by")
    # node of the computer's own, a compiler and a pyright that came with the project
    _only(monkeypatch, tmp_path, node, repo / "node_modules/typescript", repo / "node_modules/pyright/langserver.index.js")
    found = typecheck.find(repo)
    assert found["node"] == str(node.resolve()) and (found["typescript"], found["pyright"]) == (None, None)
    assert found["notes"]["typescript"].startswith("the TypeScript compiler was not found on this computer")
    assert found["notes"]["typescript"].endswith("passed by") and found["notes"]["python"].endswith("passed by")
    # the whole pass there: nothing is started, nothing changes, and the result says why
    monkeypatch.setattr(typecheck, "_start", _never)
    before = build_graph(repo)
    g = build_graph(repo, typecheck=True)
    meta = g.meta["typecheck"]
    assert meta["passed_by"] == ["the TypeScript compiler", "pyright"]
    assert meta["typescript"]["ran"] is False and meta["python"]["ran"] is False
    assert meta["typescript"]["unresolved"] == len(_open(before, typecheck.JS_ENDINGS))
    assert _shape(g) == _shape(before) and not marker.exists()
    lines = typecheck.limits(meta)
    assert any("was not asked about" in x and "passed by" in x for x in lines)
    assert lines[-1].startswith("A copy of the TypeScript compiler, pyright inside the analyzed folder was passed by")


@posix_only
def test_a_link_outside_the_project_that_leads_into_it_is_a_checker_inside_it(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", TS_APP)
    node = _write(tmp_path / "tools", {"bin/node": "a program\n"}) / "bin" / "node"
    _a_compiler(repo / "vendor/typescript")
    (tmp_path / "tools" / "typescript").symlink_to(repo / "vendor/typescript")
    _only(monkeypatch, tmp_path, node, tmp_path / "tools" / "typescript")
    found = typecheck.find(repo)
    assert found["typescript"] is None and found["passed"] == ["the TypeScript compiler"]
    # the twin: the same link to a compiler that lies outside
    real = _a_compiler(tmp_path / "elsewhere/typescript")
    (tmp_path / "tools" / "typescript").unlink()
    (tmp_path / "tools" / "typescript").symlink_to(real)
    found = typecheck.find(repo)
    assert found["typescript"] == str(real.resolve()) and found["passed"] == []


def test_a_compiler_older_than_lantern_asks_is_not_used_and_the_run_says_which(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", TS_APP)
    node = _write(tmp_path / "tools", {"bin/node": "a program\n"}) / "bin" / "node"
    _only(monkeypatch, tmp_path, node, _a_compiler(tmp_path / "tools/typescript", version="4.9.5"))
    found = typecheck.find(repo)
    assert found["typescript"] is None and found["passed"] == []
    assert found["notes"]["typescript"] == ("the TypeScript compiler on this computer is version 4.9.5, and Lantern "
                                           "asks version 5.0 or newer")
    for version, used in (("5.0.4", True), ("6.0.2", True), ("next", False), ("x" * 60, False), ("6.0 beta", False)):
        _only(monkeypatch, tmp_path, node, _a_compiler(tmp_path / "tools" / f"ts-{len(version)}-{used}", version=version))
        assert (typecheck.find(repo)["typescript"] is not None) is used, version


# ---- the report, the command line, and checking a report again ----

def test_the_command_asks_the_report_says_so_and_a_report_starts_no_checker(tmp_path, monkeypatch, capsys):
    repo = _write(tmp_path / "p", TS_APP)
    out, plain = tmp_path / "out", tmp_path / "plain"
    before = build_graph(repo)
    _stand_in(monkeypatch, ts={"save": _ts(before, SAVE)})
    monkeypatch.delenv("LANTERN_TYPECHECK", raising=False)
    ran = []
    real = typecheck.run
    monkeypatch.setattr(typecheck, "run", lambda g, root: (ran.append(1), real(g, root))[1])
    assert main(["analyze", str(repo), "--out", str(plain), "--no-scan", "--offline"]) == 0
    assert ran == [] and "typecheck" not in json.loads((plain / "run.json").read_text(encoding="utf-8"))
    was = json.loads((plain / "evidence.json").read_text(encoding="utf-8"))
    assert "typecheck" not in was["payload"]["run"] and not any("type checker" in x for x in was["limits"])
    capsys.readouterr()
    assert main(["analyze", str(repo), "--out", str(out), "--no-scan", "--offline", "--typecheck"]) == 0
    said = capsys.readouterr().out
    assert ran == [1] and re.search(r"types +the TypeScript compiler 9\.9\.9: \d+ unresolved calls asked, 1 linked", said), said
    run = json.loads((out / "run.json").read_text(encoding="utf-8"))
    assert run["typecheck"]["typescript"]["likely"] == 1 and run["typecheck"]["asked"] is True
    sites = json.loads((out / "calls.json").read_text(encoding="utf-8"))["sites"]
    assert [(s["callee"], s["to"]) for s in sites if s["via"] == "typecheck"] == [("save", [SAVE])]
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert ev["payload"]["run"]["typecheck"] == {"typescript": "9.9.9"} and ev["digest"] != was["digest"]
    assert {"tool": "typescript", "version": "9.9.9", "role": "type checker, asked for with --typecheck"} in ev["provenance"]["tools"]
    assert not any(t["tool"] in ("typescript", "pyright") for t in was["provenance"]["tools"])
    line = [x for x in ev["limits"] if x.startswith("Links from a type checker.")]
    assert len(line) == 1 and "The TypeScript compiler 9.9.9" in line[0] and "1 were linked into the project" in line[0]
    page = (out / "evidence.html").read_text(encoding="utf-8")
    assert "type checker, asked for with --typecheck" in page and "Links from a type checker." in page
    # checking the report again: a report does not start a checker, the person does, with the same word
    ran.clear()
    assert main(["verify", str(repo), "--report", str(out / "evidence.html"), "--offline"]) == 2
    err = capsys.readouterr().err
    assert ran == [] and "--typecheck" in err and "does not start them because a report says so" in err
    # the connector starts no checker either: it hands the refusal on, with the command a person would type
    from lantern.mcp_server import Projects, Server
    answer = Server(Projects([str(repo)])).handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "lantern_verify", "arguments": {"project": repo.name, "report": str(out / "evidence.json"), "offline": True}}})
    told = answer["result"]["content"][0]["text"]
    assert ran == [] and "--typecheck" in told and answer["result"]["structuredContent"].get("typecheck") is True, answer
    assert main(["verify", str(repo), "--report", str(out / "evidence.html"), "--offline", "--typecheck"]) == 0
    assert ran == [1]
    monkeypatch.setenv("LANTERN_TYPECHECK", "1")        # the person's standing word counts as the flag does
    assert main(["verify", str(repo), "--report", str(out / "evidence.html"), "--offline"]) == 0
    # a report made without the pass is checked without it, whatever is asked for now
    ran.clear()
    assert main(["verify", str(repo), "--report", str(plain / "evidence.html"), "--offline", "--typecheck"]) == 0
    assert ran == []
    # another compiler than the report's: the results are not the same results
    monkeypatch.setattr(typecheck, "find", lambda root: json.loads(json.dumps(TOOLS)) | {"typescript_version": "9.9.8"})
    monkeypatch.setattr(typecheck, "ask_typescript", lambda tools, root, g, sites, limit: {
        "version": tools["typescript_version"], "answers": [None] * len(sites), "stopped": None})
    assert main(["verify", str(repo), "--report", str(out / "evidence.html"), "--offline", "--typecheck"]) == 1


def test_a_record_read_back_from_a_file_is_taken_by_its_shape():
    odd = {"asked": True, "passed_by": ["node", "<b>x</b>", 7],
           "typescript": {"ran": True, "version": "<script>", "asked": "many", "likely": -4, "linked": True, "builtin": 2},
           "python": {"ran": False, "why": ["x"], "unresolved": 3}}
    assert typecheck.versions(odd) == {}
    assert typecheck.rows(odd) == [
        {"tool": "typescript", "version": None, "role": "type checker, asked for with --typecheck"},
        {"tool": "pyright", "version": None, "role": "type checker, asked for with --typecheck", "status": "not asked"}]
    lines = typecheck.limits(odd)
    assert len(lines) == 3 and "<" not in "".join(lines)
    assert "of a version it did not tell" in lines[0] and "asked where 0 " in lines[0] and "0 were linked" in lines[0]
    assert lines[1].endswith("was not asked about 3 unresolved Python calls.")
    assert lines[2].startswith("A copy of node inside the analyzed folder")
    for none in (None, [], "x", {}, {"asked": "yes"}, {"asked": False, "typescript": {"ran": True, "version": "1"}}):
        assert typecheck.versions(none) == {} and typecheck.rows(none) == [] and typecheck.limits(none) == []
        assert typecheck.line_words(none) is None


# ---- the second part: a program in the checker's place (POSIX) ----

SH_NODE = """#!/bin/sh
# a stand-in for node: it takes the question and answers with what the test wrote beside it
here=${0%/*}
/bin/cat > /dev/null
if [ -f "$here/wait" ]; then /bin/sleep 20; fi
/bin/cat "$here/answer"
read result < "$here/result"
exit "$result"
"""


def _a_node(folder, answer, result=0, wait=False):
    _write(folder, {"node": SH_NODE, "answer": answer if isinstance(answer, str) else json.dumps(answer),
                    "result": f"{result}\n"} | ({"wait": ""} if wait else {}))
    (folder / "node").chmod(0o755)
    return {**json.loads(json.dumps(TOOLS)), "node": str(folder / "node")}


def _raw(sites, **by_callee):
    return {"version": "9.9.9", "files": 2, "stopped": None,
            "results": [{"decl": by_callee.get(s["callee"]), "why": None, "direct": False} for s in sites]}


@posix_only
def test_the_compilers_program_is_asked_once_and_what_it_wrote_is_read(tmp_path):
    repo = _write(tmp_path / "p", TS_APP)
    g = build_graph(repo)
    sites = _open(g, typecheck.JS_ENDINGS)
    tools = _a_node(tmp_path / "bin", _raw(sites, save=RAW | {"lines": [g.nodes[SAVE].start_line]}))
    got = typecheck.ask_typescript(tools, repo, g, sites, 30)
    assert got["version"] == "9.9.9" and got["stopped"] is None and len(got["answers"]) == len(sites)
    said = dict(zip([s["callee"] for s in sites], got["answers"]))
    assert said["save"]["where"] == "project" and said["save"]["file"] == "app/store.ts"
    assert [k for k, v in said.items() if v is not None] == ["save"]


@posix_only
@pytest.mark.parametrize("answer,result,why", [
    ({"results": []}, 3, "the TypeScript compiler ended with an error (result 3)"),
    ("Segmentation fault", 0, "the TypeScript compiler's answer could not be read"),
    ("", 0, "the TypeScript compiler's answer could not be read"),
    ("[" * 200_000, 0, "the TypeScript compiler's answer could not be read"),
    ({"results": []}, 0, "the TypeScript compiler's answer has another shape than Lantern asked for"),
    ({"results": "all of them"}, 0, "the TypeScript compiler's answer has another shape than Lantern asked for"),
    (["results"], 0, "the TypeScript compiler's answer has another shape than Lantern asked for"),
])
def test_a_compiler_that_fails_or_writes_something_else_is_no_answer(tmp_path, monkeypatch, answer, result, why):
    repo = _write(tmp_path / "p", TS_APP)
    before = build_graph(repo)
    tools = _a_node(tmp_path / "bin", answer, result)
    with pytest.raises(typecheck.Failed) as e:
        typecheck.ask_typescript(tools, repo, before, _open(before, typecheck.JS_ENDINGS), 30)
    assert str(e.value) == why
    # the whole pass with that compiler: nothing changes, and the run says why in Lantern's own words
    monkeypatch.setattr(typecheck, "find", lambda root: tools)
    g = build_graph(repo, typecheck=True)
    assert _shape(g) == _shape(before)
    assert g.meta["typecheck"]["typescript"]["why"] == why and "Segmentation" not in json.dumps(g.meta["typecheck"])


def _going(program) -> list[int]:
    """The processes of this computer that were started from `program` (Linux: read from /proc)."""
    found = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if str(program).encode() in Path("/proc", pid, "cmdline").read_bytes():
                    found.append(int(pid))
            except OSError:
                pass
    return found


@posix_only
def test_a_compiler_that_does_not_answer_is_ended_with_what_it_started(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", TS_APP)
    g = build_graph(repo)
    sites = _open(g, typecheck.JS_ENDINGS)
    tools = _a_node(tmp_path / "bin", _raw(sites), wait=True)
    monkeypatch.setattr(typecheck, "GRACE", 0.5)
    with pytest.raises(typecheck.Failed) as e:
        typecheck.ask_typescript(tools, repo, g, sites, 1)
    assert str(e.value) == "the TypeScript compiler did not answer in time"
    if sys.platform.startswith("linux"):
        assert _going(tmp_path / "bin" / "node") == []        # neither the stand-in nor the `sleep` it started


SH_SAYS = """#!/bin/sh
# says where and how it was started, and tries to write inside its folder and outside it
echo "cwd=$PWD"
echo "path=$PATH"
echo "home=$HOME"
echo "ctype=$LC_CTYPE"
echo "names=$(set | while IFS='=' read name rest; do case "$name" in [A-Z]*) printf '%s ' "$name" ;; esac; done)"
echo inside > "$PWD/inside.txt" && echo "inside=written"
(echo outside > "$1") 2>/dev/null && echo "outside=written"
exit 0
"""


@posix_only
def test_a_checker_starts_in_a_folder_of_lanterns_own_with_none_of_the_shells_variables(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", TS_APP | {"says": SH_SAYS})
    program, outside, heard = repo / "says", tmp_path / "outside.txt", tmp_path / "launcher.txt"
    program.chmod(0o755)
    for name, value in (("NODE_OPTIONS", "--require /x/y.js"), ("HTTPS_PROXY", "http://127.0.0.1:9"),
                        ("NODE_PATH", str(repo)), ("PYTHONPATH", str(repo)), ("TS_NODE_PROJECT", str(repo)),
                        ("PYRIGHT_PYTHON_FORCE_VERSION", "latest"), ("A_SETTING_OF_THE_SHELL", "1"),
                        ("LC_CTYPE", "xx_YY.OF-THE-SHELL"), ("LANG", "xx_YY.OF-THE-SHELL")):
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(repo)
    work = typecheck._folder()
    try:
        with open(heard, "wb") as err:
            p = typecheck._start([str(program), str(outside)], work, 30, err)
            out, _ = p.communicate(b"", timeout=60)
            typecheck._end(p)
        said = dict(line.split("=", 1) for line in out.decode("utf-8").splitlines())
        assert p.returncode == 0 and said["cwd"] == str(work) and said["home"] == str(work), (said, heard.read_text())
        assert not typecheck._within(work, repo.resolve()) and said["inside"] == "written"
        assert said["path"] == str(work / "empty") and os.listdir(work / "empty") == []
        mine = {"HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "PATH", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "NO_COLOR"}
        shells = {"PWD", "OLDPWD", "SHLVL", "IFS", "OPTIND", "PS1", "PS2", "PS4", "PPID", "LINENO", "BASH", "BASHOPTS",
                  "BASHPID", "BASH_ALIASES", "BASH_ARGC", "BASH_ARGV", "BASH_CMDS", "BASH_LINENO", "BASH_SOURCE",
                  "BASH_VERSINFO", "BASH_VERSION", "DIRSTACK", "EUID", "GROUPS", "HOSTNAME", "HOSTTYPE", "MACHTYPE",
                  "OSTYPE", "PIPESTATUS", "POSIXLY_CORRECT", "SHELL", "SHELLOPTS", "TERM", "UID", "BASH_EXECUTION_STRING",
                  "BASH_ARGV0", "BASH_LOADABLES_PATH", "BASH_SUBSHELL", "COLUMNS", "LINES", "OPTERR", "RANDOM", "SECONDS",
                  "EPOCHREALTIME", "EPOCHSECONDS", "SRANDOM", "HISTCMD", "FUNCNAME", "COMP_WORDBREAKS", "MAILCHECK"}
        left = {n for n in said["names"].split() if n not in mine | shells and not n.startswith("LANTERN_SANDBOX_")}
        # the launcher is a Python program started with no locale, and Python then names UTF-8 for what it starts
        # (PEP 538): that one name is Python's own word, never the shell's
        assert left - {"LC_CTYPE"} == set() and said["ctype"] in ("", "C.UTF-8", "C.utf8", "UTF-8"), (left, said["ctype"])
        if "sandbox: Landlock on" in heard.read_text(encoding="utf-8"):
            assert "outside" not in said and not outside.exists()      # it writes in its own folder and nowhere else
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


PY_SERVER = r'''"""A stand-in for pyright's language server: it answers every question with the one place written beside it."""
import json
import sys
from pathlib import Path

plan = json.loads((Path(__file__).resolve().parent / "plan.json").read_text(encoding="utf-8"))
out = sys.stdout.buffer


def read():
    length = 0
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    return json.loads(sys.stdin.buffer.read(length))


def send(msg):
    body = json.dumps(msg).encode("utf-8")
    out.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    out.flush()


root, watched, asked = None, None, 0
while True:
    m = read()
    if m is None or m.get("method") == "exit":
        break
    method, ident = m.get("method"), m.get("id")
    if method == "initialize":
        root, watched = m["params"]["rootUri"], m["params"].get("processId")
        send({"jsonrpc": "2.0", "id": ident, "result": {"capabilities": {}}})
    elif method == "textDocument/definition":
        asked += 1
        # as the real server does every three seconds: it looks whether the process named as its starter is
        # still there, and where it is not let look at that process it takes it for gone and ends
        if plan.get("watches") and watched is not None:
            sys.exit(1)
        if plan.get("ends_at") == asked:
            sys.exit(3)
        if plan.get("writes") and asked == 2:
            out.write(plan["writes"].encode("utf-8"))
            out.flush()
            continue
        to = plan["to"]
        send({"jsonrpc": "2.0", "id": ident, "result": [
            {"uri": root + "/src/" + to["file"], "range": {"start": {"line": to["line"], "character": to["char"]}}}]})
    elif ident is not None:
        send({"jsonrpc": "2.0", "id": ident, "result": None})
'''
SHOUT_AT = {"file": "app/models.py", "line": 4, "char": 8}      # `    def shout(self) -> str:`, counted from 0


def _a_server(folder, **plan):
    """A stand-in for pyright: `node` is a script that starts the stand-in server whatever it is handed."""
    _write(folder, {"server.py": PY_SERVER, "plan.json": json.dumps({"to": SHOUT_AT} | plan),
                    "node": f'#!/bin/sh\nexec "{sys.executable}" -I "{folder}/server.py"\n',
                    "pyright/langserver.index.js": ""})
    (folder / "node").chmod(0o755)
    return {**json.loads(json.dumps(TOOLS)), "node": str(folder / "node"),
            "pyright": str(folder / "pyright" / "langserver.index.js")}


@posix_only
def test_pyrights_server_is_asked_over_its_pipes_and_what_it_wrote_is_read(tmp_path):
    repo = _write(tmp_path / "p", PY_APP)
    g = build_graph(repo)
    sites = _open(g, ".py")
    got = typecheck.ask_python(_a_server(tmp_path / "bin"), repo, g, sites, 60)
    assert got["version"] == "8.8.8" and got["stopped"] is None and len(got["answers"]) == len(sites) > 3
    for s, a in zip(sites, got["answers"]):
        assert a == {"where": "project", "file": "app/models.py", "line": 5, "name": "shout", "what": "function",
                     "direct": "." not in s["callee"]}, (s["callee"], a)


@posix_only
def test_a_server_that_looks_for_the_process_that_started_it_is_named_none(tmp_path, monkeypatch):
    """pyright's server looks every three seconds whether the process named to it as its starter is still there,
    and ends when it cannot see it. Behind the launcher's walls it is not let look at a process outside them: on a
    real project it ended three seconds in, with most calls not asked. So it is named no process. Its pipes end
    with Lantern, and the launcher ends what Lantern leaves."""
    repo = _write(tmp_path / "p", PY_APP)
    g = build_graph(repo)
    sites = _open(g, ".py")
    monkeypatch.setattr(typecheck, "ONE_ANSWER", 3)
    got = typecheck.ask_python(_a_server(tmp_path / "bin", watches=True), repo, g, sites, 60)
    assert got["stopped"] is None and all(a and a["where"] == "project" for a in got["answers"])


@posix_only
@pytest.mark.parametrize("plan, why", [
    ({"ends_at": 2}, "pyright ended before it had answered every call"),
    ({"writes": "Content-Length: 99999999999\r\n\r\n"}, "pyright's answer could not be read"),
    ({"writes": "Content-Length: 5\r\n\r\nhello"}, "pyright's answer could not be read"),
    ({"writes": "Content-Length: 2\r\n\r\n[]" * 3 + "Content-Length: x\r\n\r\n"}, "pyright's answer could not be read"),
], ids=["ends", "too-long", "no-json", "no-number"])
def test_a_server_that_ends_or_writes_something_else_is_no_answer_and_is_not_waited_for(tmp_path, monkeypatch, plan, why):
    repo = _write(tmp_path / "p", PY_APP)
    g = build_graph(repo)
    sites = _open(g, ".py")
    tools = _a_server(tmp_path / "bin", **plan)
    monkeypatch.setattr(typecheck, "ONE_ANSWER", 40)
    began = time.monotonic()
    with pytest.raises(typecheck.Failed) as e:
        typecheck.ask_python(tools, repo, g, sites, 120)
    assert str(e.value) == why
    assert time.monotonic() - began < 30        # nobody waits out an answer's time for a program that is gone
    if sys.platform.startswith("linux"):
        assert _going(tmp_path / "bin" / "server.py") == []
    # through the pass: no call is placed by the answers it did give, and the run says why
    monkeypatch.setattr(typecheck, "find", lambda root: tools)
    after = build_graph(repo, typecheck=True)
    assert _shape(after) == _shape(g) and not _by_checker(after)
    assert after.meta["typecheck"]["python"] == {"ran": False, "why": why, "asked": 0, "unresolved": len(sites)}


# ---- the third part: the real checkers, where the run names them ----

@pytest.fixture
def real(request, tmp_path_factory):
    """The checkers of this computer, as Lantern finds them. -> a function: the tools, or the test is skipped (or,
    under LANTERN_TESTS_TYPECHECK=required, failed) with why that language cannot be asked here."""
    def tools(lang):
        found = typecheck.find(tmp_path_factory.mktemp("nothing"))
        why = found["notes"][lang]
        if why and WANTED == "required":
            pytest.fail(f"LANTERN_TESTS_TYPECHECK=required, and {why}")
        if why:
            pytest.skip(f"no checker to start: {why}")
        ran = getattr(request.config, "_lantern_ran_against", None)
        if ran is None:
            ran = request.config._lantern_ran_against = {}
        tool = "typescript" if lang == "typescript" else "pyright"
        ran[tool] = f"{found[tool + '_version']} (node at {found['node']})"
        return found
    return tools


TS_SAYS = {"save": ("likely", [SAVE]), "drop": ("likely", [DROP]), "mk().save": ("likely", [KEPT]),
           "list[0].save": ("likely", [KEPT]), "m.save": ("likely", [KEPT]), "again": ("likely", [HOOK]),
           "n.trim": ("builtin", ["builtin:String.trim"]), "s.toUpperCase": ("builtin", ["builtin:String.toUpperCase"])}
PY_SAYS = {"items[0].shout": ("likely", [SHOUT]), "tidy": ("resolved", [TIDY]),
           "name.strip": ("builtin", ["builtin:str.strip"]), "text.strip": ("builtin", ["builtin:str.strip"]),
           "self.text.upper": ("builtin", ["builtin:str.upper"])}


def _same_counts(before, g):
    was, now = before.meta["calls"]["written"], g.meta["calls"]["written"]
    assert now["total"] == was["total"] and sum(now["outcomes"].values()) == now["total"]
    assert sum(g.unresolved.values()) + g.builtin_calls <= sum(before.unresolved.values()) + before.builtin_calls


@needs_checkers
def test_the_typescript_compiler_places_calls_on_values_whose_type_it_knows(tmp_path, real):
    tools = real("typescript")
    repo = _write(tmp_path / "p", TS_APP)
    before = build_graph(repo)
    g = build_graph(repo, typecheck=True)
    part = g.meta["typecheck"]["typescript"]
    assert part["ran"] is True and part["stopped"] is None and part["version"] == tools["typescript_version"], part
    assert _by_checker(g) == TS_SAYS
    # a type alone names no function to link: an interface's method, a parameter that is a function
    for callee in ("notes.save", "mk", "pick", "shout"):
        assert (_site(g, callee)["outcome"], _site(g, callee)["reason"]) == ("unresolved", _site(before, callee)["reason"])
    assert (part["asked"], part["linked"], part["likely"], part["builtin"], part["library"], part["declared"], part["left"]) == \
        (12, 0, 6, 2, 0, 4, 0)
    _same_counts(before, g)
    assert [e.lines for e in g.edges if e.dst == KEPT and e.via == "typecheck"] == [[9, 11, 12]]


@needs_checkers
def test_pyright_places_calls_on_values_whose_type_it_knows(tmp_path, real):
    tools = real("python")
    repo = _write(tmp_path / "p", PY_APP)
    before = build_graph(repo)
    g = build_graph(repo, typecheck=True)
    part = g.meta["typecheck"]["python"]
    assert part["ran"] is True and part["stopped"] is None and part["version"] == tools["pyright_version"], part
    assert _by_checker(g) == PY_SAYS
    # a parameter and a name given a function are no function of their own
    for callee in ("cb", "again"):
        assert (_site(g, callee)["outcome"], _site(g, callee)["reason"]) == ("unresolved", _site(before, callee)["reason"])
    assert _site(g, "make_store().first().shout")["outcome"] == "name-only"      # a guess is not asked about
    _same_counts(before, g)


PLANTED = """#!/bin/sh
echo started >> "{marker}"
exit 1
"""


@needs_checkers
@posix_only
def test_a_program_named_python_is_never_started_by_the_checker(tmp_path, monkeypatch, real):
    """pyright asks whatever `python` it finds on its PATH where libraries are. The checker's PATH is an empty folder."""
    real("python")
    repo = _write(tmp_path / "p", PY_APP)
    marker = tmp_path / "started.txt"
    for name in ("python", "python3"):
        _write(tmp_path, {f"planted/{name}": PLANTED.format(marker=marker)})
        (tmp_path / "planted" / name).chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path / "planted") + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "planted"))
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == PY_SAYS and not marker.exists()
    if sys.platform.startswith("linux"):
        # the trap is live: with that folder on the checker's own PATH (and the launcher's write wall away, so the
        # planted program can leave its mark), pyright starts it
        bare = typecheck._env
        monkeypatch.setattr(typecheck, "_env", lambda work: bare(work) | {"PATH": str(tmp_path / "planted")})
        monkeypatch.setattr(typecheck, "_launch", lambda cmd, work, limit: cmd)
        build_graph(repo, typecheck=True)
        assert marker.exists()


@needs_checkers
@posix_only
def test_settings_stubs_and_an_environment_that_come_with_the_project_decide_nothing_for_pyright(tmp_path, real):
    real("python")
    twin = build_graph(_write(tmp_path / "twin", PY_APP), typecheck=True)
    marker = tmp_path / "started.txt"
    settings = {"stubPath": "decoy", "extraPaths": ["../outside", "decoy"], "venvPath": ".", "venv": ".venv",
                "include": ["decoy"], "exclude": ["app"], "ignore": ["app"], "typeshedPath": "decoy/typeshed",
                "pythonPath": ".venv/bin/python"}
    stub = "class Note:\n    def whisper(self) -> str: ...\n\n\ndef make_store() -> Note: ...\n"
    repo = _write(tmp_path / "p", PY_APP | {
        "pyrightconfig.json": json.dumps(settings),
        "pyproject.toml": "[tool.pyright]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in settings.items()),
        "decoy/app/models.pyi": stub, "typings/app/models.pyi": stub, "app/models.pyi": stub,
        "decoy/typeshed/stdlib/builtins.pyi": "class str:\n    def strap(self) -> str: ...\n",
        "decoy/typeshed/stdlib/VERSIONS": "builtins: 3.0-\n",
        ".venv/pyvenv.cfg": "home = /usr/bin\n", ".venv/bin/python": PLANTED.format(marker=marker),
        ".venv/bin/python3": PLANTED.format(marker=marker)})
    _write(tmp_path / "outside", {"app/models.py": "class Note:\n    def shout(self):\n        return 'outside'\n"})
    for name in ("python", "python3"):
        (repo / ".venv" / "bin" / name).chmod(0o755)
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == PY_SAYS == _by_checker(twin) and not marker.exists()
    assert {k: v for k, v in g.meta["typecheck"]["python"].items() if k != "seconds"} == \
        {k: v for k, v in twin.meta["typecheck"]["python"].items() if k != "seconds"}


@needs_checkers
@posix_only
def test_settings_plugins_and_a_compiler_that_come_with_the_project_decide_nothing_for_typescript(tmp_path, monkeypatch, real):
    real("typescript")
    twin = build_graph(_write(tmp_path / "twin", TS_APP), typecheck=True)
    marker = tmp_path / "loaded.txt"
    leaves = f"require('fs').writeFileSync({json.dumps(str(marker))}, 'loaded')\nmodule.exports = () => ({{}})\n"
    repo = _write(tmp_path / "p", TS_APP | {
        "tsconfig.json": json.dumps({
            "extends": "../outside/base.json", "include": ["../outside/**/*"], "files": ["../outside/store.ts"],
            "compilerOptions": {"plugins": [{"name": "planted-plugin"}, {"transform": "planted-plugin"}], "baseUrl": "..",
                                "paths": {"./store": ["outside/store.ts"], "*": ["outside/*"]}, "noLib": True,
                                "typeRoots": ["../outside/types"], "types": ["planted"], "rootDirs": ["../outside"]}}),
        "node_modules/planted-plugin/package.json": '{"name": "planted-plugin", "version": "1.0.0", "main": "index.js"}',
        "node_modules/planted-plugin/index.js": leaves,
        "node_modules/@types/planted/index.d.ts": "declare function save(text: string): void\n"})
    _a_compiler(repo / "node_modules/typescript", version="99.0.0", marker=marker)
    (repo / "node_modules" / ".bin").mkdir()
    (repo / "node_modules" / ".bin" / "tsc").symlink_to(repo / "node_modules/typescript/bin/tsc")
    (repo / "node_modules/typescript/bin/tsc").chmod(0o755)
    _write(tmp_path / "outside", {
        "base.json": '{"compilerOptions": {"plugins": [{"name": "planted-plugin"}]}}',
        "store.ts": "export function useNotes() { return { save: 1, drop: 2 } }\n",
        "types/planted/index.d.ts": "declare function drop(text: string): void\n"})
    monkeypatch.setenv("PATH", str(repo / "node_modules" / ".bin") + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(repo)
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == TS_SAYS == _by_checker(twin) and not marker.exists()
    assert g.meta["typecheck"].get("passed_by", []) in ([], ["the TypeScript compiler"])
    assert g.meta["typecheck"]["typescript"]["version"] == twin.meta["typecheck"]["typescript"]["version"] != "99.0.0"


KIT = ("export class Kit { go() { return 1 } }\n"
       "export function make(): Kit { return new Kit() }\n")
USES = ("import { make } from './linked'\n"
        "export function use(pick: () => ReturnType<typeof make>) {\n"
        "  const kit = pick()\n"
        "  kit.go()\n"
        "}\n")


@needs_checkers
@posix_only
def test_a_file_that_is_a_link_out_of_the_project_is_not_read_by_the_compiler(tmp_path, real):
    real("typescript")
    twin = build_graph(_write(tmp_path / "twin", {"package.json": "{}", "app/linked.ts": KIT, "app/use.ts": USES}),
                       typecheck=True)
    assert _by_checker(twin) == {"kit.go": ("likely", ["js:app/linked::Kit.go"])}
    # the file outside lies where a compiler that read it would take it for a library's, and Lantern would then
    # write the library's name down: so a compiler that was let through the link shows in the result
    repo = _write(tmp_path / "p", {"package.json": "{}", "app/use.ts": USES})
    _write(tmp_path / "outside", {"node_modules/kitlib/kit.ts": KIT})
    (repo / "app" / "linked.ts").symlink_to(tmp_path / "outside" / "node_modules" / "kitlib" / "kit.ts")
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {} and _site(g, "kit.go")["outcome"] == "unresolved"
    assert not [n for n in g.nodes if "Kit" in n or "kitlib" in n or "outside" in n or "linked" in n.split("::")[-1]]
    ts = g.meta["typecheck"]["typescript"]
    assert ts["ran"] is True and (ts["library"], ts["builtin"], ts["likely"], ts["linked"]) == (0, 0, 0, 0)


@needs_checkers
def test_a_checker_has_no_network(tmp_path, real):
    """Where this system lets the launcher make a network of its own (Linux), the checker is in one: a listener of
    this computer is out of its reach. Whether the system can is asked of the sandbox, not of this run's launcher,
    so a checker started with no launcher fails here and is not passed over."""
    from lantern import sandbox
    tools = real("typescript")
    cannot = sandbox.own_network()
    if cannot:
        pytest.skip("no network of the launcher's own on this system: " + cannot)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        port = listener.getsockname()[1]
        script = (f"const s = require('net').connect({port}, '127.0.0.1');"
                  "s.on('connect', () => { console.log('connected'); process.exit(0) });"
                  "s.on('error', (e) => { console.log('refused ' + e.code); process.exit(0) })")
        plain = subprocess.run([tools["node"], "-e", script], capture_output=True, text=True, timeout=60)
        assert plain.stdout.strip() == "connected", plain
        work, heard = typecheck._folder(), tmp_path / "launcher.txt"
        try:
            with open(heard, "wb") as err:
                p = typecheck._start([tools["node"], "-e", script], work, 30, err)
                out, _ = p.communicate(b"", timeout=60)
                typecheck._end(p)
        finally:
            import shutil
            shutil.rmtree(work, ignore_errors=True)
        said = heard.read_text(encoding="utf-8")
        assert "sandbox: a network of its own" in said and "could not be made" not in said, said
        assert out.decode("utf-8").strip().startswith("refused "), (out, said)
    finally:
        listener.close()


@needs_checkers
def test_pyright_still_answers_after_its_look_for_the_process_that_started_it(tmp_path, monkeypatch, real):
    """The real server's look comes three seconds after its start (see the stand-in's test above): a run that is
    still asking then gets its answers."""
    real("python")
    repo = _write(tmp_path / "p", PY_APP)
    took, waited = typecheck._py_answer, []

    def slow(*a, **k):
        if not waited:
            waited.append(1)
            time.sleep(3.6)
        return took(*a, **k)
    monkeypatch.setattr(typecheck, "_py_answer", slow)
    monkeypatch.setattr(typecheck, "ONE_ANSWER", 3)
    g = build_graph(repo, typecheck=True)
    assert waited and g.meta["typecheck"]["python"]["ran"] is True and _by_checker(g) == PY_SAYS


# A library with written types, installed in the project (`node_modules`), and a hook of it: what the hook hands back
# is typed by the library, so the compiler knows what a part taken out of it is.
HOOK_LIB = {
    "package.json": '{"dependencies": {"tinyquery": "1.0.0"}}',
    "node_modules/tinyquery/package.json": '{"name": "tinyquery", "version": "1.0.0", "types": "index.d.ts"}',
    "node_modules/tinyquery/index.d.ts": (
        "export interface QueryResult<T> { data: T; refetch(): void }\n"
        "export function useQuery<T>(load: () => T): QueryResult<T>\n"),
    "app/note.ts": (
        "export class Note { shout() { return 'x' } }\n"
        "export class Draft { shout() { return 'y' } }\n"
        "export function loadNote(): Note { return new Note() }\n"),
    "app/view.ts": (
        "import { useQuery } from 'tinyquery'\n"
        "import { loadNote } from './note'\n"
        "\n"
        "export function view() {\n"
        "  const { data, refetch } = useQuery(loadNote)\n"
        "  data.shout()\n"
        "  refetch()\n"
        "}\n"),
}


@needs_checkers
def test_what_a_typed_librarys_hook_hands_back_is_followed_into_the_project_and_into_the_library(tmp_path, real):
    """`const { data, refetch } = useQuery(loadNote)`: Lantern's own reading leaves `data.shout()` and `refetch()`
    unresolved (a part taken out of what a library call returned). The library's written types say what they are:
    `data` is what `loadNote` returns, a Note of the project, and `refetch` is the library's own. The twin: the same
    project with the library not installed, where the compiler knows neither and both calls stay as they were."""
    real("typescript")
    repo = _write(tmp_path / "p", HOOK_LIB)
    before = build_graph(repo)
    for callee in ("data.shout", "refetch"):
        assert _site(before, callee)["outcome"] == "unresolved"
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == {"data.shout": ("likely", ["js:app/note::Note.shout"]),
                              "refetch": ("external", ["ext:tinyquery.QueryResult.refetch"])}
    assert [(e.via, e.confidence) for e in g.edges if e.dst == "ext:tinyquery.QueryResult.refetch"] == [("typecheck", INFERRED)]
    _same_counts(before, g)
    twin = build_graph(_write(tmp_path / "twin", {k: v for k, v in HOOK_LIB.items() if not k.startswith("node_modules/")}),
                       typecheck=True)
    assert _by_checker(twin) == {} and twin.meta["typecheck"]["typescript"]["left"] == 2


@needs_checkers
def test_pyright_names_the_declared_method_and_lantern_draws_what_may_run(tmp_path, real):
    """The same project with the real pyright: it names `Theme.paint` for `themes[0].paint('a')`, which is right
    about the type and is not the code that runs."""
    real("python")
    repo = _write(tmp_path / "p", TYPED_APP)
    before = build_graph(repo)
    g = build_graph(repo, typecheck=True)
    assert _by_checker(g) == TYPED_SAYS
    for callee in (*TYPED_LEFT, "cb"):
        assert (_site(g, callee)["outcome"], _site(g, callee)["reason"]) == ("unresolved", _site(before, callee)["reason"])
    part = g.meta["typecheck"]["python"]
    assert (part["likely"], part["possible"], part["declared"]) == (1, 2, 3), part       # `cb` is a parameter: declared
    _same_counts(before, g)
