"""Which tests a project with none should get first, and a first test file for it (a firm pass or fail, stage 5,
step 3; the owner's answer of 2026-11-21: what a browser saw never counts in place of tests, so a project with no
tests stays Incomplete, and the release decision says which tests to write instead).

`to_write(g, sec)` reads them from what the code shows of each route (`websec.route_logins`, which `security.scan`
writes into security.json) and of the paid services it calls (`security["ai"]`): the sign-in, the changes only a
signed-in person may make, the changes anyone can make, the routes that reach a paid service, the routes that only
read, and the pages and screens (`KINDS`, in that order). A heuristic like the login rule it is shared with: it reads
names and shapes, not meaning, and it says what to test, never that something was tested.

`starter(g, items)` writes a first test file for a FastAPI app made in the code that Python can import
(`behave_init.app_of`, the app `lantern behave` starts): tests that hold for any app that works (each page answers
without an error of the server; a visitor who is not signed in cannot make a change the code shows needs a sign-in),
and the other tests of the list written out as still to write, because only the person knows what each must do.
Nothing of the project is run here. A route is put into the file only when it is plain (`PLAIN`), every value goes
in as a Python literal (`repr`), and a name that is no plain Python name stops the file (no file is better than one
that cannot load the app).
"""
from __future__ import annotations

import keyword
import re
import textwrap
import unicodedata

from .graph import Graph, route_words

NAME = "tests/test_first.py"
KINDS = ("sign-in", "signed-in-change", "open-change", "paid", "read", "page")
WORDS = {
    "sign-in": "the sign-in",
    "signed-in-change": "the changes only a signed-in person may make",
    "open-change": "the changes anyone can make, to say who may make them and what they accept",
    "paid": "the routes that reach a paid service, to say what one person's requests may cost",
    "read": "what each route that only reads answers",
    "page": "that each page and screen opens",
}
# the first test file's list of tests still to write: what each kind is called there, and what its tests ask
STILL = {
    "sign-in": ("the sign-in", "the right password signs in, a wrong one does not, and many wrong ones in a row are "
                               "slowed down"),
    "signed-in-change": ("each change a signed-in person makes", "a person changes only what is theirs, and a "
                                                                 "second account cannot"),
    "open-change": ("each change anyone can make", "who may make it, and what it refuses"),
    "paid": ("each route that reaches a paid service", "what one person's requests may cost, and what stops a "
                                                       "stranger from running up the bill"),
}
WIDTH = 100          # the first test file's lines
GENERAL = ("Write tests for the most important flows first (sign-in, payments, changes to data), then run them "
           "under Lantern.")
MOST_NAMED = 3       # places named of each kind in the words; the rest are counted
MOST_KEPT = 50       # items kept in the release record; the words count all of them
MOST_SHOWN = 120     # characters of a route's words kept
MOST_WALKED = 20_000     # functions walked from one route when looking for a paid call
PLAIN = re.compile(r"(GET|POST|PUT|PATCH|DELETE) (/[\w\-.~{}:%@+]*)+")    # what the first test file may name
PLAIN_FILE = re.compile(r"[\w\-./]{1,200}")
PARAM = re.compile(r"\{[^{}/]*\}")
SETTING = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,80}")
PLACE = re.compile(r"[\w.\-]{1,80}")


def shown(text: str) -> str:
    """A route's words as the record and the decision's words may hold them: no control or format characters (a
    line break, an escape, a character that turns text around), cut to `MOST_SHOWN`."""
    return "".join("?" if unicodedata.category(ch)[0] == "C" else ch for ch in text[:MOST_SHOWN])


def to_write(g: Graph, sec: dict | None) -> list[dict]:
    """The tests to write first, each {"kind", "where", "file", "line"}, in the order of `KINDS` and, inside a kind,
    in the order of the routes in the code. Routes in test code are not listed (`websec.route_logins`). `where`
    names the route as the readiness page's other lists do (`graph.route_words`): `POST /api/notes`, and a Server
    Action as "the Server Action save", never the map's own `ACTION save`."""
    from . import flow
    rows = [r for r in ((sec or {}).get("route_logins") or [])
            if isinstance(r, dict) and isinstance(r.get("detail"), str) and r["detail"]]
    out: dict[str, list[dict]] = {k: [] for k in KINDS}

    def add(kind: str, where: str, file, line) -> None:
        out[kind].append({"kind": kind, "where": shown(route_words(where)), "file": file if isinstance(file, str) else None,
                          "line": line if type(line) is int else None})

    paid = _reach_paid(g, sec, [r.get("node") for r in rows])
    for r in rows:
        detail = r["detail"]
        if r.get("changes") is True:
            kind = ("sign-in" if flow.sign_in_route(detail) else
                    "signed-in-change" if r.get("login") == "shown" else "open-change")
            add(kind, detail, r.get("file"), r.get("line"))
        elif detail.partition(" ")[0].upper() == "GET":
            add("read", detail, r.get("file"), r.get("line"))
        if r.get("node") in paid:
            add("paid", detail, r.get("file"), r.get("line"))
    for n in sorted(g.entry_points(), key=lambda n: (n.file or "", n.start_line or 0, n.id)):
        entry = n.entry or {}
        if entry.get("kind") == "page" and isinstance(entry.get("detail"), str) and entry["detail"]:
            add("page", entry["detail"], n.file, n.start_line)
    return [x for k in KINDS for x in out[k]]


def _reach_paid(g: Graph, sec: dict | None, starts: list) -> set:
    """The routes among `starts` (node ids) from which the map leads to a paid call (`aiapp.PAID_KINDS`)."""
    from .aiapp import PAID_KINDS
    from .websec import call_adjacency
    calls = ((sec or {}).get("ai") or {}).get("calls") if isinstance((sec or {}).get("ai"), dict) else None
    paid = {c["node"] for c in (calls or []) if isinstance(c, dict) and c.get("kind") in PAID_KINDS
            and isinstance(c.get("node"), str)}
    if not paid:
        return set()
    adj = call_adjacency(g)
    found = set()
    for start in starts:
        if not isinstance(start, str):
            continue
        seen, frontier = {start}, [start]
        hit = start in paid
        while frontier and not hit and len(seen) < MOST_WALKED:
            step = []
            for u in frontier:
                for v in adj.get(u, []):
                    if v not in seen:
                        seen.add(v)
                        step.append(v)
                        hit = hit or v in paid
            frontier = step
        if hit:
            found.add(start)
    return found


def words(items: list[dict], first: str | None = None) -> str:
    """The tests criterion's way forward for a project with no tests: the tests to write, `MOST_NAMED` places of
    each kind named and the rest counted, and the first test file where one is offered."""
    parts = []
    for kind in KINDS:
        where = [x["where"] for x in items if x.get("kind") == kind and isinstance(x.get("where"), str)]
        if where:
            parts.append(f"{WORDS[kind]} ({_listed(where)})")
    if not parts:
        return GENERAL
    return ("Write tests for these first, read from the code: " + "; ".join(parts) + ". Then run them under "
            "Lantern: `lantern analyze PATH --trace -- <your test command>`."
            + (f" Lantern can write a first test file for this project ({first}): `lantern starter PATH --write "
               f"{first}`, or the starter files in the app." if first else ""))


def _listed(where: list[str]) -> str:
    named, left = where[:MOST_NAMED], len(where) - MOST_NAMED
    if left > 0:
        return ", ".join(named) + f" and {left} more"
    return ", ".join(named[:-1]) + (" and " if len(named) > 1 else "") + named[-1]


def _name(text: str) -> bool:
    return text.isidentifier() and text.isascii() and not keyword.iskeyword(text)


def starter(g: Graph, items: list[dict]) -> dict | None:
    """The first test file ({"why", "content"}), or None where Lantern cannot write one that loads the app: no
    FastAPI app made in the code, a module or folder whose name is no plain Python name, or nothing it can test."""
    from . import behave_init
    found = behave_init.app_of(g)
    if found is None:
        return None
    app = found["app"]
    module, _, name = str(app.get("asgi") or "").partition(":")
    cwd = app.get("cwd") or ""
    if not module or not all(_name(p) for p in module.split(".")) or not _name(name):
        return None
    if cwd and not (isinstance(cwd, str) and all(PLACE.fullmatch(p) and p not in (".", "..") for p in cwd.split("/"))):
        return None
    mine = [x for x in items if str(x.get("file") or "").endswith(".py")]
    reads = sorted({x["where"].partition(" ")[2] for x in mine if x["kind"] == "read"
                    and PLAIN.fullmatch(x["where"]) and "{" not in x["where"]}, key=lambda p: (p.count("/"), p))
    signed = []
    for x in mine:
        if x["kind"] == "signed-in-change" and PLAIN.fullmatch(x["where"]):
            method, _, path = x["where"].partition(" ")
            if (method, PARAM.sub("1", path)) not in signed:
                signed.append((method, PARAM.sub("1", path)))
    if not reads and not signed:
        return None
    return {"why": "First tests, read from the code: each address that only reads answers without a server error, "
                   "and a visitor cannot make a change that needs a sign-in. The tests only you can write (the "
                   "sign-in, who may change what, the paid calls) are listed in it, still to write.",
            "content": _content(found, module, name, cwd, reads, signed, mine)}


def _content(found: dict, module: str, name: str, cwd: str, reads: list[str], signed: list[tuple],
             items: list[dict]) -> str:
    app = found["app"]
    settings, made = _settings(app.get("env") if isinstance(app.get("env"), dict) else {})
    head = ['"""First tests, written by Lantern from this project\'s code.', "",
            *textwrap.wrap("They check what holds for any app that works: each address that only reads answers "
                           "without an error of the server, and a visitor who is not signed in cannot make a change "
                           "that the code shows needs a sign-in. Lantern cannot know what the app must do beyond "
                           "that: the tests it could not write are listed at the end of this file. Write those "
                           "next.", WIDTH), "",
            *textwrap.wrap("Run them with `python -m pytest -q` in the project's folder, and under Lantern with "
                           "`lantern analyze . --trace -- python -m pytest -q`. They use FastAPI's TestClient "
                           "(FastAPI 0.87 or newer).", WIDTH),
            '"""', "import os"]
    if made:
        head.append("import secrets")
    if cwd:
        head += ["import sys", "from pathlib import Path"]
    head += ["", "import pytest", "from fastapi.testclient import TestClient", ""]
    if reads:
        head.append(f"READS = {reads!r}")
    if signed:
        head.append(f"SIGNED_IN_ONLY = {signed!r}")
    fixture = ["", "", '@pytest.fixture(scope="module")', "def client(tmp_path_factory):",
               '    data = tmp_path_factory.mktemp("app")     # the files the app writes during these tests: never yours']
    fixture += settings
    if cwd:
        fixture.append(f"    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / {cwd!r}))")
    where = found.get("file")
    said = (f"    # Lantern found the app in {where}, line {found['line']}"
            if isinstance(where, str) and PLAIN_FILE.fullmatch(where) and type(found.get("line")) is int else None)
    if said:
        fixture.append(said)
    if app.get("factory"):
        fixture += [f"    from {module} import {name}", "", f"    app = {name}()"]
    else:
        fixture.append(f"    from {module} import {name}" + ("" if name == "app" else " as app"))
    fixture += ["    with TestClient(app) as test_client:", "        yield test_client"]
    tests = []
    if reads:
        tests += ["", "", '@pytest.mark.parametrize("path", READS)',
                  "def test_each_address_that_only_reads_answers_without_a_server_error(client, path):",
                  "    assert client.get(path).status_code < 500, path"]
    if signed:
        tests += ["", "", '@pytest.mark.parametrize("method, path", SIGNED_IN_ONLY)',
                  "def test_a_visitor_cannot_make_a_change_that_needs_a_sign_in(client, method, path):",
                  "    answer = client.request(method, path, follow_redirects=False)",
                  "    assert not 200 <= answer.status_code < 300, (",
                  '        f"{method} {path} let a visitor in: it answered {answer.status_code}")']
    still = []
    for kind, (called, asks) in STILL.items():
        where = [x["where"] for x in items if x["kind"] == kind]
        if where:
            plain = [w for w in where if PLAIN.fullmatch(w)]
            named = _listed(plain) if plain else ""
            other = len(where) - len(plain)
            if other:
                named += (" and " if named else "") + f"{other} route{'s' if other > 1 else ''} whose path is not plain text"
            still += textwrap.wrap(f"{called} ({named}): {asks}", WIDTH, initial_indent="# - ",
                                   subsequent_indent="#   ", break_long_words=False, break_on_hyphens=False)
    if still:
        tests += ["", "", "# Still to write: Lantern found these in the code, and only you know what each must do.",
                  *still]
    return "\n".join(head + fixture + tests) + "\n"


def _settings(env: dict) -> tuple[list[str], bool]:
    """The settings the app reads, given places of the test's own (`behave_init._env`: a database, a folder) and a
    secret made each time the tests run, each set only where the computer does not set it already; and whether a
    secret is made (the file then imports `secrets`). The secret is never a text written down: one text here would be
    the same in every project the file is written for, a secret anyone can read."""
    out, made = [], False
    for setting, value in sorted(env.items()):
        if not (isinstance(setting, str) and SETTING.fullmatch(setting) and isinstance(value, str)):
            continue
        if value == "{secret}":
            out.append(f"    os.environ.setdefault({setting!r}, secrets.token_hex(32))")
            made = True
            continue
        for start in ("sqlite:///{data}/", "{data}/"):
            rest = value[len(start):] if value.startswith(start) else None
            if rest is None:
                continue
            if PLACE.fullmatch(rest) and rest not in (".", ".."):
                before = start[:-len("{data}/")]
                if "." not in rest:          # a folder (`behave_init._env`: a database's place ends in .db)
                    out.append(f"    (data / {rest!r}).mkdir(exist_ok=True)")
                value_code = (f"{before!r} + str(data / {rest!r})" if before else f"str(data / {rest!r})")
                out.append(f"    os.environ.setdefault({setting!r}, {value_code})")
            break
    return out, made
