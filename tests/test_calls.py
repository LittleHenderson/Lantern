"""The call-site inventory (2026-11-09 directive, stage 3): one record per call written in the code, with what
Lantern knows about its target and, when it knows nothing, why.

`Graph.call_sites()` counts edge lines, so one call with three possible targets counts three and a call nothing was
found for counts by its text. These tests pin the per-place count beside it: two calls on one line are two records,
one call with several targets is one record listing them, the outcomes add up to the calls found, and every
unresolved call says why. Safe twins sit beside the resolution cases: a call Lantern must not link stays unresolved,
with its reason, instead of being guessed."""

import json

import pytest

from lantern import calls
from lantern.engine import build_graph


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _g(tmp_path, files):
    _write(tmp_path, files)
    return build_graph(tmp_path)


def _written(g, file=None):
    return [s for s in g.sites if s["group"] == "written" and (file is None or s["file"] == file)]


def _one(g, callee, file=None, group="written"):
    hits = [s for s in g.sites if s["group"] == group and s["callee"] == callee and (file is None or s["file"] == file)]
    assert len(hits) == 1, (callee, hits)
    return hits[0]


# ---- one record per place ----

def test_two_calls_on_one_line_are_two_records(tmp_path):
    g = _g(tmp_path, {"app.py": "def a():\n    pass\n\n\ndef b():\n    pass\n\n\ndef run():\n    a(); b()\n"})
    line = [s for s in _written(g, "app.py") if s["line"] == 10]
    assert [s["callee"] for s in line] == ["a", "b"]
    assert len({s["at"] for s in line}) == 2
    assert [s["to"] for s in line] == [["py:app.a"], ["py:app.b"]]
    assert all(s["outcome"] == "resolved" and s["caller"] == "py:app.run" for s in line)
    assert g.meta["calls"]["written"]["lines_with_several_calls"] == 1


def test_one_call_with_several_targets_is_one_record(tmp_path):
    g = _g(tmp_path, {"shapes.py": (
        "class Shape:\n    def area(self):\n        return 0\n\n    def describe(self):\n        return self.area()\n\n\n"
        "class Square(Shape):\n    def area(self):\n        return 4\n\n\n"
        "class Circle(Shape):\n    def area(self):\n        return 3\n")})
    s = _one(g, "self.area")
    assert s["outcome"] == "possible"
    assert sorted(s["to"]) == ["py:shapes.Circle.area", "py:shapes.Shape.area", "py:shapes.Square.area"]
    # the edge-line count gives this one call three call sites, one per target edge
    old = g.call_sites()
    assert old["resolved_internal"] + old["several_possible_targets"] >= 3
    assert g.meta["calls"]["written"]["with_several_targets"] == 1


def test_calls_that_start_at_the_same_place_are_told_apart(tmp_path):
    g = _g(tmp_path, {"cars.py": (
        "class Car:\n    def go(self):\n        return 1\n\n\ndef make() -> Car:\n    return Car()\n\n\n"
        "def run():\n    return make().go()\n")})
    inner, outer = _one(g, "make"), _one(g, "make().go")
    assert inner["line"] == outer["line"] == 11 and inner["at"] != outer["at"]
    assert inner["at"] == "cars.py:11:16" and outer["at"] == "cars.py:11:21"   # where each call's "(" is (bytes, from 1)
    assert inner["outcome"] == "resolved" and outer["outcome"] == "likely" and outer["via"] == "return-type"


def test_outcomes_add_up_to_the_calls_found(tmp_path):
    g = _g(tmp_path, {"svc.py": (
        "import json\nimport requests\n\n\ndef helper():\n    return 1\n\n\n"
        "def run(client, items, cb):\n    helper()\n    requests.get('https://example.com')\n    len(items)\n"
        "    json.dumps({})\n    client.fetch_all()\n    cb()\n    nothere()\n    return ', '.join(items)\n")})
    got = {s["callee"]: (s["outcome"], s["reason"]) for s in _written(g, "svc.py")}
    assert got == {
        "helper": ("resolved", None),
        "requests.get": ("external", None),
        "len": ("builtin", None),
        "json.dumps": ("external", None),
        "client.fetch_all": ("unresolved", "parameter"),
        "cb": ("unresolved", "callback-parameter"),
        "nothere": ("unresolved", "not-defined"),
        "', '.join": ("builtin", None),
    }
    w = g.meta["calls"]["written"]
    assert w["total"] == 8 and sum(w["outcomes"].values()) == w["total"]
    assert w["outcomes"]["unresolved"] == 3
    assert w["reasons"] == {"parameter": 1, "callback-parameter": 1, "not-defined": 1}
    assert all(s["why"] for s in _written(g) if s["outcome"] == "unresolved")


@pytest.mark.parametrize("files,callee,reason", [
    ({"a.py": "def f(x):\n    return x.go()\n"}, "x.go", "parameter"),
    ({"a.py": "def f(cb):\n    return cb()\n"}, "cb", "callback-parameter"),
    ({"a.py": "def f():\n    return nothere()\n"}, "nothere", "not-defined"),
    ({"a.py": "HANDLERS = {}\n\n\ndef f(k):\n    return HANDLERS[k]()\n"}, "HANDLERS[k]", "computed"),
    ({"a.py": "def g():\n    return object()\n\n\ndef f():\n    return g().go()\n"}, "g().go", "call-result"),
    ({"a.py": "class A:\n    def f(self):\n        return self.nope()\n"}, "self.nope", "not-in-class"),
    ({"a.py": "class A:\n    def __init__(self, svc):\n        self.svc = svc\n\n    def f(self):\n        return self.svc.run()\n"},
     "self.svc.run", "self-attribute"),
    ({"settings.py": "def make_config():\n    pass\n\n\nCONFIG = make_config()\n",
      "a.py": "from settings import CONFIG\n\n\ndef f():\n    return CONFIG.load()\n"}, "CONFIG.load", "repo-variable"),
    ({"pkg/__init__.py": "", "pkg/tools.py": "def other():\n    pass\n",
      "a.py": "import pkg.tools as tools\n\n\ndef f():\n    return tools.missing()\n"}, "tools.missing", "missing-member"),
    ({"a.py": "def f(items):\n    for item in items:\n        item.ship()\n"}, "item.ship", "local-unknown"),
])
def test_every_unresolved_call_says_why(tmp_path, files, callee, reason):
    s = _one(_g(tmp_path, files), callee, file="a.py")
    assert (s["outcome"], s["reason"]) == ("unresolved", reason)
    assert s["why"] and s["why"] == calls.why(reason, s)


def test_framework_calls_and_decorators_are_counted(tmp_path):
    g = _g(tmp_path, {"main.py": (
        "from fastapi import Depends, FastAPI\n\napp = FastAPI()\n\n\ndef get_db():\n    return 1\n\n\n"
        "@app.get('/items')\ndef items(db=Depends(get_db)):\n    return []\n")})
    assert _one(g, "app.get")["outcome"] == "external"
    assert _one(g, "Depends")["outcome"] == "external"
    dep = _one(g, "get_db", group="handed")    # FastAPI calls it for every request: a function handed to the framework
    assert dep["outcome"] == "resolved" and dep["to"] == ["py:main.get_db"] and dep["via"] == "fastapi-depends"
    assert g.meta["calls"]["handed"]["total"] == 1


def test_test_code_is_counted_apart(tmp_path):
    g = _g(tmp_path, {"app.py": "def f():\n    return 1\n", "tests/test_app.py": "from app import f\n\n\ndef test_f():\n    assert f() == 1\n"})
    t = _one(g, "f", file="tests/test_app.py")
    assert t["test"] is True and t["outcome"] == "resolved"
    assert g.meta["calls"]["written"]["total"] == 0 and g.meta["calls"]["in_tests"]["total"] == 1


def test_js_sites_builtins_externals_and_computed_calls(tmp_path):
    g = _g(tmp_path, {"package.json": '{"dependencies": {"axios": "1.0.0"}}', "web/app.js": (
        "import axios from 'axios'\n"
        "function load () { return 1 }\n"
        "export function run (list, k) {\n"
        "  console.log('x'); JSON.parse('{}')\n"
        "  load()\n"
        "  axios.get('/api/x')\n"
        "  list[k]()\n"
        "  ;(function () { return 2 })()\n"
        "}\n")})
    got = {s["callee"]: (s["outcome"], s["reason"], s["line"]) for s in _written(g, "web/app.js")}
    assert got["console.log"] == ("builtin", None, 4) and got["JSON.parse"] == ("builtin", None, 4)
    assert got["load"] == ("resolved", None, 5)
    assert got["axios.get"] == ("external", None, 6)
    assert got["list[k]"] == ("unresolved", "computed", 7)
    iife = [s for s in _written(g, "web/app.js") if s["line"] == 8]
    assert len(iife) == 1 and iife[0]["outcome"] == "resolved" and iife[0]["via"] == "inline-function"
    w = g.meta["calls"]["written"]
    assert w["total"] == 6 and sum(w["outcomes"].values()) == 6   # the six calls written above, one record each
    assert g.meta["calls"]["languages"] == ["typescript/javascript"]


def test_languages_without_an_inventory_are_named(tmp_path):
    g = _g(tmp_path, {"main.go": "package main\n\nfunc main() {\n\thelper()\n}\n\nfunc helper() {}\n", "go.mod": "module x\n"})
    assert g.meta["calls"]["written"]["total"] == 0
    assert g.meta["calls"]["not_inventoried"] == ["go"]


def test_the_inventory_is_saved_beside_the_graph(tmp_path):
    from lantern import pipeline
    _write(tmp_path / "repo", {"app.py": "def a():\n    pass\n\n\ndef b(x):\n    a()\n    x.go()\n"})
    out = tmp_path / "out"
    out.mkdir()
    pipeline.analyze(tmp_path / "repo", out, no_scan=True, log=lambda *_: None)
    data = json.loads((out / "calls.json").read_text(encoding="utf-8"))
    assert data["summary"]["written"]["total"] == 2
    assert [s["callee"] for s in data["sites"]] == ["a", "x.go"]
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert graph["meta"]["calls"]["written"]["outcomes"]["resolved"] == 1
    assert graph["meta"]["calls"]["written"]["reasons"] == {"parameter": 1}
