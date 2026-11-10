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
    # the file is there, but nothing Lantern reads in it binds the name: not "a variable of the repo"
    ({"pkg/__init__.py": "", "pkg/tools.py": "def other():\n    pass\n",
      "a.py": "from pkg.tools import nothere\n\n\ndef f():\n    return nothere()\n"}, "nothere", "missing-export"),
    # a marker base with no members of its own (ABC) leaves nowhere else to look; Enum has members of its own
    ({"a.py": "from abc import ABC\n\n\nclass Shape(ABC):\n    def f(self):\n        return self.nope()\n"},
     "self.nope", "not-in-class"),
    ({"a.py": "from enum import Enum\n\n\nclass Color(Enum):\n    RED = 1\n\n    def f(self):\n        return self.nope()\n"},
     "self.nope", "unknown-base"),
    ({"a.py": "def make():\n    return object\n\n\nBase = make()\n\n\nclass A(Base):\n    def f(self):\n"
              "        return super().nope()\n"}, "super().nope", "unknown-base"),
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


# ---- Python resolution added in stage 3 (each with its twin that must stay unresolved) ----

def test_methods_inherited_from_a_library_class_are_external(tmp_path):
    g = _g(tmp_path, {"checks.py": (
        "import unittest\n\n\nclass Checks(unittest.TestCase):\n    def check_one(self):\n        self.assertEqual(1, 1)\n"
        "        return self.helper()\n\n    def helper(self):\n        return 2\n")})
    s = _one(g, "self.assertEqual")
    assert (s["outcome"], s["to"], s["via"], s["confidence"]) == (
        "external", ["ext:unittest.TestCase.assertEqual"], "inherited-library", "inferred")
    assert _one(g, "self.helper")["to"] == ["py:checks.Checks.helper"]   # a method the repo defines still wins


def test_model_managers_and_typed_parameters_reach_the_library_base(tmp_path):
    g = _g(tmp_path, {"notes.py": (
        "from django.db import models\n\n\nclass Note(models.Model):\n    def short(self):\n        return 1\n\n\n"
        "def recent():\n    return Note.objects.filter(title='x')\n\n\n"
        "def keep(n: Note):\n    n.short()\n    n.save()\n")})
    assert _one(g, "Note.objects.filter")["to"] == ["ext:django.Model.objects.filter"]
    assert _one(g, "n.save")["to"] == ["ext:django.Model.save"]
    assert _one(g, "n.short")["to"] == ["py:notes.Note.short"]


def test_a_function_stored_on_self_is_not_taken_for_a_library_method(tmp_path):
    g = _g(tmp_path, {"jobs.py": (
        "import threading\n\n\nclass Worker(threading.Thread):\n    def __init__(self, cb):\n        super().__init__()\n"
        "        self.cb = cb\n\n    def work(self):\n        self.cb()\n        self.join()\n\n\n"
        "class Plain:\n    def go(self):\n        return self.missing()\n")})
    assert (_one(g, "self.cb")["outcome"], _one(g, "self.cb")["reason"]) == ("unresolved", "self-attribute")
    assert _one(g, "self.join")["to"] == ["ext:threading.Thread.join"]
    assert _one(g, "self.missing")["reason"] == "not-in-class"


def test_calls_on_a_library_result_are_library_calls(tmp_path):
    g = _g(tmp_path, {"fetch.py": "import requests\n\n\ndef get(u):\n    return requests.get(u).json()\n"})
    s = _one(g, "requests.get(u).json")
    assert (s["outcome"], s["to"], s["via"]) == ("external", ["ext:requests.get().json"], "library-result")


def test_include_router_prefixes_reach_the_routes(tmp_path):
    g = _g(tmp_path, {
        "app/__init__.py": "",
        "app/items.py": "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n@router.get('/list')\ndef list_items():\n    return []\n",
        "app/users.py": "from fastapi import APIRouter\n\nrouter = APIRouter(prefix='/users')\n\n\n@router.get('/me')\ndef me():\n    return {}\n",
        "app/api.py": ("from fastapi import APIRouter\n\nfrom app import items, users\n\napi = APIRouter()\n"
                       "api.include_router(items.router, prefix='/items')\napi.include_router(users.router)\n"),
        "app/admin.py": "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n@router.post('/reset')\ndef reset():\n    return {}\n",
        "app/main.py": ("from fastapi import FastAPI\n\nfrom app.admin import router as admin_router\nfrom app.api import api\n\n"
                        "app = FastAPI()\napp.include_router(api, prefix='/v1')\napp.include_router(admin_router, prefix='/admin')\n"),
    })
    assert g.nodes["py:app.items.list_items"].entry["detail"] == "GET /v1/items/list"
    assert g.nodes["py:app.users.me"].entry["detail"] == "GET /v1/users/me"
    assert g.nodes["py:app.admin.reset"].entry["detail"] == "POST /admin/reset"


def test_an_include_router_prefix_that_is_not_a_written_string_is_left_alone(tmp_path):
    g = _g(tmp_path, {
        "app/__init__.py": "",
        "app/items.py": "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n@router.get('/list')\ndef list_items():\n    return []\n",
        "app/main.py": ("import os\n\nfrom fastapi import FastAPI\n\nfrom app import items\n\napp = FastAPI()\n"
                        "app.include_router(items.router, prefix=os.environ['PREFIX'])\n"),
    })
    assert g.nodes["py:app.items.list_items"].entry["detail"] == "GET /list"


def test_a_flask_url_prefix_given_at_registration_replaces_the_blueprints_own(tmp_path):
    g = _g(tmp_path, {
        "app/__init__.py": "",
        "app/bp.py": ("from flask import Blueprint\n\nbp = Blueprint('bp', __name__, url_prefix='/old')\n\n\n"
                      "@bp.route('/x')\ndef x():\n    return ''\n"),
        "app/main.py": ("from flask import Flask\n\nfrom app.bp import bp\n\napp = Flask(__name__)\n"
                        "app.register_blueprint(bp, url_prefix='/new')\n"),
    })
    assert g.nodes["py:app.bp.x"].entry["detail"] == "GET /new/x"


def test_built_in_results_stay_built_ins(tmp_path):
    g = _g(tmp_path, {"app.py": "def clean(x):\n    return str(x).strip()\n"})
    assert _one(g, "str(x).strip")["outcome"] == "builtin"


def test_a_class_attribute_set_in_the_repo_is_not_taken_for_the_library_base(tmp_path):
    g = _g(tmp_path, {"views.py": (
        "from django.views import View\n\n\nclass Notes(View):\n    store = None\n\n    def get(self):\n"
        "        return self.store.load()\n")})
    assert _one(g, "self.store.load")["outcome"] != "external"


# ---- what Lantern did not read is not called a library ----

def test_a_project_file_lantern_did_not_read_is_not_called_a_library(tmp_path):
    """`from .missing import …` names a file of the project: a relative import never names a library. When that file
    is not there to read, what comes from it is unknown, not "a library". The twin beside it is a real library."""
    g = _g(tmp_path, {"app/__init__.py": "", "app/a.py": (
        "import requests\n\nfrom .missing import Gone, helper\n\n\n"
        "class C(Gone):\n    def run(self):\n        self.thing()\n        return helper()\n\n\n"
        "class E(requests.Session):\n    def run(self, u):\n        return self.get(u)\n\n\n"
        "def use(u):\n    Gone().go()\n    x = Gone()\n    x.go()\n    return requests.get(u, timeout=5).json()\n")})
    for callee in ("helper", "Gone().go"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "missing-module", []), (callee, s)
    assert "cannot find in the repository" in _one(g, "helper")["why"]
    s = _one(g, "x.go")   # x = Gone(): the value's type is in the file Lantern did not read
    assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "local-unknown", []), s
    s = _one(g, "self.thing")
    assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "unknown-base", []), s
    assert "may be defined there" in s["why"]
    s = _one(g, "self.get")
    assert (s["outcome"], s["to"], s["via"]) == ("external", ["ext:requests.Session.get"], "inherited-library")
    s = _one(g, "requests.get(u, timeout=5).json")
    assert (s["outcome"], s["via"]) == ("external", "library-result")
    w = g.meta["calls"]["written"]
    assert sum(w["outcomes"].values()) == w["total"] and w["reasons"]["missing-module"] == 4   # + the two Gone()
    # the map keeps the link the older rule drew (so counts compare across versions); only the inventory changed
    assert any(e.dst == "ext:app.missing.helper" and e.via == "import" for e in g.edges)


def test_a_class_with_a_base_lantern_cannot_identify_makes_no_library_claim(tmp_path):
    """`class Notes(Audit, View)`: `Audit` comes in by a star import of a library, so Lantern cannot see what it
    defines. A method the class does not define may be Audit's, so it is not called Django's `View`'s. So does a
    computed base. The twin has only `View`."""
    g = _g(tmp_path, {"app/__init__.py": "", "app/views.py": (
        "from django.views import View\n\nfrom auditlib.mixins import *\n\n\n"
        "class Notes(Audit, View):\n    def get(self):\n        self.note()\n        return self.render_to_response()\n\n\n"
        "class Plain(View):\n    def get(self):\n        return self.http_method_not_allowed()\n\n\n"
        "def make():\n    return object\n\n\n"
        "class Odd(make(), View):\n    def get(self):\n        return self.options()\n")})
    for callee in ("self.note", "self.render_to_response", "self.options"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "unknown-base", []), (callee, s)
    s = _one(g, "self.http_method_not_allowed")
    assert (s["outcome"], s["to"]) == ("external", ["ext:django.View.http_method_not_allowed"])


def test_typing_markers_and_class_keywords_do_not_hide_a_library_base(tmp_path):
    g = _g(tmp_path, {"models.py": (
        "from abc import ABCMeta\nfrom typing import Generic, TypeVar\n\nfrom pydantic import BaseModel\n\n"
        "T = TypeVar('T')\n\n\n"
        "class Page(BaseModel, Generic[T], metaclass=ABCMeta):\n    def dump(self):\n        return self.model_dump()\n")})
    s = _one(g, "self.model_dump")
    assert (s["outcome"], s["to"], s["via"]) == ("external", ["ext:pydantic.BaseModel.model_dump"], "inherited-library")


def test_js_this_calls_say_whether_a_base_class_outside_the_repo_could_hold_them(tmp_path):
    """`this.setState()` in a class that extends React's Component is not traced yet, and the reason must not say
    the class has no base it could come from. A class with no base outside the repo keeps the old reason."""
    g = _g(tmp_path, {"package.json": '{"name": "p", "dependencies": {"react": "18.0.0"}}',
                      "src/base.js": "export class Base { fromBase() { return 1; } }\n",
                      "src/App.jsx": (
        "import { Component } from 'react';\nimport { Base } from './base';\nimport { Gone } from './gone';\n\n"
        "export class App extends Component {\n  load() { this.setState({ a: 1 }); }\n}\n"
        "export class Lost extends Gone {\n  go() { this.thing(); }\n}\n"
        "export class Mixed extends mix(Base) {\n  go() { this.added(); }\n}\n"
        "export class Child extends Base {\n  go() { this.fromBase(); this.nowhere(); }\n}\n"
        "export class Plain {\n  go() { this.nope(); }\n}\n")})
    for callee in ("this.setState", "this.thing", "this.added"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"]) == ("unresolved", "unknown-base"), (callee, s)
    for callee in ("this.nowhere", "this.nope"):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"]) == ("unresolved", "not-in-class"), (callee, s)
        assert "no other base class that could" in s["why"]
    assert _one(g, "this.fromBase")["to"] == ["js:src/base::Base.fromBase"]


# ---- `from x import *` ----

STAR = {
    "app/__init__.py": "",
    "app/auth/__init__.py": "from .tokens import *\nfrom .users import *\n",
    "app/auth/tokens.py": (
        "__all__ = ['make_token']\n\n\ndef make_token(u):\n    return _sign(u)\n\n\ndef _sign(u):\n    return u\n\n\n"
        "def hidden(u):\n    return u\n"),
    "app/auth/users.py": (
        "LIMIT = 3\n\n\nclass User:\n    def save(self):\n        return 1\n\n\ndef find_user(name):\n    return User()\n\n\n"
        "def _private(name):\n    return name\n"),
}


def test_names_that_come_in_by_a_star_import_of_a_repo_file_are_followed(tmp_path):
    """dvra's shape: `auth/__init__.py` says `from .users import *`, a route says `from app.auth import find_user`.
    The function is the repo's own; it used to be reported as a variable whose value Lantern does not know."""
    g = _g(tmp_path, {**STAR, "app/routes.py": (
        "from app.auth import find_user, make_token\nfrom app.auth.users import *\n\n\n"
        "def login(name):\n    u = find_user(name)\n    User().save()\n    return make_token(u)\n")})
    assert _one(g, "find_user")["to"] == ["py:app.auth.users.find_user"]
    assert _one(g, "make_token")["to"] == ["py:app.auth.tokens.make_token"]
    s = _one(g, "User().save")
    assert (s["outcome"], s["to"]) == ("resolved", ["py:app.auth.users.User.save"])


def test_a_star_import_brings_only_what_python_would_bring(tmp_path):
    """The twins: a name left out of `__all__`, a name that starts with an underscore, a name the file binds itself,
    a parameter of the same name, and a star import of a library are not linked through the star import."""
    g = _g(tmp_path, {**STAR, "app/routes.py": (
        "from somelib import *\n\nfrom app.auth import *\n\n\n"
        "def a(u):\n    hidden(u)\n    _private(u)\n    return lib_helper(u)\n\n\n"
        "def b(find_user):\n    return find_user('x')\n\n\n"
        "def make():\n    return len\n\n\nmake_token = make()\n\n\n"
        "def c(u):\n    return make_token(u)\n")})
    for callee, reason in (("hidden", "not-defined"), ("_private", "not-defined"), ("lib_helper", "not-defined"),
                           ("find_user", "callback-parameter"), ("make_token", "repo-variable")):
        s = _one(g, callee)
        assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", reason, []), (callee, s)


def test_a_star_import_after_a_library_star_import_is_not_trusted_over_it(tmp_path):
    """`from app.auth import *` then `from somelib import *`: the library's star import comes last and may bring a
    `find_user` of its own, so Lantern does not say which one runs."""
    g = _g(tmp_path, {**STAR, "app/routes.py": (
        "from app.auth import *\nfrom somelib import *\n\n\ndef a(n):\n    return find_user(n)\n")})
    s = _one(g, "find_user")
    assert (s["outcome"], s["reason"]) == ("unresolved", "not-defined")


def test_a_base_class_that_comes_in_by_a_star_import_is_read(tmp_path):
    g = _g(tmp_path, {"app/__init__.py": "", "app/mixins.py": "class Audit:\n    def note(self):\n        return 1\n",
                      "app/views.py": (
        "from django.views import View\n\nfrom .mixins import *\n\n\n"
        "class Notes(Audit, View):\n    def get(self):\n        self.note()\n        return self.render_to_response()\n")})
    assert _one(g, "self.note")["to"] == ["py:app.mixins.Audit.note"]
    s = _one(g, "self.render_to_response")
    assert (s["outcome"], s["to"], s["via"]) == ("external", ["ext:django.View.render_to_response"], "inherited-library")


# ---- a library label never hides a call that may be the project's own ----

def test_a_call_through_a_library_base_attribute_is_a_library_call_only_when_no_repo_method_has_its_name(tmp_path):
    """`self.object` comes from Django's DetailView, but it holds the project's own Order: `self.object.total()` is
    the project's method, and the older name-only link to it must stay. `self.request.build_absolute_uri()` cannot be
    project code (no class in it has such a method), so it is the library's. A longer chain is not claimed."""
    g = _g(tmp_path, {"shop/views.py": (
        "from django.views.generic import DetailView\n\n\n"
        "class Order:\n    def total(self):\n        return 1\n\n\n"
        "class OrderView(DetailView):\n    def get_context_data(self):\n        self.object.total()\n"
        "        self.request.session.cycle_key()\n        return self.request.build_absolute_uri()\n")})
    s = _one(g, "self.object.total")
    assert (s["outcome"], s["to"], s["via"]) == ("name-only", ["py:shop.views.Order.total"], "unique-method-name")
    s = _one(g, "self.request.build_absolute_uri")
    assert (s["outcome"], s["to"], s["via"]) == (
        "external", ["ext:django.DetailView.request.build_absolute_uri"], "inherited-library")
    s = _one(g, "self.request.session.cycle_key")
    assert (s["outcome"], s["reason"]) == ("unresolved", "self-attribute")


def test_a_method_a_sibling_class_gives_a_subclass_is_not_called_the_librarys(tmp_path):
    """`Base.run` calls `self.helper()`. Base has no `helper`, but `Page(Base, Tools)` gets one from `Tools`, so the
    call may run the project's own code: no library label. The twin `Solo` has no such subclass."""
    g = _g(tmp_path, {"shop/views.py": (
        "from django.views import View\n\n\n"
        "class Base(View):\n    def run(self):\n        return self.helper()\n\n\n"
        "class Tools:\n    def helper(self):\n        return 1\n\n\n"
        "class Page(Base, Tools):\n    pass\n\n\n"
        "class Solo(View):\n    def run(self):\n        return self.http_method_not_allowed()\n")})
    s = _one(g, "self.helper")
    assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "unknown-base", []), s
    assert _one(g, "self.http_method_not_allowed")["outcome"] == "external"


def test_a_call_on_a_library_result_is_not_called_the_librarys_when_a_project_class_has_that_method(tmp_path):
    """`get_user_model()` is Django's, but what it returns is the project's own user class, whose manager has the
    project's `create_member`: the older name-only reading must stay. Twins: a name no project class has, an everyday
    name (`get`, which lists, dicts and most libraries have), and a method of a built-in type (`str.title`)."""
    g = _g(tmp_path, {
        "accounts/__init__.py": "",
        "accounts/models.py": (
            "from django.contrib.auth.base_user import BaseUserManager\n\n\n"
            "class Members(BaseUserManager):\n    def create_member(self, email):\n        return email\n\n"
            "    def title(self):\n        return 'members'\n\n    def get(self, key):\n        return key\n\n\n"
            + "".join(f"class Group{i}:\n    def announce(self):\n        return {i}\n\n\n" for i in range(5))),
        "accounts/views.py": (
            "import copy\nimport json\n\nfrom django.contrib.auth import get_user_model\n\n\n"
            "def join(email, draft, body):\n"
            "    get_user_model().objects.create_member(email)\n"
            "    get_user_model().objects.count()\n"
            "    copy.copy(draft).announce()\n"
            "    json.loads(body).get('email')\n"
            "    return str(email).title()\n"),
    })
    s = _one(g, "get_user_model().objects.create_member")
    assert (s["outcome"], s["to"], s["via"]) == (
        "name-only", ["py:accounts.models.Members.create_member"], "unique-method-name"), s
    # five classes define announce(): too many to guess which, and it is not the library's for sure either
    s = _one(g, "copy.copy(draft).announce")
    assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "library-or-repo", []), s
    assert "has its own `announce`" in s["why"]
    assert _one(g, "get_user_model().objects.count")["via"] == "library-result"
    assert _one(g, "json.loads(body).get")["via"] == "library-result"
    s = _one(g, "str(email).title")
    assert (s["outcome"], s["to"], s["via"]) == ("builtin", ["builtin:str().title"], "library-result"), s


def test_a_library_base_attribute_whose_method_the_project_also_has_says_so(tmp_path):
    g = _g(tmp_path, {"shop/checks.py": (
        "from django.test import TestCase\n\n\n"
        "class Cart:\n    def get(self, key):\n        return key\n\n\n"
        "class CartPages(TestCase):\n    def check_open(self):\n        self.client.get('/cart')\n"
        "        return self.client.force_login(None)\n")})
    s = _one(g, "self.client.get")
    assert (s["outcome"], s["reason"], s["to"]) == ("unresolved", "library-or-repo", []), s
    assert _one(g, "self.client.force_login")["via"] == "inherited-library"
