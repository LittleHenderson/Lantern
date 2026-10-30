from pathlib import Path

import pytest

from lantern.python_frontend import build_graph

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def g():
    return build_graph(FIX)


def edge(g, src, dst):
    want = dst if dst.startswith("ext:") else f"py:{dst}"
    for e in g.call_edges():
        if e.src == f"py:{src}" and e.dst == want:
            return e
    return None


@pytest.mark.parametrize("src,dst,conf", [
    ("shop.app.read_user", "shop.auth.Session.__init__", "resolved"),      # constructor
    ("shop.app.read_user", "shop.auth.Session.login", "inferred"),         # local var type
    ("shop.auth.Session.login", "shop.repo.UserRepo.get", "inferred"),     # self.attr type
    ("shop.auth.Session.login", "shop.auth.check_password", "resolved"),   # module function
    ("shop.repo.UserRepo.get", "shop.repo.BaseRepo.execute", "resolved"),  # inherited method
    ("shop.repo.UserRepo.save", "shop.repo.CachedUserRepo.validate", "possible"),  # override
    ("shop.repo.CachedUserRepo.validate", "shop.repo.UserRepo.validate", "resolved"),  # super()
    ("shop.auth.make_repo", "shop.repo.BaseRepo.__init__", "resolved"),    # module alias import
    ("shop.cli.<main>", "shop.cli.admin", "resolved"),                     # __main__ block
    ("shop.app.helper", "shop.app.helper.inner", "resolved"),              # nested function
])
def test_expected_edges(g, src, dst, conf):
    e = edge(g, src, dst)
    assert e is not None, f"missing {src} -> {dst}"
    assert e.confidence == conf


def test_external_edges(g):
    e = edge(g, "shop.app.backup", "ext:subprocess.call")
    assert e is not None and e.confidence == "resolved"
    e = edge(g, "shop.repo.BaseRepo.execute", "ext:sqlite3.connect().execute")
    assert e is not None


def test_no_false_recursion(g):
    assert edge(g, "shop.repo.BaseRepo.execute", "shop.repo.BaseRepo.execute") is None


def test_entry_points(g):
    entries = {n.qualname: n.entry["kind"] for n in g.entry_points()}
    assert entries["shop.app.read_user"] == "route"
    assert entries["shop.app.backup"] == "route"
    assert entries["shop.cli.admin"] == "cli"
    assert entries["shop.cli.<main>"] == "main"
    assert entries["tests.test_auth.test_check_password"] == "test"


def test_route_detail(g):
    assert g.nodes["py:shop.app.read_user"].entry["detail"] == "GET /users/{user_id}"


def test_fingerprint_ignores_comments_and_whitespace(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    for d in (a, b):
        d.mkdir()
    (a / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    (b / "m.py").write_text("def f(x):  # adds one\n\n    return x   +   1\n", encoding="utf-8")
    fa = build_graph(a).nodes["py:m.f"].fingerprint
    fb = build_graph(b).nodes["py:m.f"].fingerprint
    assert fa == fb


def test_roundtrip(g, tmp_path):
    from lantern.graph import Graph
    p = tmp_path / "g.json"
    g.save(p)
    g2 = Graph.load(p)
    assert g2.stats() == g.stats()


def test_cls_constructor(g):
    e = edge(g, "shop.repo.Settings.default", "shop.repo.Settings.__init__")
    assert e is not None and e.via == "cls-constructor"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_subproject_import_root(tmp_path):
    _write(tmp_path, {
        "backend/app/__init__.py": "",
        "backend/app/crud.py": "def create_user(s):\n    return s\n",
        "backend/app/api.py": "from app import crud\n\ndef route():\n    return crud.create_user(1)\n",
        "backend/app/json.py": "def dumps(x):\n    return x\n",
        "backend/app/other.py": "import json\n\ndef f():\n    return json.dumps(1)\n",
    })
    g = build_graph(tmp_path)
    assert edge(g, "backend.app.api.route", "backend.app.crud.create_user") is not None
    # stdlib imports never map onto a same-named repo file
    assert edge(g, "backend.app.other.f", "backend.app.json.dumps") is None
    assert edge(g, "backend.app.other.f", "ext:json.dumps") is not None


def test_param_type_hints(tmp_path):
    _write(tmp_path, {
        "svc.py": "class Repo:\n    def load(self):\n        return 1\n\n"
                  "def handler(repo: Repo, n: int = 3):\n    return repo.load()\n",
    })
    g = build_graph(tmp_path)
    e = edge(g, "svc.handler", "svc.Repo.load")
    assert e is not None and e.confidence == "inferred"


def test_routes_in_test_files_are_not_app_entries(tmp_path):
    _write(tmp_path, {
        "tests/test_api.py": "from flask import Flask\napp = Flask(__name__)\n\n"
                             "def test_index():\n    @app.route('/')\n    def index():\n        return 'x'\n",
    })
    g = build_graph(tmp_path)
    kinds = {n.qualname: n.entry["kind"] for n in g.entry_points()}
    assert kinds == {"tests.test_api.test_index": "test"}


def test_decorator_factory_closure(tmp_path):
    _write(tmp_path, {"cli.py": (
        "def command(name=None):\n"
        "    def decorator(f):\n"
        "        return f\n"
        "    return decorator\n\n"
        "def plain(f):\n    return f\n\n"
        "@command()\n@plain\ndef hello():\n    pass\n")})
    g = build_graph(tmp_path)
    assert edge(g, "cli", "cli.command") is not None              # factory call
    assert edge(g, "cli", "cli.command.decorator").via == "decorator-closure"
    assert edge(g, "cli", "cli.plain") is not None                # bare decorator applied


def test_return_type_inference(tmp_path):
    _write(tmp_path, {"svc.py": (
        "class Repo:\n    def save(self):\n        return 1\n\n"
        "def make_repo():\n    return Repo()\n\n"
        "def typed() -> Repo:\n    return build()\n\n"
        "def use():\n    r = make_repo()\n    r.save()\n    typed().save()\n")})
    g = build_graph(tmp_path)
    e = edge(g, "svc.use", "svc.Repo.save")
    assert e is not None and e.confidence == "inferred"


def test_property_reads(tmp_path):
    _write(tmp_path, {"m.py": (
        "class User:\n"
        "    @property\n    def full_name(self):\n        return 'x'\n"
        "    def greet(self):\n        return 'hi ' + self.full_name\n"
        "    def plain_attr(self):\n        return self.other\n")})
    g = build_graph(tmp_path)
    assert edge(g, "m.User.greet", "m.User.full_name").via == "property"
    assert not [e for e in g.callees("py:m.User.plain_attr")]


def test_with_statement(tmp_path):
    _write(tmp_path, {"m.py": (
        "class Tx:\n    def __enter__(self):\n        return self\n"
        "    def __exit__(self, *a):\n        return False\n"
        "    def commit(self):\n        pass\n\n"
        "def run():\n    with Tx() as tx:\n        tx.commit()\n")})
    g = build_graph(tmp_path)
    assert edge(g, "m.run", "m.Tx.__enter__") is not None
    assert edge(g, "m.run", "m.Tx.__exit__") is not None
    assert edge(g, "m.run", "m.Tx.commit") is not None


def test_pytest_fixture_param(tmp_path):
    _write(tmp_path, {
        "app.py": "class Runner:\n    def invoke(self):\n        return 0\n",
        "tests/conftest.py": "import pytest\nfrom app import Runner\n\n@pytest.fixture\ndef runner():\n    return Runner()\n",
        "tests/test_x.py": "def test_a(runner):\n    runner.invoke()\n",
    })
    g = build_graph(tmp_path)
    assert edge(g, "tests.test_x.test_a", "app.Runner.invoke").via == "fixture-type"


def test_fastapi_depends_and_aliases(tmp_path):
    _write(tmp_path, {
        "app/__init__.py": "",
        "app/deps.py": (
            "from typing import Annotated\nfrom fastapi import Depends\nfrom sqlmodel import Session\n\n"
            "def get_db():\n    yield Session()\n\n"
            "SessionDep = Annotated[Session, Depends(get_db)]\n\n"
            "def get_current_user(session: SessionDep):\n    return session.get(1)\n\n"
            "CurrentUser = Annotated[object, Depends(get_current_user)]\n"),
        "app/items.py": (
            "from fastapi import APIRouter, Depends\nfrom app.deps import SessionDep, CurrentUser, get_db\n\n"
            "router = APIRouter(prefix=\"/items\")\n\n"
            "@router.get(\"/{id}\")\n"
            "def read_item(session: SessionDep, user: CurrentUser, id: int):\n"
            "    return session.exec(id)\n\n"
            "@router.post(\"/\")\n"
            "def create(db=Depends(get_db)):\n    return 1\n"),
    })
    g = build_graph(tmp_path)
    assert g.nodes["py:app.items.read_item"].entry["detail"] == "GET /items/{id}"
    assert edge(g, "app.items.read_item", "app.deps.get_db").via == "fastapi-depends"
    assert edge(g, "app.items.read_item", "app.deps.get_current_user").via == "fastapi-depends"
    assert edge(g, "app.items.create", "app.deps.get_db").via == "fastapi-depends"
    # the aliased parameter's type is the real external class, not a fake "app.deps" library
    assert edge(g, "app.items.read_item", "ext:sqlmodel.Session().exec") is not None
    assert not any(e.dst.startswith("ext:app.") for e in g.call_edges())
