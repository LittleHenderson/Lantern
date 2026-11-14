import shutil
from pathlib import Path

from lantern.python_frontend import build_graph
from lantern.trace import merge_trace, run_trace

FIX = Path(__file__).parent / "fixtures" / "shop"


def test_trace_marks_observed_edges(tmp_path):
    repo = tmp_path / "shop"
    shutil.copytree(FIX, repo)
    g = build_graph(repo)
    data = run_trace(repo, ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    assert data["returncode"] == 0, data["stderr_tail"]
    m = merge_trace(g, data)
    assert m["observed_edges"] == 1
    assert m["recall"] == 1.0
    e = next(e for e in g.call_edges()
             if e.src == "py:tests.test_auth.test_check_password" and e.dst == "py:shop.auth.check_password")
    assert e.confidence == "observed"


def test_decorator_wrapper_hops_collapse(tmp_path):
    (tmp_path / "app.py").write_text(
        "import functools\n\n"
        "def logged(f):\n"
        "    @functools.wraps(f)\n"
        "    def wrapper(*a, **k):\n"
        "        return f(*a, **k)\n"
        "    return wrapper\n\n"
        "class App:\n"
        "    @logged\n"
        "    def route(self):\n"
        "        return 1\n\n"
        "def main():\n"
        "    app = App()\n"
        "    app.route()\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n")
    g = build_graph(tmp_path)
    merge_trace(g, run_trace(tmp_path, ["python", "app.py"]))
    e = next(e for e in g.call_edges() if e.src == "py:app.main" and e.dst == "py:app.App.route")
    assert e.confidence == "observed"
    assert not any(e.src == "py:app.main" and e.dst == "py:app.logged.wrapper" for e in g.call_edges())


def test_a_function_named_like_a_file_of_its_package_does_not_stop_the_reading_of_a_run(tmp_path):
    """`pkg/views/__init__.py` defines `message()` and `pkg/views/message.py` is a file of the same package: both
    are `pkg.views.message`, and the map keeps one entry under that name. Found on a public project (2026-11-13):
    the file then had functions on the map and no entry of its own, and reading a test run back ended the whole
    check with an error (`KeyError`). The run is read, and a call into that file is marked as seen running."""
    views = tmp_path / "pkg" / "views"
    views.mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (views / "__init__.py").write_text(
        "from .message import Handler\n\n\ndef message():\n    return Handler().handle()\n", encoding="utf-8")
    (views / "message.py").write_text("class Handler:\n    def handle(self):\n        return 42\n", encoding="utf-8")
    (tmp_path / "run.py").write_text("from pkg import views\n\n\ndef main():\n    return views.message()\n\n\n"
                                     "if __name__ == '__main__':\n    main()\n", encoding="utf-8")
    g = build_graph(tmp_path)
    data = run_trace(tmp_path, ["python", "run.py"])
    assert data["returncode"] == 0, data["stderr_tail"]
    m = merge_trace(g, data)
    seen = {(e.src, e.dst) for e in g.call_edges() if e.confidence == "observed"}
    assert ("py:pkg.views.message", "py:pkg.views.message.Handler.handle") in seen, (m, sorted(seen))


def test_the_twin_with_no_such_name_is_read_as_before(tmp_path):
    views = tmp_path / "pkg" / "views"
    views.mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (views / "__init__.py").write_text(
        "from .message import Handler\n\n\ndef send():\n    return Handler().handle()\n", encoding="utf-8")
    (views / "message.py").write_text("class Handler:\n    def handle(self):\n        return 42\n", encoding="utf-8")
    (tmp_path / "run.py").write_text("from pkg import views\n\n\ndef main():\n    return views.send()\n\n\n"
                                     "if __name__ == '__main__':\n    main()\n", encoding="utf-8")
    g = build_graph(tmp_path)
    merge_trace(g, run_trace(tmp_path, ["python", "run.py"]))
    seen = {(e.src, e.dst) for e in g.call_edges() if e.confidence == "observed"}
    assert ("py:pkg.views.send", "py:pkg.views.message.Handler.handle") in seen, sorted(seen)
