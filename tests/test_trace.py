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
    m = merge_trace(g, run_trace(tmp_path, ["python", "app.py"]))
    e = next(e for e in g.call_edges() if e.src == "py:app.main" and e.dst == "py:app.App.route")
    assert e.confidence == "observed"
    assert not any(e.src == "py:app.main" and e.dst == "py:app.logged.wrapper" for e in g.call_edges())
