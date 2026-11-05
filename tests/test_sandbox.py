"""The test sandbox ("Watch my tests run"): both backends run the shop's pytest, record calls, and refuse writes to
the project, network connections, inherited secrets and runaway tests."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lantern import sandbox
from lantern.graph import Graph

FIX = Path(__file__).parent / "fixtures"


def _docker_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "Docker backend is used on Linux only (host packages must be Linux packages)"
    if not shutil.which("docker"):
        return "docker is not installed"
    if not sandbox.docker_ok():
        return "the Docker daemon does not answer (`docker info` failed)"
    if not sandbox.image_for("python"):
        return f"no pinned image for Python {sys.version_info[0]}.{sys.version_info[1]}"
    return None


DOCKER_SKIP = _docker_reason()
BACKENDS = ["subprocess", pytest.param("docker", marks=pytest.mark.skipif(DOCKER_SKIP is not None, reason=DOCKER_SKIP or ""))]

PLANTED = '''
import os, socket, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent

def test_write_to_the_project():
    (HERE / "planted.txt").write_text("x")

def test_open_a_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 80))

def test_write_below_python():
    if not sys.platform.startswith("linux"):
        return
    # bypasses Python's own file functions: only the kernel (Landlock, read-only mount) can stop this
    r = subprocess.run(["sh", "-c", "echo x > " + str(HERE / "planted-sh.txt")], capture_output=True, text=True)
    print("SH", r.returncode, r.stderr.strip())
    assert r.returncode == 0, r.stderr

def test_environment_is_scrubbed():
    assert "LANTERN_TEST_SECRET" not in os.environ
    assert not any(k.endswith("_API_KEY") for k in os.environ)
    home = os.environ.get("HOME", "")
    assert home in ("/tmp",) or "lantern-sandbox-" in home, home
'''


@pytest.fixture()
def planted(tmp_path):
    repo = tmp_path / "planted"
    (repo / "tests").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'planted'\n", encoding="utf-8")
    (repo / "tests" / "test_planted.py").write_text(PLANTED, encoding="utf-8")
    return repo


@pytest.mark.parametrize("backend", BACKENDS)
def test_shop_tests_run_and_calls_are_recorded(backend, tmp_path):
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
    lines = []
    r = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lines.append, backend=backend)
    assert r["backend"] == backend and r["language"] == "python" and r["traced"]
    assert r["returncode"] == 0, r["output_tail"]
    assert r["pairs"], "no calls recorded"
    files = {row["callee"][0] for row in r["pairs"]}
    assert all(f.startswith(str(repo.resolve())) for f in files), files   # mapped back from the copy / container
    assert any("passed" in x for x in lines)   # output streamed line by line


@pytest.mark.parametrize("backend", BACKENDS)
def test_at_least_one_edge_becomes_observed(backend, tmp_path, monkeypatch):
    from lantern import pipeline
    monkeypatch.setenv("LANTERN_SANDBOX", backend)
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=["python", "-m", "pytest", "-q"], sandbox=True, offline=True, log=lambda m: None)
    g = Graph.load(out / "graph.json")
    observed = [e for e in g.call_edges() if e.confidence == "observed"]
    assert observed, "no edge moved to observed"
    run = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    assert run["backend"] == backend and run["traced"] is True and run["observed_edges"] >= 1 and run["blocked"] == []


@pytest.mark.parametrize("backend", BACKENDS)
def test_planted_tests_cannot_write_reach_the_network_or_read_secrets(backend, planted, monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_SECRET", "s3cret")
    monkeypatch.setenv("FAKE_API_KEY", "k")
    before = sorted(p.name for p in (planted / "tests").iterdir())
    r = sandbox.run(planted, ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"], log=lambda m: None, backend=backend)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    assert "test_write_to_the_project FAILED" in out or "FAILED tests/test_planted.py::test_write_to_the_project" in out
    assert "FAILED tests/test_planted.py::test_open_a_socket" in out
    assert "test_environment_is_scrubbed" not in out.split("short test summary")[-1], out   # the scrub test passed
    kinds = {b["kind"] for b in r["blocked"]}
    assert kinds == {"write", "network"}, r["blocked"]   # what the toast shows
    if sys.platform.startswith("linux") and (backend == "docker" or sandbox.landlock_abi() >= 1):
        assert "FAILED tests/test_planted.py::test_write_below_python" in out, out
    # the project itself is untouched
    assert sorted(p.name for p in (planted / "tests").iterdir()) == before


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except OSError:
        return True


@pytest.mark.parametrize("backend", BACKENDS)
def test_runaway_tests_are_killed_at_the_wall_clock(backend, tmp_path):
    repo = tmp_path / "slow"
    (repo / "tests").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'slow'\n", encoding="utf-8")
    (repo / "tests" / "test_slow.py").write_text(
        "import subprocess, sys, time\n"
        "def test_forever():\n"
        "    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])\n"
        "    print('GRANDCHILD', p.pid, flush=True)\n"
        "    time.sleep(300)\n", encoding="utf-8")
    r = sandbox.run(repo, ["python", "-m", "pytest", "-q", "-s"], log=lambda m: None, backend=backend, timeout=6)
    assert r["timed_out"] and r["returncode"] is None
    if backend == "subprocess" and os.name == "posix":
        pid = next(int(x.split()[1]) for x in r["output_tail"].splitlines() if x.startswith("GRANDCHILD"))
        assert not _alive(pid), "a process the tests started survived the wall clock"
    if backend == "docker":
        left = subprocess.run(["docker", "ps", "-aq", "--filter", "name=lantern-sbx-"], capture_output=True, text=True)
        assert not left.stdout.strip(), "the container was not removed"


def test_temp_copy_is_read_only_and_removed(tmp_path, monkeypatch):
    seen = {}
    real = sandbox._stream

    def spy(cmd, cwd, env, timeout, log, job=None):
        seen["cwd"], seen["env"] = Path(cwd), env
        seen["writable"] = os.access(cwd, os.W_OK) if os.name == "posix" and os.geteuid() != 0 else False
        return real(cmd, cwd, env, timeout, log, job)
    monkeypatch.setattr(sandbox, "_stream", spy)
    monkeypatch.setenv("LANTERN_TEST_SECRET", "s3cret")
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
    sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda m: None, backend="subprocess")
    assert seen["cwd"] != repo and "lantern-sandbox-" in str(seen["cwd"])   # a copy, not the project
    assert not seen["writable"]
    assert "LANTERN_TEST_SECRET" not in seen["env"] and "lantern-sandbox-" in seen["env"]["HOME"]
    assert not seen["cwd"].exists()   # deleted after


def test_backend_choice_and_description(monkeypatch, tmp_path):
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    d = sandbox.describe(tmp_path, "python")
    assert d["name"] == "subprocess" and any("read-only copy" in x for x in d["details"])
    assert any("environment variables are not passed on" in x for x in d["details"])
    assert sandbox.blocked_reasons('    msg = "LANTERN-SANDBOX-BLOCKED: " + what\nLANTERN-SANDBOX-BLOCKED: write to /app/x') == \
        [{"kind": "write", "what": "write to /app/x"}]


def test_server_needs_confirmation_once_per_command(tmp_path, monkeypatch):
    from test_server import call, srv  # noqa: F401
    from lantern.server import App, Handler, Store
    import threading
    from http.server import ThreadingHTTPServer
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.app = App(store, "tok-123", httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        repo = tmp_path / "shop"
        shutil.copytree(FIX / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
        code, pj = call(base, "/api/projects", "POST", {"path": str(repo)})
        pid = (pj.get("project") or pj)["id"]
        code, d = call(base, f"/api/projects/{pid}/testcmd")
        assert code == 200 and d["sandbox"]["name"] == "subprocess" and d["confirmed"] is False
        code, e = call(base, f"/api/projects/{pid}/trace", "POST", {"command": "python -m pytest -q"})
        assert code == 409 and "confirm" in e["error"]
        code, e = call(base, f"/api/projects/{pid}/trace", "POST", {"command": "rm -rf /", "confirm": True})
        assert code == 400
        code, e = call(base, f"/api/projects/{pid}/trace", "POST", {"command": "python -m pytest -q"}, token=None)
        assert code == 403
        code, j = call(base, f"/api/projects/{pid}/trace", "POST", {"command": "python -m pytest -q", "confirm": True})
        assert code == 202
        from test_server import wait
        done = wait(base, j["id"], timeout=180)
        assert done["status"] == "done", done
        assert done["result"]["backend"] == "subprocess" and done["result"]["observed"] >= 1 and done["result"]["blocked"] == []
        code, d = call(base, f"/api/projects/{pid}/testcmd")
        assert d["confirmed"] is True   # once per project per command
    finally:
        httpd.shutdown()
        httpd.server_close()
