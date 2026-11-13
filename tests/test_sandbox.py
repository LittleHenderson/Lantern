"""The test sandbox ("Watch my tests run"): both backends run the shop's pytest, record calls, and refuse writes to
the project, network connections, inherited secrets and runaway tests."""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
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
OUT = Path((HERE / "where.txt").read_text(encoding="utf-8").strip())    # a folder that is not the tests' own copy

def test_write_outside_the_copy():
    (OUT / "planted.txt").write_text("x")

def test_open_a_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 80))

def test_write_below_python():
    if not sys.platform.startswith("linux"):
        return
    # bypasses Python's own file functions: only the kernel (Landlock, a container's read-only files) can stop this
    r = subprocess.run(["sh", "-c", "echo x > " + str(OUT / "planted-sh.txt")], capture_output=True, text=True)
    print("SH", r.returncode, r.stderr.strip())
    assert r.returncode == 0, r.stderr

def test_environment_is_scrubbed():
    assert "LANTERN_TEST_SECRET" not in os.environ
    assert not any(k.endswith("_API_KEY") for k in os.environ)
    home = os.environ.get("HOME", "")
    assert home in ("/tmp",) or "lantern-sandbox-" in home, home
'''


@pytest.fixture()
def outside():
    """A folder that is not the tests' copy and that every user of this computer may come to and write in (a
    test's tmp_path is its owner's alone, and the sandbox's tests run as `nobody` when Lantern is root): nothing
    but the sandbox keeps the tests out of it."""
    folder = Path(tempfile.mkdtemp(prefix="outside-"))
    folder.chmod(0o777)
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture()
def planted(tmp_path, outside):
    repo = tmp_path / "planted"
    (repo / "tests").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname = 'planted'\n", encoding="utf-8")
    (repo / "tests" / "test_planted.py").write_text(PLANTED, encoding="utf-8")
    (repo / "tests" / "where.txt").write_text(str(outside), encoding="utf-8")
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
def test_planted_tests_cannot_write_reach_the_network_or_read_secrets(backend, planted, outside, monkeypatch):
    monkeypatch.setenv("LANTERN_TEST_SECRET", "s3cret")
    monkeypatch.setenv("FAKE_API_KEY", "k")
    if backend == "docker":              # a container has its own files: there the place outside is one of its folders
        (planted / "tests" / "where.txt").write_text("/usr", encoding="utf-8")
    before = sorted(p.name for p in (planted / "tests").iterdir())
    r = sandbox.run(planted, ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"], log=lambda m: None, backend=backend)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    assert "test_write_outside_the_copy FAILED" in out or "FAILED tests/test_planted.py::test_write_outside_the_copy" in out
    assert "FAILED tests/test_planted.py::test_open_a_socket" in out
    assert "test_environment_is_scrubbed" not in out.split("short test summary")[-1], out   # the scrub test passed
    kinds = {b["kind"] for b in r["blocked"]}
    assert kinds == {"write", "network"}, r["blocked"]   # what the toast shows
    if sys.platform.startswith("linux") and (backend == "docker" or sandbox.landlock_abi() >= 1):
        assert "FAILED tests/test_planted.py::test_write_below_python" in out, out
    # the project itself is untouched, and so is the folder outside
    assert sorted(p.name for p in (planted / "tests").iterdir()) == before
    if sys.platform.startswith("linux") and (backend == "docker" or sandbox.landlock_abi() >= 1):
        assert list(outside.iterdir()) == []
    assert not (outside / "planted.txt").exists()


# Tests that tidy up after themselves in their own temp folder. Python removes a folder tree by names beside an
# open folder (`os.unlink(name, dir_fd=...)`), and so does `tempfile.TemporaryDirectory` when it ends.
TIDY = '''
import os, shutil, tempfile
from pathlib import Path

def test_a_temp_folder_is_cleaned_up():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "a", "b"))
        Path(d, "a", "b", "f.txt").write_text("x")
    assert not os.path.exists(d)

def test_a_tree_is_removed(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f.txt").write_text("x")
    shutil.rmtree(tmp_path / "a")
    assert not (tmp_path / "a").exists()

def test_names_beside_an_open_folder(tmp_path):
    if os.unlink not in os.supports_dir_fd:
        return
    (tmp_path / "f.txt").write_text("x")
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        os.mkdir("made", dir_fd=fd)
        os.rename("f.txt", "g.txt", src_dir_fd=fd, dst_dir_fd=fd)
        os.remove("g.txt", dir_fd=fd)
        os.rmdir("made", dir_fd=fd)
    finally:
        os.close(fd)
    assert list(tmp_path.iterdir()) == []
'''

# The same way of naming a file, used to reach a file outside the tests' copy from a folder the tests may write in.
REACH = '''
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = Path((HERE / "where.txt").read_text(encoding="utf-8").strip())

def test_remove_a_file_outside_beside_an_open_folder(tmp_path):
    os.chdir(tmp_path)
    fd = os.open(OUT, os.O_RDONLY)
    try:
        os.remove("keep.txt", dir_fd=fd)
    finally:
        os.close(fd)
'''


def _tiny(folder: Path, source: str) -> Path:
    (folder / "tests").mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    (folder / "tests" / "keep.txt").write_text("kept", encoding="utf-8")
    return folder


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_tidy_their_own_temp_folder_are_not_refused(backend, tmp_path):
    """Found 2026-11-11 by the behaviour runner's first run: the guard read a name given beside an open folder as a
    name in the current folder (the project's copy, read-only), so every `shutil.rmtree` and every
    `TemporaryDirectory` in a project's tests failed in the sandbox and was reported as a refused write."""
    r = sandbox.run(_tiny(tmp_path / "tiny", TIDY), ["python", "-m", "pytest", "-q", "-p", "no:randomly"],
                    log=lambda m: None, backend=backend)
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []


@pytest.mark.skipif(os.unlink not in os.supports_dir_fd, reason="needs names beside an open folder (not on Windows)")
@pytest.mark.parametrize("backend", BACKENDS)
def test_a_file_outside_named_beside_an_open_folder_is_refused_and_reported(backend, tmp_path, outside):
    """The dangerous twin: the name is read where the open folder is, not where the tests happen to stand. (Until
    2026-11-13 the folder was the project's copy, which the tests could not change either; now it is a folder
    outside the copy, which is what they still cannot change.)"""
    repo = _tiny(tmp_path / "tiny", REACH)
    (outside / "keep.txt").write_text("kept", encoding="utf-8")
    (outside / "keep.txt").chmod(0o666)
    # a container has its own files: there the folder outside is one of the container's, which holds no such file
    (repo / "tests" / "where.txt").write_text("/usr" if backend == "docker" else str(outside), encoding="utf-8")
    r = sandbox.run(repo, ["python", "-m", "pytest", "-q", "-p", "no:randomly"], log=lambda m: None, backend=backend)
    assert r["returncode"] == 1, r["output_tail"]
    assert any(b["kind"] == "write" and "keep.txt" in b["what"] for b in r["blocked"]), r["blocked"]
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "kept"
    assert (repo / "tests" / "keep.txt").read_text(encoding="utf-8") == "kept"


LOOP = '''
import asyncio, threading

def test_an_event_loop_runs_and_a_thread_can_wake_it():
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        threading.Thread(target=lambda: loop.call_soon_threadsafe(done.set_result, "woken")).start()
        return await asyncio.wait_for(done, 20)
    assert asyncio.run(main()) == "woken"
'''


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_use_an_event_loop_run_except_on_windows_where_the_guard_still_refuses_them(backend, tmp_path):
    """Every async test, and every test of a FastAPI or Starlette app through its test client, starts an event loop.

    Known and not fixed on Windows (found 2026-11-11): there Python makes the pair of sockets a loop wakes itself
    with out of a listener on this computer, the guard refuses the listener, and the test fails. The guard does not
    let that listener through, because the loop Windows uses by default connects with a call the guard is never
    told about: a loop that could start could connect with nothing seen. This test says so on Windows itself, so the
    day a loop starts there it fails, and is rewritten together with a guard that sees what such a loop connects to."""
    r = sandbox.run(_tiny(tmp_path / "tiny", LOOP), ["python", "-m", "pytest", "-q", "-p", "no:randomly"],
                    log=lambda m: None, backend=backend)
    if sys.platform == "win32":
        assert r["returncode"] != 0, r["output_tail"]
        assert any(b["kind"] == "network" for b in r["blocked"]), (r["blocked"], r["output_tail"])
        return
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []


def _guard_alone(tmp_path, code: str, *args: str, first: str = "", net: str | None = None) -> subprocess.CompletedProcess:
    """A Python program with the sandbox's guard and nothing else around it, as on a system with no kernel layer.
    `net` is what a launcher would have said about the network (LANTERN_SANDBOX_NET); nothing is said unless the
    test says it: when these tests themselves run in a sandbox, the word of the sandbox around them is not theirs."""
    hook, room = tmp_path / "hook", tmp_path / "room"
    hook.mkdir(exist_ok=True)
    room.mkdir(exist_ok=True)
    (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(hook), "LANTERN_SANDBOX_WRITABLE": str(room)}
    env.pop("LANTERN_SANDBOX_NET", None)
    if net is not None:
        env["LANTERN_SANDBOX_NET"] = net
    return subprocess.run([sys.executable, "-c", first + textwrap.dedent(code), *args], cwd=room, env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


# What Windows has in place of a real socket pair, used here so that the defect can be seen on every system.
THE_WINDOWS_WAY = "import socket\nsocket.socketpair = socket._fallback_socketpair\n"


@pytest.mark.skipif(not hasattr(socket, "_fallback_socketpair"), reason="this Python has no such function to borrow")
def test_an_event_loop_whose_socket_pair_is_made_the_windows_way_does_not_start_which_is_known_and_not_fixed(tmp_path):
    """The defect of the test above, on every system: the pair is a listener on this computer and a connection to
    it, the guard refuses the listener, and the loop never starts."""
    r = _guard_alone(tmp_path, '''
        import asyncio, sys
        assert sys.lantern_sandbox_guard == "on"
        async def main():
            return "ran"
        print(asyncio.run(main()))
    ''', first=THE_WINDOWS_WAY)
    assert r.returncode != 0 and "ran" not in r.stdout, r.stdout
    assert "PermissionError" in r.stderr and sandbox.MARK + " network bind" in r.stderr, r.stderr[-2000:]


def test_the_guard_refuses_every_listener_and_every_connection_on_this_computer_too(tmp_path):
    """Nothing on this computer is let through either: another program's listener, a listener of the program's own
    (at a port the system picks or one it picked, at one address or at all of them), and sending without connecting."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as somebody_else:
        somebody_else.bind(("127.0.0.1", 0))
        somebody_else.listen()
        somebody_else.setblocking(False)
        r = _guard_alone(tmp_path, '''
            import socket, sys
            port = int(sys.argv[1])
            def refused(what, do):
                try:
                    do()
                except PermissionError as e:
                    print("refused:", what)
                else:
                    print("ALLOWED:", what)
            def connect(to):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect(to)
            def bind(at):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(at)
            def send():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"x", ("127.0.0.1", port))
            refused("another program's listener", lambda: connect(("127.0.0.1", port)))
            refused("a listener of its own", lambda: bind(("127.0.0.1", 0)))
            refused("a port it picked", lambda: bind(("127.0.0.1", 8765)))
            refused("every address at once", lambda: bind(("0.0.0.0", 0)))
            refused("every address at once, unnamed", lambda: bind(("", 0)))
            refused("sending without connecting", send)
        ''', str(somebody_else.getsockname()[1]))
        with pytest.raises(BlockingIOError):
            somebody_else.accept()                      # nobody came
    assert r.stdout.splitlines() == [
        "refused: another program's listener", "refused: a listener of its own", "refused: a port it picked",
        "refused: every address at once", "refused: every address at once, unnamed",
        "refused: sending without connecting"], r.stdout + r.stderr[-2000:]


DATABASE = '''
import sqlite3
from pathlib import Path

def test_a_database_file_of_the_project_can_be_read():
    conn = sqlite3.connect(Path(__file__).parent / "fixture.db")
    assert conn.execute("SELECT text FROM notes").fetchall() == [("kept",)]
    conn.close()

def test_a_database_of_the_tests_own_is_made_and_filled(tmp_path):
    conn = sqlite3.connect(tmp_path / "mine.db")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    assert conn.execute("SELECT count(*) FROM t").fetchone() == (1,)
    assert sqlite3.connect(":memory:").execute("SELECT 1").fetchone() == (1,)
'''


def _database(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE notes (text)")
    conn.execute("INSERT INTO notes VALUES ('kept')")
    conn.commit()
    conn.close()
    return path


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_read_a_database_file_of_the_project_and_fill_their_own_are_not_refused(backend, tmp_path):
    repo = _tiny(tmp_path / "tiny", DATABASE)
    _database(repo / "tests" / "fixture.db")
    r = sandbox.run(repo, ["python", "-m", "pytest", "-q", "-p", "no:randomly"], log=lambda m: None, backend=backend)
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []


def test_the_guard_refuses_a_database_file_outside_the_temp_folder_that_could_be_changed(tmp_path):
    """SQLite opens and writes its files itself, below Python, so the guard never saw them: where no kernel layer
    stands behind the guard (macOS, Windows, old kernels) a test could change any database file its user can."""
    theirs = _database(tmp_path / "theirs.db")
    r = _guard_alone(tmp_path, '''
        import os, sqlite3, sys
        theirs = sys.argv[1]
        def refused(what, do):
            try:
                do()
            except PermissionError:
                print("refused:", what)
            except sqlite3.Error as e:
                print("OPENED:", what, e)
            else:
                print("OPENED:", what)
        def change(path, **how):
            conn = sqlite3.connect(path, **how)
            conn.execute("DELETE FROM notes")
            conn.commit()
        refused("a database outside", lambda: change(theirs))
        refused("the same as bytes", lambda: change(os.fsencode(theirs)))
        refused("the same as an address", lambda: change("file:" + theirs + "?mode=rw", uri=True))
        refused("a new one beside it", lambda: sqlite3.connect(os.path.join(os.path.dirname(theirs), "new.db")).execute("CREATE TABLE t (x)"))
        mine = sqlite3.connect("mine.db")           # the program stands in its own room
        mine.execute("CREATE TABLE t (x)")
        mine.commit()
        print("made: its own", sqlite3.connect(":memory:").execute("SELECT 1").fetchone(),
              sqlite3.connect("file:scratch?mode=memory", uri=True).execute("SELECT 2").fetchone())
    ''', str(theirs))
    assert r.stdout.splitlines() == ["refused: a database outside", "refused: the same as bytes", "refused: the same as an address",
                                     "refused: a new one beside it", "made: its own (1,) (2,)"], r.stdout + r.stderr[-2000:]
    assert sqlite3.connect(theirs).execute("SELECT text FROM notes").fetchall() == [("kept",)]
    assert not (tmp_path / "new.db").exists()
    assert r.stderr.count(sandbox.MARK) == 4


def test_the_guard_refuses_a_question_about_a_name_asked_the_older_ways_too(tmp_path):
    """`socket.getaddrinfo` was refused; `gethostbyname`, `gethostbyname_ex` and `gethostbyaddr` put the same
    question to the same resolver and were not. The safe twins: this computer under its own names."""
    r = _guard_alone(tmp_path, '''
        import socket
        def refused(what, do):
            try:
                do()
            except PermissionError:
                print("refused:", what)
            except OSError as e:
                print("ASKED:", what, type(e).__name__)
            else:
                print("ASKED:", what)
        refused("getaddrinfo", lambda: socket.getaddrinfo("lantern-test.invalid", 80))
        refused("gethostbyname", lambda: socket.gethostbyname("lantern-test.invalid"))
        refused("gethostbyname_ex", lambda: socket.gethostbyname_ex("lantern-test.invalid"))
        refused("gethostbyaddr", lambda: socket.gethostbyaddr("192.0.2.1"))
        print(socket.gethostbyname("localhost"), socket.gethostbyname("127.0.0.1"))
        import sys
        sys.audit("socket.gethostbyaddr", socket.gethostname())   # what socket.getfqdn() asks, without the resolver
        print(bool(socket.getaddrinfo("localhost", 80)), True)
    ''')
    assert r.stdout.splitlines() == ["refused: getaddrinfo", "refused: gethostbyname", "refused: gethostbyname_ex",
                                     "refused: gethostbyaddr", "127.0.0.1 127.0.0.1", "True True"], r.stdout + r.stderr[-2000:]
    assert r.stderr.count(sandbox.MARK) == 4            # this computer's own name is not written down as refused


def _alive(pid: int) -> bool:
    if sys.platform == "win32":   # asked of Windows itself (os.kill would end the process there)
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype, k32.OpenProcess.argtypes = ctypes.c_void_p, [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = k32.OpenProcess(0x1000, 0, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_uint32(0)
        ok = k32.GetExitCodeProcess(handle, ctypes.byref(code))
        k32.CloseHandle(handle)
        return bool(ok) and code.value == 259      # STILL_ACTIVE
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
    if backend == "subprocess":   # Windows too, since 2026-11-10 (the Job Object)
        pid = next(int(x.split()[1]) for x in r["output_tail"].splitlines() if x.startswith("GRANDCHILD"))
        assert not _alive(pid), "a process the tests started survived the wall clock"
    if backend == "docker":
        left = subprocess.run(["docker", "ps", "-aq", "--filter", "name=lantern-sbx-"], capture_output=True, text=True)
        assert not left.stdout.strip(), "the container was not removed"


def test_the_tests_get_a_temp_copy_which_is_removed(tmp_path, monkeypatch):
    """What the tests may and may not change there: `tests/test_sandbox_copy.py`."""
    seen = {}
    real = sandbox._stream

    def spy(cmd, cwd, env, timeout, log, **more):
        seen["cwd"], seen["env"] = Path(cwd), env
        return real(cmd, cwd, env, timeout, log, **more)
    monkeypatch.setattr(sandbox, "_stream", spy)
    monkeypatch.setenv("LANTERN_TEST_SECRET", "s3cret")
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
    sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda m: None, backend="subprocess")
    assert seen["cwd"] != repo and "lantern-sandbox-" in str(seen["cwd"])   # a copy, not the project
    assert "LANTERN_TEST_SECRET" not in seen["env"] and "lantern-sandbox-" in seen["env"]["HOME"]
    assert not seen["cwd"].exists()   # deleted after


def test_backend_choice_and_description(monkeypatch, tmp_path):
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    d = sandbox.describe(tmp_path, "python")
    assert d["name"] == "subprocess" and any("a fresh copy of your project" in x for x in d["details"])
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
