"""Every program of a project's Python tests inside a wall of Windows' own around the run (a firm pass or fail,
stage 4, step 5, 2026-11-20).

On Linux the kernel keeps every program of a run to the run's walls, whatever language it is written in. On Windows
Lantern's guard is inside Python, and the one wall Windows gives a program without the administrator is an
AppContainer: a token of its own kind, with which Windows keeps the program from every file and folder that is not
given to it and from the network, and every program it starts is in the same container (`lantern.wincontainer`).

The wall is put up for a project's own Python tests where they run on the libraries fetched for them, and so on a
whole Python of the run's own (`sandbox._whole_python`), which lies in the run's folder, where the wall may read it.
Then every program the tests start, Python or not (the shell, curl, a compiled helper), is inside it. Each test here
sits beside a twin the wall must not stop: the run's own file is read, the test's own server answers, and what an
honest Python test does with pipes and programs of its own still works there (a pool of processes, a program started
from the event loop, a second program's server and datagram socket), while what the guard refuses stays refused and
is named.

The stores are stand-ins on this computer (`tests/stores.py`); the address outside is one kept for examples
(RFC 5737), which no computer answers."""
import itertools
import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from stores import PyStore
from test_libraries import UNITTEST, _online, _py_project
from test_sandbox_windows import _named, _Outside

from lantern import _jail, sandbox, wincontainer

WINDOWS = sys.platform == "win32"
ONLY_WINDOWS = pytest.mark.skipif(not WINDOWS, reason="an AppContainer is Windows' own")
WORDS = "the person's own words"
# what the project's test printed about each try (unittest -v may put its own words in front on the same line)
TRIED = re.compile(r"tried ([^:]+): (\S+)\s*$")
WALL = "a wall of Windows' own made for this run"

# The project's test: the library fetched for it is there, then each try of the case is made and its outcome
# printed as one word. A try that raises says the kind of error.
HEAD = '''import os
import socket
import subprocess
import sys
import threading
import time
import unittest

import stage2sample

SYSTEM = os.path.join(os.environ.get("SYSTEMROOT", "C:\\\\Windows"), "System32")
WORDS = {words!r}
SERVES = ("import socket; s = socket.create_server(('127.0.0.1', 0)); print(s.getsockname()[1], flush=True); "
          "c, _ = s.accept(); c.sendall(b'w'); c.close()")
HEARS = ("import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0)); "
         "print(s.getsockname()[1], flush=True); print(s.recv(16).decode(), flush=True)")


def tried(what, how):
    try:
        word = how()
    except Exception as e:
        word = type(e).__name__
    print("tried %s: %s" % (what, word), flush=True)


class T(unittest.TestCase):
    def test_it(self):
        self.assertEqual(stage2sample.answer(), 42)
'''


@pytest.fixture()
def pystore():
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        yield store


def _project(folder: Path, body: str) -> Path:
    """A project whose one library is fetched for its tests, with a file of its own (`own.txt`)."""
    repo = _py_project(folder)
    (repo / "own.txt").write_text(WORDS + "\n", encoding="utf-8")
    (repo / "test_it.py").write_text(HEAD.format(words=WORDS) + textwrap.indent(
        textwrap.dedent(body).strip("\n") + "\n", " " * 8), encoding="utf-8")
    return repo


def _run(repo: Path, monkeypatch, store) -> tuple[dict, dict, list[str]]:
    _online(monkeypatch, python=store)
    lines: list[str] = []
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    said = {}
    for line in lines:
        m = TRIED.search(line)
        if m:
            said[m.group(1)] = m.group(2)
    return said, res, lines


def _ran(res: dict) -> None:
    assert res["libraries"]["state"] == "fetched" and res["returncode"] == 0, res["output_tail"]


# --------------------------------------------------------------------------------- programs that are not Python
@ONLY_WINDOWS
def test_a_program_a_python_test_starts_reads_the_runs_own_file_and_not_yours(tmp_path, monkeypatch, pystore):
    person = tmp_path / "person"
    person.mkdir()
    (person / "notes.txt").write_text(WORDS + "\n", encoding="utf-8")
    said, res, lines = _run(_project(tmp_path / "proj", f'''
        def reads(path):
            def go():
                got = subprocess.run([os.path.join(SYSTEM, "cmd.exe"), "/d", "/c", "type", path],
                                     capture_output=True, text=True)
                return "read" if WORDS in got.stdout else "not-read"
            return go
        tried("your file", reads({str(person / "notes.txt")!r}))
        tried("the run's own file", reads("own.txt"))
    '''), monkeypatch, pystore)
    _ran(res)
    assert said == {"your file": "not-read", "the run's own file": "read"}, said


@ONLY_WINDOWS
def test_a_program_a_python_test_starts_reaches_the_tests_own_server_and_not_another_programs(tmp_path, monkeypatch,
                                                                                            pystore):
    with _Outside() as other:
        said, res, lines = _run(_project(tmp_path / "proj", f'''
            import http.server

            class Ok(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

                def log_message(self, *args):
                    pass
            own = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ok)
            threading.Thread(target=own.serve_forever, daemon=True).start()

            def curl(port):
                def go():
                    got = subprocess.run([os.path.join(SYSTEM, "curl.exe"), "-sS", "--max-time", "4",
                                          "http://127.0.0.1:%d/" % port], capture_output=True, text=True)
                    return "answered" if got.stdout == "ok" else "rc%d" % got.returncode
                return go
            tried("the test's own server", curl(own.server_address[1]))
            tried("another program's server", curl({other.where()["tcp"]}))
            own.shutdown()
        '''), monkeypatch, pystore)
        time.sleep(0.5)
        came = other.came()
    _ran(res)
    assert said["the test's own server"] == "answered", said
    assert said["another program's server"] != "answered" and came == [], (said, came)


@ONLY_WINDOWS
def test_a_program_a_python_test_starts_is_refused_an_address_outside_at_once(tmp_path, monkeypatch, pystore):
    said, res, lines = _run(_project(tmp_path / "proj", '''
        def outside():
            start = time.monotonic()
            got = subprocess.run([os.path.join(SYSTEM, "curl.exe"), "-sS", "--max-time", "6", "http://192.0.2.1:9/"],
                                 capture_output=True, text=True)
            took = time.monotonic() - start
            return "refused-at-once" if got.returncode == 7 and took < 3 else "rc%d-after-%ds" % (got.returncode, took)
        tried("an address outside", outside)
    '''), monkeypatch, pystore)
    _ran(res)
    assert said == {"an address outside": "refused-at-once"}, said


# --------------------------------------------------------------------------------- what Python's tests still do
HONEST = {
    "a pool of processes": '''
        def pool():
            import multiprocessing
            with multiprocessing.Pool(2) as p:
                return "ok" if p.map(abs, [-1, -2]) == [1, 2] else "wrong"
        tried("a pool of processes", pool)
    ''',
    "a program the event loop started": '''
        def loop():
            import asyncio

            async def main():
                child = await asyncio.create_subprocess_exec(sys.executable, "-c", "print('child')",
                                                             stdout=asyncio.subprocess.PIPE)
                out, _ = await child.communicate()
                return out.decode().strip()
            return "ok" if asyncio.run(main()) == "child" else "wrong"
        tried("a program the event loop started", loop)
    ''',
    "a second program's server": '''
        def second():
            child = subprocess.Popen([sys.executable, "-c", SERVES], stdout=subprocess.PIPE, text=True)
            try:
                port = int(child.stdout.readline())
                with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
                    return "ok" if c.recv(16) == b"w" else "wrong"
            finally:
                child.wait(30)
        tried("a second program's server", second)
    ''',
    "a second program's datagram socket": '''
        def datagram():
            child = subprocess.Popen([sys.executable, "-c", HEARS], stdout=subprocess.PIPE, text=True)
            try:
                port = int(child.stdout.readline())
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"d", ("127.0.0.1", port))
                return "ok" if child.stdout.readline().strip() == "d" else "wrong"
            finally:
                child.wait(30)
        tried("a second program's datagram socket", datagram)
    ''',
    "a file of the copy changed": '''
        def change():
            with open("own.txt", "a", encoding="utf-8") as f:
                f.write("more\\n")
            os.makedirs(os.path.join("made", "deeper"))
            with open(os.path.join("made", "deeper", "new.txt"), "w", encoding="utf-8") as f:
                f.write("new")
            os.replace(os.path.join("made", "deeper", "new.txt"), os.path.join("made", "moved.txt"))
            os.remove(os.path.join("made", "moved.txt"))
            with open("own.txt", encoding="utf-8") as f:
                return "ok" if f.read() == WORDS + "\\n" + "more\\n" else "wrong"
        tried("a file of the copy changed", change)
    ''',
    "the test's own server": '''
        def own():
            srv = socket.create_server(("127.0.0.1", 0))

            def answer():
                c, _ = srv.accept()
                c.sendall(b"x")
                c.close()
            threading.Thread(target=answer, daemon=True).start()
            try:
                with socket.create_connection(srv.getsockname(), timeout=10) as c:
                    return "ok" if c.recv(4) == b"x" else "wrong"
            finally:
                srv.close()
        tried("the test's own server", own)
    ''',
}


@ONLY_WINDOWS
@pytest.mark.parametrize("case", list(HONEST))
def test_what_an_honest_python_test_does_still_works_inside_the_wall(tmp_path, monkeypatch, pystore, case):
    said, res, lines = _run(_project(tmp_path / "proj", HONEST[case]), monkeypatch, pystore)
    _ran(res)
    assert said == {case: "ok"}, (said, res["blocked"])
    assert any(WALL in line for line in lines), lines


@ONLY_WINDOWS
def test_inside_the_wall_python_is_refused_another_programs_listener_and_datagram_socket_and_they_are_named(
        tmp_path, monkeypatch, pystore):
    with _Outside() as other:
        where = other.where()
        said, res, lines = _run(_project(tmp_path / "proj", f'''
            def listener():
                socket.create_connection(("127.0.0.1", {where["tcp"]}), timeout=5).close()
                return "reached"

            def datagram():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"u", ("127.0.0.1", {where["udp"]}))
                return "sent"
            tried("another program's listener", listener)
            tried("another program's datagram socket", datagram)
        '''), monkeypatch, pystore)
        time.sleep(0.5)
        came = other.came()
    _ran(res)
    assert said == {"another program's listener": "PermissionError",
                    "another program's datagram socket": "PermissionError"}, said
    assert came == [], came
    named = " ".join(_named(res))
    assert str(where["tcp"]) in named and str(where["udp"]) in named, res["blocked"]
    assert any(WALL in line for line in lines), lines


# --------------------------------------------------------------------------------- what the run says, what it leaves
MAPPINGS = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings"


def _mappings() -> list[tuple[str, str]] | None:
    """Every AppContainer profile Windows keeps for this user, as (its SID, its name), or None where the list
    cannot be opened."""
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, MAPPINGS)
    except OSError:
        return None
    rows: list[tuple[str, str]] = []
    with key:
        for i in itertools.count():
            try:
                sid = winreg.EnumKey(key, i)
            except OSError:
                break
            try:
                with winreg.OpenKey(key, sid) as one:
                    moniker = winreg.QueryValueEx(one, "Moniker")[0]
            except OSError:
                moniker = ""
            rows.append((sid, moniker if isinstance(moniker, str) else ""))
    return rows


def _profiles() -> dict[str, str]:
    """The profiles this program made that Windows still keeps: SID (in small letters) -> name. Windows may keep a
    profile's name in small letters (it did on GitHub's Windows machine), so names are compared without case."""
    mine = f"{wincontainer.PREFIX}{os.getpid()}.".lower()
    return {sid.lower(): name for sid, name in _mappings() or () if name.lower().startswith(mine)}


def _looked() -> str:
    """What the look for profiles found, in counts only (for an assertion's message)."""
    rows = _mappings()
    if rows is None:
        return "the list of profiles could not be opened"
    ours = wincontainer.PREFIX.lower()
    mine = f"{ours}{os.getpid()}."
    return (f"{len(rows)} profiles listed, {sum(1 for _, n in rows if not n)} without a name, "
            f"{sum(1 for _, n in rows if n.lower().startswith(ours))} of Lantern's, "
            f"{sum(1 for _, n in rows if n.lower().startswith(mine))} of this program")


@ONLY_WINDOWS
def test_the_run_says_its_tests_were_inside_the_wall_and_leaves_nothing_of_it(tmp_path, monkeypatch, pystore):
    box = wincontainer.Container()          # the way of looking for profiles sees one that is there
    try:
        assert box.text.lower() in _profiles(), _looked()
    finally:
        box.close()
    assert box.text.lower() not in _profiles(), _looked()
    said, res, lines = _run(_project(tmp_path / "proj", "pass"), monkeypatch, pystore)
    _ran(res)
    assert res["windows_wall"] is True, res
    assert any(WALL in line for line in lines), lines
    assert not any("did not delete the record of the wall" in line for line in lines), lines
    assert _profiles() == {}, _looked()


@ONLY_WINDOWS
@pytest.mark.parametrize("what", ["the wall", "a whole Python of the run's own"])
def test_tests_that_were_promised_the_wall_are_not_run_where_it_cannot_be_put_up(tmp_path, monkeypatch, pystore,
                                                                                 what):
    """The sheet said every program of the tests is kept from your files: where the wall then cannot be made, or
    the whole Python it can hold them on, the tests are not started, and the run says why in Lantern's words."""
    def refuse(*args, **kwargs):
        if what == "the wall":
            raise wincontainer.ContainerError("CreateAppContainerProfile", 0x80070005)
        raise OSError(28, "no room")
    assert sandbox.wall_here() == ""            # asked once, before the wall is made to fail
    assert sandbox.reach("python", fetched=True)["files"] == "all"
    if what == "the wall":
        monkeypatch.setattr(wincontainer, "Container", refuse)
    else:
        monkeypatch.setattr(sandbox, "_whole_python", refuse)
    repo = _project(tmp_path / "proj", 'print("PLANTED-RAN")')
    with pytest.raises(sandbox.Unavailable) as e:
        _run(repo, monkeypatch, pystore)
    if what == "the wall":
        assert str(e.value) == sandbox.NO_WALL + " (error 0x80070005)", e.value
    else:
        assert str(e.value) == sandbox.NO_WALL_PYTHON, e.value


@ONLY_WINDOWS
def test_where_this_computer_makes_no_wall_the_tests_run_as_before_and_the_sheet_says_so(tmp_path, monkeypatch,
                                                                                       pystore):
    monkeypatch.setattr(sandbox, "_WALL_HERE", ["this Windows makes no AppContainer for Lantern"])
    r = sandbox.reach("python", fetched=True)
    assert (r["network"], r["files"]) == ("python", "python"), r
    said, res, lines = _run(_project(tmp_path / "proj", "pass"), monkeypatch, pystore)
    _ran(res)
    assert res["windows_wall"] is False and not any(WALL in line for line in lines), lines


@ONLY_WINDOWS
def test_the_sheet_says_what_the_wall_holds_and_asks_for_what_it_does_not(tmp_path):
    r = sandbox.reach("python", fetched=True)
    assert (r["network"], r["files"]) == ("python", "all"), r
    assert WALL in r["ask"] and "not every way" in r["ask"], r
    assert "read and change the files" not in r["ask"], r
    plain = sandbox.reach("python")             # no libraries fetched: the tests run on this computer's Python
    assert (plain["network"], plain["files"]) == ("python", "python"), plain
    assert WALL not in plain["ask"], plain
    for language in ("node", "go"):             # tests that are not Python stay outside the wall
        assert WALL not in sandbox.reach(language, fetched=True)["ask"]


# --------------------------------------------------------------------------------- on every system, with stand-ins
@pytest.mark.parametrize("promised", [True, False])
def test_the_recorder_starts_no_test_outside_the_wall_it_was_promised(tmp_path, promised):
    """`LANTERN_SANDBOX_CONTAINER` tells the recorder that its tests were to run inside a wall of Windows' own; the
    guard marks a Python that Windows says is inside that wall (`sys.lantern_sandbox_wall`). Without the mark the
    recorder starts nothing and says so the way the launcher does. The twin: nothing was promised, and the same
    test runs."""
    (tmp_path / "planted.py").write_text("print('PLANTED-RAN')\n", encoding="utf-8")
    hook = tmp_path / "hook"
    hook.mkdir()
    tracer = sandbox._tracer(hook)          # the recorder as the sandbox hands it to tests on fetched libraries
    env = {k: v for k, v in os.environ.items() if not k.startswith("LANTERN_SANDBOX")}
    if promised:
        env["LANTERN_SANDBOX_CONTAINER"] = "S-1-15-2-1-2-3-4-5-6-7"
    r = subprocess.run([sys.executable, str(tracer), str(tmp_path / "trace.json"), str(tmp_path), "--",
                        str(tmp_path / "planted.py")], capture_output=True, text=True, encoding="utf-8", env=env,
                       cwd=str(tmp_path), timeout=120)
    if promised:
        assert r.returncode == _jail.UNAVAILABLE and "PLANTED-RAN" not in r.stdout, (r.stdout, r.stderr)
        assert sandbox._unavailable(r.returncode, r.stdout + r.stderr) == _jail.REASONS["container"], r.stderr
    else:
        assert r.returncode == 0 and "PLANTED-RAN" in r.stdout, (r.stdout, r.stderr)


BROKER = "\\\\.\\pipe\\lantern-broker-" + "0" * 32
PIPES_ALONE = r'''
import json, sitecustomize as g
g._BROKER_PIPE = "lantern-broker-" + "0" * 32
names = json.loads(input())
local = [g._local(name) for name in names]
same_bytes = g._local(b"\\\\.\\pipe\\x") == b"\\\\.\\pipe\\x"
broker = "\\\\.\\pipe\\lantern-broker-" + "0" * 32
place = [g._windows_place(broker)[1], g._windows_place(broker, made=True)[0] is not None,
         g._windows_place("\\\\.\\pipe\\lantern-broker-" + "1" * 32)[0] is not None]
g._IN_WALL = True
inside = [g._pipe_pid(n) for n in ("LOCAL\\pyc-12-3", "local\\python-pipe-7-x", "pyc-12-3", "LOCAL\\other",
                                   "LOCAL\\LOCAL\\pyc-1-2")]
g._IN_WALL = False
outside = [g._pipe_pid(n) for n in ("LOCAL\\pyc-12-3", "pyc-12-3")]
print(json.dumps({"local": local, "bytes": same_bytes, "place": place, "inside": inside, "outside": outside}))
'''


def test_inside_the_wall_a_pipe_of_the_run_is_named_among_the_walls_own_names(tmp_path):
    """Inside the wall Windows lets a program make a pipe only among the wall's own names (`\\\\.\\pipe\\LOCAL\\`),
    and finds it there for the wall's programs alone (round 2 on GitHub's Windows machine: a pool of processes, a
    manager and the event loop's programs failed until their pipes were named there). The guard names there every
    pipe a program of the run names, in either way of writing a pipe's name, and reads the program that made it
    from that name; the launcher's pipe stays where it is, and may be opened but not made. Read here from the guard
    by itself, on every system (`_local`, `_pipe_pid`, `_windows_place`)."""
    plain, local = "\\\\.\\pipe\\", "\\\\.\\pipe\\LOCAL\\"
    names = [plain + "pyc-12-3", "\\\\?\\pipe\\pyc-12-3", "\\\\.\\PIPE\\x", local + "x", plain + "local\\x", BROKER,
             "C:\\x\\pipe\\y", "\\\\.\\pipe", "//./pipe/x"]
    said = _said_alone(tmp_path, names)
    assert said["local"] == [local + "pyc-12-3", local + "pyc-12-3", local + "x", local + "x", plain + "local\\x",
                             BROKER, "C:\\x\\pipe\\y", "\\\\.\\pipe", "//./pipe/x"], said["local"]
    assert said["bytes"] is True
    assert said["place"] == [True, True, True], said["place"]
    assert said["inside"] == [12, 7, 12, None, None] and said["outside"] == [None, 12], said


def _said_alone(tmp_path, names: list[str]) -> dict:
    """What the guard by itself says of `names` (`PIPES_ALONE`), in a Python of its own as `_guard_alone` starts
    one, with the names handed over on its input."""
    hook, room = tmp_path / "hook", tmp_path / "room"
    hook.mkdir(exist_ok=True)
    room.mkdir(exist_ok=True)
    (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(hook), "LANTERN_SANDBOX_WRITABLE": str(room)}
    for k in [k for k in env if k.startswith("LANTERN_SANDBOX_") and k != "LANTERN_SANDBOX_WRITABLE"]:
        env.pop(k)
    r = subprocess.run([sys.executable, "-c", PIPES_ALONE], input=json.dumps(names) + "\n", cwd=room, env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_a_run_promised_the_wall_starts_no_test_without_a_whole_python_of_its_own(tmp_path, monkeypatch, pystore):
    """Where the wall is made (`wall_here`) for Python's tests on fetched libraries, it can hold them only on a
    whole Python of the run's own, which lies where it may read it: where none is made the tests are not started,
    whatever else could run them. On every system: elsewhere than on Windows no whole Python is made at all, so a
    pretend system that makes the wall shows the refusal (the run itself is real)."""
    whole = sandbox._whole_python
    monkeypatch.setattr(sandbox, "docker_ok", lambda: False)
    monkeypatch.setattr(sandbox, "_WALL_HERE", [""])
    if WINDOWS:
        def refuse(home, named, timeout=120):
            raise OSError(28, "no room")
        monkeypatch.setattr(sandbox, "_whole_python", refuse)
    repo = _project(tmp_path / "proj", 'print("PLANTED-RAN")')
    _online(monkeypatch, python=pystore)
    lines: list[str] = []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert str(e.value) == sandbox.NO_WALL_PYTHON and not any("PLANTED-RAN" in line for line in lines), lines
    # the twin: the same tests where no wall is made run as before
    monkeypatch.setattr(sandbox, "_WALL_HERE", ["this computer makes no wall of Windows' own"])
    monkeypatch.setattr(sandbox, "_whole_python", whole)
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0 and res["windows_wall"] is False, res["output_tail"]
