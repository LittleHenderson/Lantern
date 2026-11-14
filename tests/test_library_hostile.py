"""Hostile libraries beside safe twins (a firm pass or fail, stage 2).

A project's tests run the code of every library the project names, and of every library those need. Nobody who
runs the tests has read that code. So here are libraries that do what a planted one would: look for keys (in the
environment, in the person's key files by their full path, in what another program was started with), reach for
another address, write outside the run's folders, bring code that runs before any test asks for it, and try to
run code or to write outside while they are being fetched. Each stands beside a twin that does the honest thing,
which has to keep working: a wall that stops the tests too is no wall.

What a library says it managed is printed by the project's one test (`SAID`), and each case also looks at the
world outside the run: the folder anybody may write into, the person's project, the other server's record of who
called.

Found by these tests on the first run: a key file named by its full path was read (Lantern as an ordinary user,
and as root wherever the file is one every user may read): until this step the kernel's rules were about writes
only. Now the person's own folders are closed to the tests' reads (`sandbox.read_wall`): the home folder, the
session's folder, the shared temp folders, other disks, the project's own folder (the tests run on a copy).

Programs that are not Python are held by the kernel alone, so those cases need Linux with Landlock; a way from
such a program to another program through a socket file, and a name it looks up, are step 6's
(`tests/test_sandbox_sockets.py`).

No test here reaches the internet: the stores are stand-ins on this computer (`tests/stores.py`), the address
"outside" is one that is nobody's (192.0.2.1), the name one that never exists (`example.invalid`)."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from stores import NpmStore, PyStore
from test_libraries import UNITTEST, WALLS, _files, _online, needs_npm

from lantern import _jail, libraries, sandbox

LINUX = sys.platform.startswith("linux")
KERNEL = LINUX and sandbox.landlock_abi() >= 1
kernel = pytest.mark.skipif(not KERNEL, reason="needs Linux with Landlock (what holds a program that is not Python)")
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
QUIET = lambda line: None       # noqa: E731
LAUNCHER = "import sys; from lantern._jail import main; main(sys.argv[1:])"
HERE = Path(_jail.__file__).resolve().parent.parent


@pytest.fixture()
def pystore():
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        yield store


@pytest.fixture()
def npmstore():
    with NpmStore() as store:
        yield store


@pytest.fixture()
def other():
    """A server on this computer that is none of the tests': it writes down every call."""
    with PyStore() as server:
        server.pages["/secret"] = ("text/plain", b"not for the tests")
        yield server


@pytest.fixture(params=WALLS)
def walls(request, monkeypatch):
    """Both ways a run is held (`tests/test_libraries.py`): with a network of its own, and without one."""
    if request.param == "doorkeeper":
        monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
        # inside a sandbox that makes every connection for what runs in it, that sandbox judges an address
        held = LINUX and sandbox.landlock_abi() >= 4 and sandbox.own_sockets() != sandbox.DOORMAN_ABOVE
        return "port-rule" if held else "told"
    return request.param


@pytest.fixture()
def person(monkeypatch):
    """What is the person's own on this computer: a home folder with a key file in it that every user may read,
    as such files often are (`.npmrc`, `.git-credentials`, a `.env` of another project), and a folder anybody
    may write into with a file of theirs in it. HOME names the home folder, as it does for whoever runs Lantern."""
    top = Path(tempfile.mkdtemp(prefix="lantern-test-person-"))
    try:
        home, drop = top / "home", top / "drop"
        (home / ".ssh").mkdir(parents=True)
        drop.mkdir()
        secret = "PLANTED-" + os.urandom(8).hex()
        (home / ".ssh" / "id_planted").write_text(secret + "\n", encoding="utf-8")
        (drop / "kept.txt").write_text("the person's own\n", encoding="utf-8")
        for path, mode in ((top, 0o755), (home, 0o755), (home / ".ssh", 0o755), (home / ".ssh" / "id_planted", 0o644),
                           (drop, 0o777), (drop / "kept.txt", 0o666)):
            os.chmod(path, mode)
        monkeypatch.setenv("HOME", str(home))
        yield SimpleNamespace(top=top, home=home, key=home / ".ssh" / "id_planted", secret=secret, drop=drop)
    finally:
        assert sandbox._rm(top) is True


@pytest.fixture()
def another_program(person):
    """Another program of the user the tests run as, started with a key in its environment: the shell the person
    started Lantern from, an editor, an agent."""
    more = {"user": 65534, "group": 65534, "extra_groups": []} if ROOT else {}
    program = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(600)"], cwd=str(person.home),
                               env={"PATH": os.environ.get("PATH", ""), "PLANTED_API_KEY": person.secret}, **more)
    try:
        yield program
    finally:
        program.kill()
        program.wait()


# What every hostile library starts with: each thing it tries is written down as "got ..." or "refused ...".
HEAD = '''import os
import subprocess
import sys
import tempfile

SAID = {}
TMP = tempfile.gettempdir()


def attempt(name, fn):
    try:
        SAID[name] = "got " + repr(fn())[:70]
    except BaseException as e:      # whatever the sandbox answers with
        SAID[name] = "refused " + type(e).__name__


def run(*cmd):
    done = subprocess.run(list(cmd), capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise PermissionError(done.returncode, (done.stderr or "")[-200:])
    return done.stdout.strip()


'''


def _project(folder: Path, name: str, also: str = "") -> Path:
    """A project that names the library `name`; its one test imports it and prints what the library says."""
    folder.mkdir(parents=True)
    (folder / "requirements.txt").write_text(f"{name}==1.0.0\n{also}", encoding="utf-8")
    (folder / "test_it.py").write_text(
        "import json\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        import {name}\n        print('SAID ' + json.dumps({name}.SAID))\n", encoding="utf-8")
    return folder


def _said(res) -> dict:
    lines = [line for line in res["output_tail"].splitlines() if line.startswith("SAID ")]
    assert len(lines) == 1, res["output_tail"]
    return json.loads(lines[0][5:])


def _split(said: dict) -> tuple[dict, dict]:
    return ({k: v for k, v in said.items() if not k.startswith("twin: ")},
            {k: v for k, v in said.items() if k.startswith("twin: ")})


def _unchanged(person, repo: Path, before: set[str]) -> None:
    """Nothing of the person's own was written, removed or changed."""
    assert _files(person.drop) == {"kept.txt"}
    assert (person.drop / "kept.txt").read_text(encoding="utf-8") == "the person's own\n"
    assert os.stat(person.drop / "kept.txt").st_mode & 0o777 == 0o666
    assert (person.key).read_text(encoding="utf-8") == person.secret + "\n"
    assert _files(repo) == before
    assert "changed" not in (repo / "test_it.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------- a library that looks for keys
PLANTED_NAMES = ("ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "LANTERN_TOKEN",
                 "DATABASE_PASSWORD", "PIP_INDEX_URL")

IN_THE_ENVIRONMENT = HEAD + '''attempt("names", lambda: sorted(k for k in os.environ if any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSW"))))
attempt("what they hold", lambda: sorted(k for k, v in os.environ.items() if "PLANTED" in v))
attempt("a python it starts", lambda: run(sys.executable, "-c", "import os; print(sorted(k for k, v in os.environ.items() if 'PLANTED' in v))"))
attempt("twin: what the tests are told", lambda: os.environ["CI"])
'''


def test_a_library_finds_no_key_in_the_environment(tmp_path, monkeypatch, pystore):
    """On every system: what the person's shell holds is not handed to the tests, so there is nothing to find."""
    for name in PLANTED_NAMES:
        monkeypatch.setenv(name, "PLANTED-" + name.lower())
    pystore.add("stage2env", "1.0.0", {"stage2env/__init__.py": IN_THE_ENVIRONMENT})
    _online(monkeypatch, python=pystore)
    res = sandbox.run(_project(tmp_path / "proj", "stage2env"), UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert _said(res) == {"names": "got []", "what they hold": "got []", "a python it starts": "got '[]'",
                          "twin: what the tests are told": "got 'true'"}
    assert "PLANTED" not in res["output_tail"]
    assert res["blocked"] == []         # an honest run: nothing was refused, and nothing is said to have been


KEY_FILES = '''KEY, HOME, PID = {key!r}, {home!r}, {pid}
attempt("the key file", lambda: open(KEY).read())
attempt("the key file, by its number", lambda: os.read(os.open(KEY, os.O_RDONLY), 200))
attempt("the key file, through a link", lambda: (os.symlink(KEY, TMP + "/link"), open(TMP + "/link").read())[1])
attempt("the key file, under a second name", lambda: (os.link(KEY, TMP + "/second"), open(TMP + "/second").read())[1])
attempt("the key file, another program", lambda: run("cat", KEY))
attempt("the key file, a python without the guard", lambda: run(sys.executable, "-S", "-c", "print(open(%r).read())" % KEY))
attempt("the names in the key folder", lambda: os.listdir(os.path.dirname(KEY)))
attempt("the names in the home folder", lambda: os.listdir(HOME))
attempt("the names in the home folder, another program", lambda: run("ls", HOME))
attempt("what another program was started with", lambda: open("/proc/%d/environ" % PID, "rb").read())
attempt("what another program was started with, another program", lambda: run("cat", "/proc/%d/environ" % PID))
attempt("the folder another program works in", lambda: os.readlink("/proc/%d/cwd" % PID))
attempt("twin: its own file", lambda: len(open(__file__).read()) > 0)
attempt("twin: the project's file", lambda: open("requirements.txt").read().strip() != "")
attempt("twin: the project's file, another program", lambda: run("cat", "requirements.txt") != "")
attempt("twin: python's own library", lambda: len(open(os.__file__).read()) > 0)
attempt("twin: the system's files", lambda: len(os.listdir("/usr")) > 0 and len(open("/etc/passwd").read()) > 0)
attempt("twin: what it was started with itself", lambda: len(open("/proc/self/environ", "rb").read()) > 0)
attempt("twin: a temp file", lambda: (open(TMP + "/t.txt", "w").write("x"), open(TMP + "/t.txt").read())[1])
attempt("twin: the temp home", lambda: (open(os.path.expanduser("~/note"), "w").write("x"), os.listdir(os.path.expanduser("~")))[1])
attempt("twin: the folder it runs in", lambda: len(os.listdir(".")) > 0)
'''


@kernel
def test_a_library_cannot_read_what_is_the_persons_own(tmp_path, monkeypatch, pystore, person, another_program):
    """Named by its full path, whichever way it is opened and by whichever program: the key file, the names in
    the home folder, what another program of the same user was started with."""
    pystore.add("stage2keys", "1.0.0", {"stage2keys/__init__.py": HEAD + KEY_FILES.format(
        key=str(person.key), home=str(person.home), pid=another_program.pid)})
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2keys")
    before = _files(repo)
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    hostile, twins = _split(_said(res))
    assert len(hostile) == 12 and all(v.startswith("refused ") for v in hostile.values()), hostile
    assert len(twins) == 9 and all(v.startswith("got ") and "False" not in v for v in twins.values()), twins
    assert person.secret not in res["output_tail"]
    _unchanged(person, repo, before)
    # what Python's own code reached for is written down, the place and never what is in it (a second name for
    # the key file is something the guard itself refuses, as a change to a file that is not the run's own)
    reads = [b["what"] for b in res["blocked"] if b["kind"] == "read"]
    assert any(what.startswith(f"read of {person.key} ") for what in reads), res["blocked"]
    assert any(what.startswith(f"read of {person.home} ") for what in reads), res["blocked"]
    assert [b["what"].split()[0] for b in res["blocked"] if b["kind"] != "read"] == ["link"], res["blocked"]


@kernel
@pytest.mark.parametrize("reads", [True, False], ids=["after a read of the person's folder", "by themselves"])
def test_tests_that_fail_after_they_were_refused_are_told_from_tests_that_fail_by_themselves(
        tmp_path, monkeypatch, pystore, person, reads):
    """Tests that need a file of the person's own cannot have it here, and fail: that may be the sandbox's doing
    and not the code's, so the run says what was refused and the release decision does not count it as tests
    that failed. Tests that fail by themselves say nothing of the kind, and count."""
    from lantern import release
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2sample")
    wants = f"open({str(person.key)!r}).read()" if reads else "open('requirements.txt').read()"
    (repo / "test_it.py").write_text(
        "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        self.assertEqual({wants}, 'what the test expects')\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 1 and person.secret not in res["output_tail"], res["output_tail"]
    assert [b["kind"] for b in res["blocked"]] == (["read"] if reads else []), res["blocked"]
    said = release._tests(True, {"trace": {"ran": True, "returncode": 1, "blocked": res["blocked"]}})
    assert said["state"] == ("missing" if reads else "failed"), said


THROUGH_A_LINK = '''attempt("the key file, through the project's link", lambda: open("shared/.ssh/id_planted").read())
attempt("the key file, through the project's link, another program", lambda: run("cat", "shared/.ssh/id_planted"))
attempt("the names in the home folder, through the project's link", lambda: os.listdir("shared"))
attempt("the names in the home folder, as a folder to look through", lambda: [e.name for e in os.scandir("shared")])
attempt("twin: where the link leads", lambda: os.readlink("shared"))
attempt("twin: a file through a link that stays in the project", lambda: open("inner/notes.txt").read())
attempt("twin: the names through a link that stays in the project", lambda: os.listdir("inner"))
'''


@kernel
def test_a_link_the_project_brings_is_no_way_into_the_persons_own_folders(tmp_path, monkeypatch, pystore, person):
    """A project's folder may hold a link to anywhere (a clone made by Lantern holds none): the copy keeps it as a
    link, and what it leads to is closed like any other of the person's own, and named by the place it leads to.
    A link that stays inside the project works as it does at home."""
    pystore.add("stage2links", "1.0.0", {"stage2links/__init__.py": HEAD + THROUGH_A_LINK})
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2links")
    (repo / "data").mkdir()
    (repo / "data" / "notes.txt").write_text("the project's own\n", encoding="utf-8")
    os.symlink(person.home, repo / "shared")
    os.symlink("data", repo / "inner")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    hostile, twins = _split(_said(res))
    assert len(hostile) == 4 and all(v.startswith("refused ") for v in hostile.values()), hostile
    assert len(twins) == 3 and all(v.startswith("got ") for v in twins.values()), twins
    assert person.secret not in res["output_tail"]
    assert {b["kind"] for b in res["blocked"]} == {"read"}, res["blocked"]
    said = [b["what"] for b in res["blocked"]]
    assert any(what.startswith(f"read of {person.key} (reached as ") for what in said), said
    assert any(what.startswith(f"read of {person.home} (reached as ") for what in said), said
    assert os.readlink(repo / "shared") == str(person.home) and (person.key).read_text(encoding="utf-8") == person.secret + "\n"


# ---------------------------------------------------------------------------- a library that reaches out
REACHES = '''import socket

OTHER = {other}
CALL = b"GET /secret HTTP/1.0\\r\\n\\r\\n"


def tcp(host, port):
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(CALL)
        return s.recv(200)


def udp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        return s.sendto(b"x", (host, port))


def own():
    import threading
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def answer():
            caller, _ = server.accept()
            with caller:
                caller.sendall(b"mine")
        threading.Thread(target=answer, daemon=True).start()
        with socket.create_connection(server.getsockname(), timeout=5) as s:
            return s.recv(10)


attempt("another program of this computer", lambda: tcp("127.0.0.1", OTHER))
attempt("an address outside", lambda: tcp("192.0.2.1", 80))
attempt("an address outside, with no connection", lambda: udp("192.0.2.1", 53))
attempt("a name", lambda: socket.getaddrinfo("example.invalid", 80))
attempt("a name, the older way", lambda: socket.gethostbyname("example.invalid"))
if {below}:
    attempt("another program of this computer, a python without the guard", lambda: run(
        sys.executable, "-S", "-c", "import socket; s = socket.create_connection(('127.0.0.1', %d), timeout=5); "
        "s.sendall(%r); print(s.recv(200))" % (OTHER, CALL)))
if {own}:
    attempt("twin: a server of the tests' own", own)
'''


@pytest.mark.skipif(os.name != "posix", reason="the launcher is POSIX's")
def test_a_library_reaches_no_other_address(tmp_path, monkeypatch, pystore, other, walls):
    """Nothing of this computer's that is not the tests' own, no address outside, no name asked of anybody. A
    Python the library starts without the guard is held by the kernel, where the kernel has a rule for it."""
    pystore.add("stage2reach", "1.0.0", {"stage2reach/__init__.py": HEAD + REACHES.format(
        other=other.port, below=walls != "told", own=walls == "own-network")})
    _online(monkeypatch, python=pystore)
    res = sandbox.run(_project(tmp_path / "proj", "stage2reach"), UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    hostile, twins = _split(_said(res))
    assert len(hostile) == (6 if walls != "told" else 5)
    assert all(v.startswith("refused ") for v in hostile.values()), hostile
    assert hostile["a name"] == hostile["a name, the older way"] == "refused PermissionError"    # asked of nobody
    assert twins == ({"twin: a server of the tests' own": "got b'mine'"} if walls == "own-network" else {})
    assert other.seen == [], "a program that is none of the tests' was reached"
    assert res["blocked"], "what the tests reached for is said"


# ---------------------------------------------------------------------------- a library that writes outside
WRITES = '''import stage2sample

DROP, PROJECT = {drop!r}, {project!r}
open(TMP + "/mine.txt", "w").write("x")
attempt("a file in a folder anybody may write into", lambda: open(DROP + "/a.txt", "w").write("x"))
attempt("the same, by its number", lambda: os.close(os.open(DROP + "/b.txt", os.O_CREAT | os.O_WRONLY)))
attempt("a folder made there", lambda: os.mkdir(DROP + "/c"))
attempt("a file moved there", lambda: os.rename(TMP + "/mine.txt", DROP + "/d.txt"))
attempt("a link made there", lambda: os.symlink("/etc/passwd", DROP + "/e"))
attempt("the person's file there, written", lambda: open(DROP + "/kept.txt", "a").write("changed"))
attempt("the person's file there, removed", lambda: os.remove(DROP + "/kept.txt"))
attempt("the person's file there, its rights", lambda: os.chmod(DROP + "/kept.txt", 0o600))
attempt("the person's project", lambda: open(PROJECT + "/test_it.py", "a").write("# changed"))
attempt("a new file in the person's project", lambda: open(PROJECT + "/planted.py", "w").write("# changed"))
attempt("its own code", lambda: open(__file__, "a").write("# changed"))
attempt("another library's code", lambda: open(stage2sample.__file__, "a").write("# changed"))
attempt("the python the tests run on", lambda: open(os.path.join(sys.prefix, "pyvenv.cfg"), "a").write("# changed"))
if {below}:
    attempt("a file in that folder, another program", lambda: run("sh", "-c", "echo x > %s/f.txt" % DROP))
    attempt("a file in that folder, a python without the guard", lambda: run(
        sys.executable, "-S", "-c", "open(%r, 'w').write('x')" % (DROP + "/g.txt")))
    attempt("the person's file there, another program", lambda: run("sh", "-c", "echo changed >> %s/kept.txt" % DROP))
    attempt("the person's project, another program", lambda: run("sh", "-c", "echo '# changed' >> %s/test_it.py" % PROJECT))
    attempt("another library's code, another program", lambda: run("sh", "-c", "echo '# changed' >> %s" % stage2sample.__file__))
    attempt("twin: a temp file, another program", lambda: run("sh", "-c", "echo x > %s/sh.txt && cat %s/sh.txt" % (TMP, TMP)))
attempt("twin: a temp file", lambda: (open(TMP + "/t.txt", "w").write("x"), open(TMP + "/t.txt").read())[1])
attempt("twin: the temp home", lambda: (open(os.path.expanduser("~/note"), "w").write("x"), "note" in os.listdir(os.path.expanduser("~")))[1])
attempt("twin: the copy the tests run in", lambda: (open("made-by-the-tests.txt", "w").write("x"), os.path.exists("made-by-the-tests.txt"))[1])
'''


@pytest.mark.skipif(os.name != "posix", reason="the folder anybody may write into, and its rights, are POSIX's")
def test_a_library_writes_nothing_outside_the_runs_folders(tmp_path, monkeypatch, pystore, person):
    """Not into a folder anybody may write into, not into the person's project, not into the libraries the tests
    run on or the Python that runs them; by Python, and where the kernel has rules also by another program."""
    repo = tmp_path / "proj"
    pystore.add("stage2write", "1.0.0", {"stage2write/__init__.py": HEAD + WRITES.format(
        drop=str(person.drop), project=str(repo), below=KERNEL)}, requires=("stage2sample",))
    _online(monkeypatch, python=pystore)
    _project(repo, "stage2write")
    before = _files(repo)
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    hostile, twins = _split(_said(res))
    assert len(hostile) == (18 if KERNEL else 13) and all(v.startswith("refused ") for v in hostile.values()), hostile
    assert len(twins) == (4 if KERNEL else 3) and all(v.startswith("got ") and "False" not in v for v in twins.values()), twins
    _unchanged(person, repo, before)
    assert res["blocked"], "what the tests tried to write is said"


# ---------------------------------------------------------------------------- code nobody asked to run
def test_code_a_library_brings_to_run_at_every_start_is_not_run(tmp_path, monkeypatch, pystore):
    """A library may bring a file that Python reads at every start, and a line of it can be code: it would run in
    every Python the tests start, whether or not anything imports the library. Here no such line is run: the
    fetched libraries are a folder on the path, not the Python's own installed ones."""
    pystore.add("stage2start", "1.0.0", {
        "stage2start/__init__.py": "import sys\n\nRAN = getattr(sys, 'stage2start_ran', False)\n",
        "stage2start.pth": "import sys; sys.stage2start_ran = True; print('a library ran code nobody asked for')\n"})
    _online(monkeypatch, python=pystore)
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "requirements.txt").write_text("stage2start==1.0.0\n", encoding="utf-8")
    (repo / "test_it.py").write_text(
        "import subprocess\nimport sys\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        "        import stage2start\n"
        "        self.assertFalse(stage2start.RAN)\n"
        "        for more in ([], ['-I']):\n"
        "            got = subprocess.run([sys.executable, *more, '-c', 'import sys; import stage2start; "
        "print(stage2start.RAN)'], capture_output=True, text=True)\n"
        "            self.assertEqual(got.stdout.strip(), 'False', got.stderr)\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]       # the twin is in it: the library itself is there to import
    assert "nobody asked for" not in res["output_tail"]


# ---------------------------------------------------------------------------- while the libraries are fetched
def test_a_library_that_has_to_be_built_runs_nothing_while_the_store_can_be_reached(tmp_path, monkeypatch, pystore, person):
    """Building a library runs code it brings. While the libraries are fetched, with the store in reach, only
    ready-built files are taken. A library that is there as source only is built afterwards, behind the walls of
    the tests' run and with the network off, where those walls hold any program (`tests/test_library_build.py`:
    what a hostile build gets there); anywhere else its source is never asked of the store. Here the build would
    need a tool the store does not have: either way nothing of the package runs and no test is started."""
    mark = person.drop / "built.txt"
    pystore.add("stage2built", "1.0.0", source=True, files={
        "setup.py": f"open({str(mark)!r}, 'w').write('x')\nfrom setuptools import setup\nsetup(name='stage2built', version='1.0.0')\n",
        "stage2built/__init__.py": ""})
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2built")
    (repo / "test_it.py").write_text("raise SystemExit('a test file was run')\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert "ready-built" in str(e.value) and "stage2built" in str(e.value)
    if libraries.cannot_build():
        assert not any(path.endswith(".tar.gz") for path in pystore.seen), pystore.seen
    else:       # the build was begun, and stopped at the tool it names (setuptools, by the rule for a `setup.py`)
        assert "setuptools" in str(e.value), str(e.value)
    assert _files(person.drop) == {"kept.txt"}


def test_a_ready_built_library_whose_files_are_named_outside_its_folder_puts_nothing_there(tmp_path, monkeypatch,
                                                                                            pystore, person):
    """A package is a list of file names, and a name can say `../..`. Nothing is written outside the folder the
    libraries are fetched into, and tests are not run on a library that was taken in part."""
    climb = "../" * 12 + str(person.drop).lstrip("/") + "/climbed.py"
    pystore.add("stage2climb", "1.0.0", {"stage2climb/__init__.py": "SAID = {}\n", climb: "x = 1\n"})
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2climb")
    (repo / "test_it.py").write_text("raise SystemExit('a test file was run')\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable):
        sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert _files(person.drop) == {"kept.txt"}


def _js_hostile(folder: Path, store: NpmStore, name: str, files: dict, more: dict | None = None,
                project: dict | None = None) -> Path:
    """A JavaScript project with a lock file that names the package `name`; its test prints what the package says."""
    entry = store.add(name, "1.0.0", files, more)
    folder.mkdir(parents=True)
    manifest = {"name": "proj", "version": "1.0.0", "scripts": {"test": "node test.js", **(project or {})},
                "dependencies": {name: "1.0.0"}}
    lock = {"name": "proj", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": {k: manifest[k] for k in ("name", "version", "dependencies")}, f"node_modules/{name}": entry}}
    (folder / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (folder / "test.js").write_text(
        f"const it = require('{name}');\n"
        "(it.later || ((done) => done()))(() => console.log('SAID ' + JSON.stringify(it.said)));\n", encoding="utf-8")
    return folder


MARKS = "require('fs').writeFileSync({mark!r}, 'x');\n"


@needs_npm
def test_a_packages_install_scripts_are_not_run(tmp_path, monkeypatch, npmstore, person):
    """npm runs a package's own scripts when it installs it, and the project's own: code of a stranger, while the
    store can be reached. Here none of them runs, the record says that the package brings one, and the package
    itself is there for the tests (the twin)."""
    scripts = {when: f"node {when}.js" for when in ("preinstall", "install", "postinstall", "prepare")}
    files = {f"{when}.js": MARKS.format(mark=str(person.drop / f"{when}.txt")) for when in scripts}
    repo = _js_hostile(tmp_path / "proj", npmstore, "stage2-scripts", {"index.js": "exports.said = {twin: 'got it'};\n", **files},
                       more={"scripts": scripts}, project={"preinstall": "node mine.js", "prepare": "node mine.js"})
    (repo / "mine.js").write_text(MARKS.format(mark=str(person.drop / "project.txt")), encoding="utf-8")
    _online(monkeypatch, npm=npmstore)
    res = sandbox.run(repo, ["npm", "test"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert _said(res) == {"twin": "got it"}
    assert _files(person.drop) == {"kept.txt"}
    assert any("install script, which was not run" in note for note in res["libraries"]["notes"])


@needs_npm
def test_a_package_whose_files_are_named_outside_its_folder_puts_nothing_there(tmp_path, monkeypatch, npmstore, person):
    climb = "../" * 12 + str(person.drop).lstrip("/") + "/climbed.js"
    repo = _js_hostile(tmp_path / "proj", npmstore, "stage2-climb", {"index.js": "exports.said = {};\n", climb: "x"})
    _online(monkeypatch, npm=npmstore)
    try:
        sandbox.run(repo, ["npm", "test"], log=QUIET, backend="subprocess")
    except sandbox.Unavailable:
        pass                    # npm may take the rest of the package or none of it: either way nothing outside
    assert _files(person.drop) == {"kept.txt"}


PROBE = '''import os
print("NAMES", sorted(k for k, v in os.environ.items() if "PLANTED" in v or any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSW"))))
for name in ("a.txt", "kept.txt"):
    try:
        open(os.path.join({drop!r}, name), "a").write("changed")
        print("WROTE", name)
    except OSError as e:
        print("REFUSED", name, type(e).__name__)
'''


@pytest.mark.skipif(os.name != "posix", reason="the launcher is POSIX's")
def test_the_program_that_fetches_holds_no_key_and_writes_only_in_its_own_folders(monkeypatch, pystore, person):
    """Whatever the fetching program is, and whatever a package makes it do: it is handed nothing of the person's
    environment (a store address with a password in it, a token), and where the kernel has rules it writes only
    into the folders of the fetch."""
    from lantern import libraries
    for name in PLANTED_NAMES:
        monkeypatch.setenv(name, "PLANTED-" + name.lower())
    _online(monkeypatch, python=pystore)
    root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
    try:
        job = libraries._Fetch(libraries.Plan("python"), root, QUIET, None, 512)
        probe = job.dir / "probe.py"
        probe.write_text(PROBE.format(drop=str(person.drop)), encoding="utf-8")
        job.hand_over()
        rc, output, timed_out = job.run([sys.executable, "-I", "-S", str(probe)], job.dir, [job.dir],
                                        [os.path.dirname(os.__file__)])
    finally:
        assert sandbox._rm(root)
    assert rc == 0 and not timed_out, output
    assert "NAMES []" in output and "PLANTED" not in output, output
    if KERNEL:
        assert "REFUSED a.txt" in output and "REFUSED kept.txt" in output and "WROTE" not in output, output
        assert _files(person.drop) == {"kept.txt"}


# ---------------------------------------------------------------------------- a JavaScript package, at test time
JS_HOSTILE = '''const fs = require('fs'), net = require('net'), os = require('os'), path = require('path');
const cp = require('child_process');
const KEY = {key}, HOME = {home}, DROP = {drop}, PROJECT = {project}, PID = {pid}, OTHER = {other};
const said = {{}};
function attempt(name, fn) {{
  try {{ said[name] = 'got ' + String(fn()).slice(0, 70); }} catch (e) {{ said[name] = 'refused ' + (e.code || e.name); }}
}}
attempt('names in the environment', () => JSON.stringify(Object.keys(process.env).filter(
  (k) => /KEY|TOKEN|SECRET|PASSW/i.test(k) || /PLANTED/.test(process.env[k]))));
attempt('the key file', () => fs.readFileSync(KEY, 'utf8'));
attempt('the key file, another program', () => cp.execFileSync('cat', [KEY], {{stdio: ['ignore', 'pipe', 'ignore']}}));
attempt('the names in the home folder', () => fs.readdirSync(HOME));
attempt('what another program was started with', () => fs.readFileSync('/proc/' + PID + '/environ', 'utf8'));
attempt('a file in a folder anybody may write into', () => fs.writeFileSync(path.join(DROP, 'js.txt'), 'x'));
attempt('the person\\'s file there', () => fs.appendFileSync(path.join(DROP, 'kept.txt'), 'changed'));
attempt('the person\\'s project', () => fs.appendFileSync(path.join(PROJECT, 'test.js'), '// changed'));
attempt('twin: its own file', () => fs.readFileSync(__filename, 'utf8').length > 0);
attempt('twin: the project\\'s file', () => fs.readFileSync('package.json', 'utf8').length > 0);
attempt('twin: a temp file', () => {{ fs.writeFileSync(path.join(os.tmpdir(), 't.txt'), 'x'); return true; }});
attempt('twin: the copy the tests run in', () => {{ fs.writeFileSync('made-by-the-tests.txt', 'x'); return true; }});
exports.said = said;
exports.later = (done) => {{
  const s = net.connect({{host: '127.0.0.1', port: OTHER}});
  const end = (what) => {{ said['another program of this computer'] = what; s.destroy(); done(); }};
  s.setTimeout(5000, () => end('refused timeout'));
  s.on('connect', () => end('got a connection'));
  s.on('error', (e) => end('refused ' + e.code));
}};
'''


@kernel
@needs_npm
def test_a_javascript_package_is_held_by_the_kernel_alone(tmp_path, monkeypatch, npmstore, person, another_program,
                                                           other):
    """No guard of Lantern's is in a JavaScript program: what holds it is the environment it is handed, the
    kernel's rules and the network of the run's own."""
    for name in PLANTED_NAMES:
        monkeypatch.setenv(name, "PLANTED-" + name.lower())
    repo = tmp_path / "proj"
    code = JS_HOSTILE.format(key=json.dumps(str(person.key)), home=json.dumps(str(person.home)),
                             drop=json.dumps(str(person.drop)), project=json.dumps(str(repo)),
                             pid=another_program.pid, other=other.port)
    _js_hostile(repo, npmstore, "stage2-hostile", {"index.js": code})
    _online(monkeypatch, npm=npmstore)
    before = _files(repo)
    res = sandbox.run(repo, ["npm", "test"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    hostile, twins = _split(_said(res))
    assert hostile.pop("names in the environment") == "got []"
    reached = hostile.pop("another program of this computer")
    assert len(hostile) == 7 and all(v.startswith("refused ") for v in hostile.values()), hostile
    assert len(twins) == 4 and all(v == "got true" for v in twins.values()), twins
    assert person.secret not in res["output_tail"] and "PLANTED" not in res["output_tail"]
    # A connection is the kernel's to refuse where it is asked of the program itself. Inside a sandbox that makes
    # the connections (these tests, run by Lantern) that sandbox decides, and the other program is inside it too.
    if sandbox.held_below_python():
        assert reached.startswith("refused ") and other.seen == [], reached
    assert _files(person.drop) == {"kept.txt"} and _files(repo) == before
    assert (person.drop / "kept.txt").read_text(encoding="utf-8") == "the person's own\n"


# ---------------------------------------------------------------------------- which folders are closed to reads
posix = pytest.mark.skipif(os.name != "posix", reason="the folders, and the links between them, are POSIX's")


@posix
def test_what_is_open_lies_beside_the_way_to_what_is_closed(tmp_path):
    """The kernel's rules can only open folders, so what is open is named: every entry beside the way to a closed
    folder. A closed folder, what is in it, the folders on the way to it and every link are not named (a link
    is opened or not by where it leads)."""
    top = tmp_path / "top"
    for folder in ("usr/lib", "home/person/.ssh", "home/person/projects", "home/other", "run/user/1000", "run/lock",
                   "tmp/x", "var/tmp", "var/lib"):
        (top / folder).mkdir(parents=True)
    (top / "home" / "readme").write_text("x", encoding="utf-8")
    os.symlink(top / "home" / "person", top / "to-home")
    os.symlink(top / "home" / "person", top / "home" / "me")
    closed = [str(top / p) for p in ("home/person", "run/user", "tmp", "var/tmp", "home/person/projects", "nowhere/at/all")]
    assert set(_jail._beside(closed, str(top))) == {str(top / p) for p in (
        "usr", "home/other", "home/readme", "run/lock", "var/lib")}
    assert _jail._beside([str(top)], str(top)) == [] == _jail._beside(["/"], "/")       # everything closed: nothing named


@posix
def test_which_folders_are_the_persons_own(tmp_path, monkeypatch):
    """The home folder (the one HOME names and the one the system's list of users names), the temp folder, the
    session's folder, other disks and the project itself; never the whole computer, and the run's own folder and
    the Python the tests are made of are opened by name wherever they lie."""
    home, repo, root = tmp_path / "home", tmp_path / "elsewhere" / "proj", tmp_path / "run"
    for folder in (home, repo, root):
        folder.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    closed = sandbox.persons_own(repo)
    assert str(home) in closed and str(repo) in closed and os.path.realpath(tempfile.gettempdir()) in closed
    assert {"/run/user", "/mnt", "/media"} & set(closed) == {p for p in ("/run/user", "/mnt", "/media") if os.path.isdir(p)}
    assert "/" not in closed and "/usr" not in closed and all(os.path.isabs(p) for p in closed)
    assert len(closed) == len(set(closed)) and all(os.path.isdir(p) and not os.path.islink(p) for p in closed)
    monkeypatch.setenv("HOME", "/")                 # a user whose home is the whole computer: never closed
    assert "/" not in sandbox.persons_own(repo)
    monkeypatch.setenv("HOME", str(home))
    wall = sandbox.read_wall(repo, root, "python", fetched=True)
    if not KERNEL:                                  # no such rules on this system: nothing is promised
        assert wall is None
        return
    assert wall["closed"] == closed
    assert str(root) in wall["open"] and os.path.realpath(os.path.dirname(os.__file__)) in wall["open"]
    assert wall["list"] == []                       # on fetched libraries the recorder is a file of the run's own
    for rule in (wall, sandbox.read_wall(repo, root, "python", fetched=False), sandbox.read_wall(repo, root, "node", fetched=True)):
        assert not [p for p in rule["open"] for c in closed if c == p or c.startswith(p.rstrip("/") + "/")], \
            "a closed folder, or one around it, was opened again"
    assert sandbox.read_wall(repo, root, "go", fetched=False) is None       # only where Lantern fetches the libraries


@posix
def test_a_tool_in_the_home_folder_opens_its_own_folders_only(tmp_path):
    """A Python or a Node installed in the home folder (pyenv, nvm, an environment of the person's) has to be
    read by the tests it runs: the folders of the tool, never the folder around them."""
    home = tmp_path / "home"
    env, plain, loose = home / "envs" / "one", home / ".tool" / "versions" / "3", home
    for folder in (env / "bin", env / "lib", plain / "bin", plain / "lib", plain / "share", home / "bin", home / "lib",
                   home / ".ssh"):
        folder.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    closed = [str(home)]
    assert sandbox._tool_folders(str(env), closed) == [str(env)]                            # an environment, whole
    assert sandbox._tool_folders(str(plain), closed) == [str(plain / "bin"), str(plain / "lib")]
    assert sandbox._tool_folders(str(loose), closed) == [str(home / "bin"), str(home / "lib")]  # never the home itself
    assert sandbox._tool_folders("/usr", closed) == ["/usr"]                                # outside: as it is


READS = '''import os, subprocess, sys
for name, path in (("key", {key!r}), ("beside", {beside!r}), ("tool", {tool!r}), ("own", {own!r})):
    try:
        print(name + "\\tgot", len(open(path).read()))
    except OSError as e:
        print(name + "\\trefused", type(e).__name__)
for name, path in (("home", {home!r}), ("around", {around!r}), ("bin", {bin!r})):
    try:
        print(name + "\\tgot", sorted(os.listdir(path)))
    except OSError as e:
        print(name + "\\trefused", type(e).__name__)
for name, path in (("runs tool", {tool!r}), ("runs other", {other!r})):
    try:
        print(name + "\\tgot", subprocess.run([path], capture_output=True, text=True).stdout.strip())
    except OSError as e:
        print(name + "\\trefused", type(e).__name__)
'''


@kernel
def test_the_kernel_closes_the_named_folders_and_nothing_beside_them():
    """The launcher itself, with rules written by hand: a closed folder cannot be read, listed or run from; what
    lies beside it can; a folder opened by name inside it can; a folder that may only be listed shows its names
    and no file."""
    spot = "/dev/shm" if os.access("/dev/shm", os.W_OK | os.X_OK) else None       # a folder with few others beside it
    top = Path(tempfile.mkdtemp(prefix="lantern-test-closed-", dir=spot))
    try:
        home, own = top / "around" / "home", top / "own"
        for folder in (home / ".ssh", home / "tools" / "bin", home / "other", own):
            folder.mkdir(parents=True)
        for path, text in ((home / ".ssh" / "key", "PLANTED\n"), (top / "around" / "beside.txt", "x\n"),
                           (own / "mine.txt", "x\n"), (home / "tools" / "bin" / "tool", "#!/bin/sh\necho tool ran\n"),
                           (home / "other" / "tool", "#!/bin/sh\necho other ran\n")):
            path.write_text(text, encoding="utf-8")
            os.chmod(path, 0o755)
        for folder in (top, *top.rglob("*")):
            if folder.is_dir():
                os.chmod(folder, 0o755)
        code = READS.format(key=str(home / ".ssh" / "key"), beside=str(top / "around" / "beside.txt"),
                            tool=str(home / "tools" / "bin" / "tool"), own=str(own / "mine.txt"), home=str(home),
                            around=str(top / "around"), bin=str(home / "tools" / "bin"), other=str(home / "other" / "tool"))
        policy = {"writable": [str(own)], "nobody": False, "python": False, "net": False, "must": True,
                  "read": {"closed": [str(home)], "open": [str(home / "tools" / "bin")], "list": [str(home / "other")]}}
        r = subprocess.run([sys.executable, "-c", LAUNCHER, json.dumps(policy), "--", sys.executable, "-I", "-S", "-c", code],
                           capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=HERE)
    finally:
        assert sandbox._rm(top) is True
    said = dict(line.split("\t", 1) for line in r.stdout.splitlines())
    assert r.returncode == 0, r.stderr
    assert said["key"].startswith("refused") and said["home"].startswith("refused"), r.stdout
    assert said["beside"] == "got 2" and said["own"] == "got 2" and said["tool"].startswith("got"), r.stdout
    assert said["bin"] == "got ['tool']", r.stdout
    assert said["around"].startswith("refused"), r.stdout       # the way to a closed folder: passed through, not listed
    assert said["runs tool"] == "got tool ran" and said["runs other"] == "refused PermissionError", r.stdout
    assert "closed to reads" in r.stderr, r.stderr


INSIDE = '''import os
for name, path in (("key", {key!r}), ("inner key", {inner!r}), ("beside", {beside!r}), ("system", "/etc/passwd"),
                   ("python", os.__file__)):
    try:
        print(name + "\\tgot", len(open(path).read()) > 0)
    except OSError as e:
        print(name + "\\trefused", type(e).__name__)
for name, path in (("usr", "/usr"), ("top", "/")):
    try:
        print(name + "\\tgot", len(os.listdir(path)) > 0)
    except OSError as e:
        print(name + "\\trefused", type(e).__name__)
'''


@kernel
def test_a_sealed_run_started_inside_a_sealed_run_closes_its_own_folders_too():
    """Lantern's own tests start runs, and they run in one: under the outer rules `/` cannot be listed, so the
    inner launcher cannot see what lies beside the way to its closed folders. It tries the names a Linux system
    has there, and the inner run still reads the system and Python, and neither the outer nor the inner key."""
    try:        # a folder with few others beside it, where every user may make one (not where these tests run in a sandbox)
        top = Path(tempfile.mkdtemp(prefix="lantern-test-nested-", dir="/dev/shm"))
    except OSError:
        top = Path(tempfile.mkdtemp(prefix="lantern-test-nested-"))
    try:
        home, own = top / "home", top / "own"
        for folder in (home, own / "inner-home", own / "work"):
            folder.mkdir(parents=True)
        for path in (home / "key", own / "inner-home" / "key", own / "beside.txt"):
            path.write_text("PLANTED\n", encoding="utf-8")
            os.chmod(path, 0o644)
        for folder in (top, *top.rglob("*")):
            if folder.is_dir():
                os.chmod(folder, 0o755)
        code = INSIDE.format(key=str(home / "key"), inner=str(own / "inner-home" / "key"), beside=str(own / "beside.txt"))
        # this Python, wherever it is installed (and the inner run's own folder, which the rule names first)
        tools = sandbox.read_wall(top, own / "work", "python", fetched=False)["open"]
        outer = {"writable": [str(own)], "nobody": False, "python": False, "net": False, "must": True,
                 "read": {"closed": [str(home)], "open": tools, "list": [str(HERE)]}}
        inner = {"writable": [str(own / "work")], "nobody": False, "python": False, "net": False, "must": True,
                 "read": {"closed": [str(home), str(own / "inner-home")], "open": tools, "list": [str(HERE)]}}
        r = subprocess.run([sys.executable, "-c", LAUNCHER, json.dumps(outer), "--",
                            sys.executable, "-c", LAUNCHER, json.dumps(inner), "--", sys.executable, "-I", "-S", "-c", code],
                           capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=HERE)
    finally:
        assert sandbox._rm(top) is True
    assert r.returncode == 0, r.stderr
    assert dict(line.split("\t", 1) for line in r.stdout.splitlines()) == {
        "key": "refused PermissionError", "inner key": "refused PermissionError", "beside": "got True",
        "system": "got True", "python": "got True", "usr": "got True", "top": "refused PermissionError"}, r.stdout
    assert r.stderr.count("closed to reads") == 2, r.stderr


@kernel
def test_the_sheet_says_what_the_tests_cannot_read(tmp_path, monkeypatch, pystore):
    # the restricted process's sheet: where Docker is installed the sheet is the container's by default, which
    # has none of the person's folders in it at all (GitHub's machines have Docker; this test failed there)
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    _online(monkeypatch, python=pystore)
    repo = _project(tmp_path / "proj", "stage2sample")
    said = " ".join(sandbox.describe(repo, "python")["details"])
    assert "your home folder" in said and "cannot be read" in said
    assert "cannot be read" not in " ".join(sandbox.describe(repo, "go")["details"])
