"""A project's libraries are fetched before its tests run (a firm pass or fail, stage 2).

Until then the sandbox ran a project's tests on whatever libraries the Python that runs Lantern happened to have.
A project whose libraries are not on the computer, which is most projects a person hands Lantern, failed at its
first import, and the release decision read "Blocked: the tests failed" for code nobody had run.

Now what the project asks for is fetched first, in a step of its own (`lantern/libraries.py`): from the official
store and from nowhere else, into a folder of Lantern's own that is deleted with the run, with no code of any
library run while a network can be reached. The tests then run on exactly those libraries, with the network off
wherever the run's own walls keep them from it (the sheet says which), and the record names each one with its
fingerprint.

No test here reaches the internet: the stores are stand-ins on this computer (`tests/stores.py`)."""
import json
import os
import re
import sys
import sysconfig
import tempfile
import tomllib
from pathlib import Path

import pytest
from stores import NpmStore, PyStore

from lantern import programs, sandbox

UNITTEST = ["python", "-m", "unittest", "-v"]
QUIET = lambda line: None       # noqa: E731
NPM = programs.find("npm")
needs_npm = pytest.mark.skipif(NPM is None, reason="npm is not installed on this computer")


def _online(monkeypatch, **stores) -> None:
    """A check that may fetch: not offline, and the stores are the stand-ins."""
    monkeypatch.delenv("LANTERN_OFFLINE", raising=False)
    for kind, store in stores.items():
        monkeypatch.setenv(f"LANTERN_STORE_{kind.upper()}", store.url)


@pytest.fixture()
def pystore():
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        yield store


@pytest.fixture()
def npmstore():
    with NpmStore() as store:
        yield store


def _py_project(folder: Path, check: str = "self.assertEqual(stage2sample.answer(), 42)",
                needs: str = "stage2sample==1.0.0\n") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "requirements.txt").write_text(needs, encoding="utf-8")
    (folder / "test_it.py").write_text(
        "import unittest\n\nimport stage2sample\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        {check}\n", encoding="utf-8")
    return folder


def _js_project(folder: Path, store: NpmStore, check: str = "sample.answer() === 42") -> Path:
    """A project with a lock file, as `npm install` writes one: the exact version, where the real registry keeps
    it, and its fingerprint."""
    entry = store.add("stage2-sample", "1.0.0", {"index.js": "exports.answer = () => 42;\n"})
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {"name": "proj", "version": "1.0.0", "scripts": {"test": "node test.js"},
                "dependencies": {"stage2-sample": "1.0.0"}}
    lock = {"name": "proj", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": {k: manifest[k] for k in ("name", "version", "dependencies")},
                         "node_modules/stage2-sample": entry}}
    (folder / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (folder / "test.js").write_text(
        "const sample = require('stage2-sample');\n"
        f"if (!({check})) {{ console.error('the check failed'); process.exit(1); }}\nconsole.log('ok');\n",
        encoding="utf-8")
    return folder


def _files(folder: Path) -> set[str]:
    return {p.relative_to(folder).as_posix() for p in folder.rglob("*")}


def _named(res) -> dict:
    return {p["name"]: p for p in res["libraries"]["packages"]}


# ---------------------------------------------------------------------------- Python
def test_the_library_is_not_on_this_computer():
    """What the cases below stand on: the Python that runs these tests has no `stage2sample`."""
    with pytest.raises(ImportError):
        __import__("stage2sample")


def test_tests_that_need_a_library_this_computer_does_not_have_run_on_the_fetched_one(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    lines = []
    res = sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert libs["state"] == "fetched" and libs["language"] == "python" and libs["store"] == pystore.host
    got = _named(res)["stage2sample"]
    assert got["version"] == "1.0.0"
    assert got["fingerprint"] == "sha256:" + pystore.sha256["stage2sample-1.0.0-py3-none-any.whl"]
    assert got["file"] == "stage2sample-1.0.0-py3-none-any.whl"
    assert libs["exact"] is True and libs["asked"] == [{"text": "stage2sample==1.0.0", "file": "requirements.txt"}]
    assert any("stage2sample 1.0.0" in line and got["fingerprint"][:19] in line for line in lines), lines


def test_the_twin_whose_test_fails_still_fails(tmp_path, monkeypatch, pystore):
    """Fetching makes the tests run; it does not make them pass."""
    _online(monkeypatch, python=pystore)
    res = sandbox.run(_py_project(tmp_path / "proj", check="self.assertEqual(stage2sample.answer(), 41)"), UNITTEST,
                      log=lambda line: None)
    assert res["returncode"] == 1 and res["libraries"]["state"] == "fetched"
    assert "42 != 41" in res["output_tail"]


def test_a_library_the_store_does_not_have_means_no_test_is_run(tmp_path, monkeypatch, pystore):
    """Not "the tests failed": nothing of the project was run, and the reason names the library."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", needs="stage2sample==1.0.0\nstage2-nowhere==3.1\n")
    (repo / "test_it.py").write_text("raise SystemExit('a test file was run')\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=lambda line: None)
    assert "stage2-nowhere" in str(e.value) and "could not be fetched" in str(e.value)


def test_the_tests_see_the_fetched_libraries_and_no_others(tmp_path, monkeypatch, pystore):
    """Exactly the libraries the project names: one that happens to be installed beside Lantern is not there, so
    a project that forgot to name a library hears of it here and not from its first user."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj")
    (repo / "test_it.py").write_text(
        "import importlib.util\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        "        self.assertIsNotNone(importlib.util.find_spec('stage2sample'))\n"
        "        self.assertIsNone(importlib.util.find_spec('pytest'))\n", encoding="utf-8")
    assert __import__("importlib").util.find_spec("pytest") is not None      # it is installed beside Lantern
    res = sandbox.run(repo, UNITTEST, log=lambda line: None)
    assert res["returncode"] == 0, res["output_tail"]


def test_nothing_of_the_fetch_is_left(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj")
    home = Path(os.environ["LANTERN_HOME"])
    site = Path(sysconfig.get_path("purelib"))
    before = (_files(repo), _files(home) if home.exists() else set(), set(os.listdir(site)),
              {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")})
    res = sandbox.run(repo, UNITTEST, log=lambda line: None)
    assert res["returncode"] == 0, res["output_tail"]
    after = (_files(repo), _files(home) if home.exists() else set(), set(os.listdir(site)),
             {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")})
    assert after == before


def test_the_store_is_asked_for_what_the_project_names_and_nothing_else(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lambda line: None)
    assert sorted(set(pystore.seen)) == ["/files/stage2sample-1.0.0-py3-none-any.whl", "/simple/stage2sample/"]


def test_a_store_the_project_names_itself_is_never_asked(tmp_path, monkeypatch, pystore):
    """Where libraries come from is the person's setting, never the project's: a line of the project that names
    another store is not followed, and the tests are not run on libraries nobody fetched."""
    _online(monkeypatch, python=pystore)
    with PyStore() as theirs:
        theirs.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 'theirs'\n"})
        repo = _py_project(tmp_path / "proj", needs=f"--index-url {theirs.url}\nstage2sample==1.0.0\n")
        with pytest.raises(sandbox.Unavailable) as e:
            sandbox.run(repo, UNITTEST, log=lambda line: None)
        assert theirs.seen == [] and pystore.seen == []
    assert "another store" in str(e.value) and theirs.host not in str(e.value)


def test_offline_nothing_is_fetched_and_a_missing_library_is_said(tmp_path, monkeypatch, pystore):
    """Offline (`--offline`, LANTERN_OFFLINE) nothing is asked of any store. A project whose libraries are not on
    this computer then gets no test run, and is told which are missing: not "the tests failed"."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    monkeypatch.setenv("LANTERN_STORE_PYTHON", pystore.url)
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lambda line: None)
    assert pystore.seen == []
    assert "stage2sample" in str(e.value) and "offline" in str(e.value)


def test_offline_a_project_whose_libraries_are_here_runs_on_them(tmp_path, monkeypatch, pystore):
    """The twin: every library the project names is installed beside Lantern (pytest is), so offline its tests
    run as they always did, and the record says on what."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = _py_project(tmp_path / "proj", needs="pytest\n")
    (repo / "test_it.py").write_text("import pytest\n\n\ndef test_it():\n    assert pytest.__version__\n", encoding="utf-8")
    res = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda line: None)
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["state"] == "installed" and pystore.seen == []


def test_a_project_that_names_no_library_fetches_nothing(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "test_it.py").write_text(
        "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n        self.assertTrue(True)\n",
        encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=lambda line: None)
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["state"] == "none" and pystore.seen == []


# ---------------------------------------------------------------------------- JavaScript
@needs_npm
def test_javascript_tests_that_need_a_package_run_on_the_fetched_one(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    repo = _js_project(tmp_path / "proj", npmstore)
    lines = []
    res = sandbox.run(repo, ["npm", "test"], log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert libs["state"] == "fetched" and libs["language"] == "node" and libs["store"] == npmstore.host
    got = _named(res)["stage2-sample"]
    lock = json.loads((repo / "package-lock.json").read_text(encoding="utf-8"))
    assert got["version"] == "1.0.0" and got["fingerprint"] == lock["packages"]["node_modules/stage2-sample"]["integrity"]
    assert libs["exact"] is True
    assert "/stage2-sample/-/stage2-sample-1.0.0.tgz" in npmstore.seen
    assert not (repo / "node_modules").exists()          # fetched into the run's own copy, not into the project


@needs_npm
def test_the_javascript_twin_whose_test_fails_still_fails(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore, check="sample.answer() === 41"), ["npm", "test"],
                      log=lambda line: None)
    assert res["returncode"] == 1 and res["libraries"]["state"] == "fetched"
    assert "the check failed" in res["output_tail"]


@needs_npm
def test_a_package_that_is_not_the_one_the_lock_file_names_is_refused(tmp_path, monkeypatch, npmstore):
    """The fingerprint in the lock file is followed to the letter: the store hands out other bytes under the same
    name and version, and no test runs on them."""
    _online(monkeypatch, npm=npmstore)
    repo = _js_project(tmp_path / "proj", npmstore)
    npmstore.add("stage2-sample", "1.0.0", {"index.js": "exports.answer = () => 'swapped';\n"})   # after the lock was written
    (repo / "test.js").write_text("require('fs').writeFileSync('ran.txt', 'x'); process.exit(0);\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, ["npm", "test"], log=lambda line: None)
    assert "stage2-sample" in str(e.value) or "fingerprint" in str(e.value)


@pytest.mark.skipif(sys.platform != "linux", reason="the walls of the fetching step are Linux's")
def test_the_sheet_says_how_libraries_are_fetched(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    said = " ".join(sandbox.describe(_py_project(tmp_path / "proj"), "python")["details"])
    assert "libraries" in said and "fetched" in said and "network off" in said


# ---------------------------------------------------------------------------- the walls of the fetching step
LINUX = sys.platform.startswith("linux")
WALLS = [pytest.param("own-network", marks=pytest.mark.skipif(not LINUX or bool(sandbox.own_network()),
                                                              reason="this system gives a run no network of its own")),
         pytest.param("doorkeeper", marks=pytest.mark.skipif(os.name != "posix", reason="the launcher is POSIX's"))]


def kernel_rule() -> bool:
    """Does the kernel hold a program to the addresses its own sandbox names? On Linux with Landlock's rule for
    connections, and not inside a sandbox that makes every connection for what runs in it (these tests, run by
    Lantern: the sandbox around them is then the one that judges an address)."""
    return LINUX and sandbox.landlock_abi() >= 4 and sandbox.own_sockets() != sandbox.DOORMAN_ABOVE


@pytest.fixture(params=WALLS)
def walls(request, monkeypatch):
    """Both ways a fetch is held: in a network of its own (Linux, where the system gives one), and, where there is
    none, by the doorkeeper on this computer's own address with the kernel's rule beside it where it has one."""
    if request.param == "doorkeeper":
        monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
        return "port-rule" if kernel_rule() else "told"
    return request.param


def test_inside_a_sandbox_that_makes_the_connections_the_kernels_rule_is_not_claimed(monkeypatch):
    """A run inside a run (Lantern's own tests, run by Lantern): the sandbox around it makes every connection for
    what runs inside it, so the kernel's rule for the fetching program's own connections decides nothing there.
    The fetch then says `told`. (On the code before it said `port-rule`, and inside such a sandbox a program that
    went round the doorkeeper arrived: `straight/store: HTTP/1.0 200 OK`.) A sandbox that makes the connections
    is Linux's: on another system the fetch is only told as well, and the reason it gives is that system's own
    (until 2026-11-14 this test asked Windows for Linux's reason, and failed there)."""
    from lantern import libraries
    monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 7)
    monkeypatch.setattr(sandbox, "_OWN_SOCKETS", [sandbox.DOORMAN_ABOVE])
    assert libraries.walls() == "told"
    job = libraries._Fetch(libraries.Plan("python"), Path(tempfile.mkdtemp(prefix="lantern-sandbox-")), QUIET, None, 512)
    try:
        assert job.own is False
        assert job.held_by() == (libraries.TOLD_INSIDE if LINUX else libraries.WALL_WORDS["told"])
        assert ("sandbox around this one" in job.held_by()) is LINUX
    finally:
        job.close()
        assert sandbox._rm(job.root)
    # the twins: a doorman of the run's own, or none on this system, leaves the kernel's rule what it is
    for why in ("", "this system does not let Lantern put a doorman between the tests' programs and the kernel"):
        monkeypatch.setattr(sandbox, "_OWN_SOCKETS", [why])
        assert libraries.walls() == ("port-rule" if LINUX else "told")
        assert "sandbox around this one" not in libraries.wall_words(libraries.walls())


PROBE = r'''
import socket, sys
door, store, other = (int(x) for x in sys.argv[1:4])
def ask(port, text):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(text.encode())
            got = b""
            while True:
                data = s.recv(65536)
                if not data:
                    break
                got += data
            return got.split(b"\r\n", 1)[0].decode("latin-1")
    except OSError as e:
        return "no way (" + type(e).__name__ + ")"
print("door/store:", ask(door, f"GET http://127.0.0.1:{store}/simple/stage2sample/ HTTP/1.1\r\n\r\n"))
print("door/other:", ask(door, f"GET http://127.0.0.1:{other}/secret HTTP/1.1\r\n\r\n"))
print("door/tunnel-to-other:", ask(door, f"CONNECT 127.0.0.1:{other} HTTP/1.1\r\n\r\n"))
print("straight/store:", ask(store, "GET /simple/stage2sample/ HTTP/1.0\r\n\r\n"))
print("straight/other:", ask(other, "GET /secret HTTP/1.0\r\n\r\n"))
'''


def test_a_fetching_program_reaches_the_store_through_the_doorkeeper_and_nothing_else(monkeypatch, pystore, walls):
    """Whatever the program that fetches is: here one that tries every way round. The store answers through the
    doorkeeper; any other place is refused by it, by name; and going round the doorkeeper leads nowhere, where
    the kernel or a network of the fetch's own holds it to the doorkeeper."""
    from lantern import libraries
    _online(monkeypatch, python=pystore)
    root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
    lines: list[str] = []
    with PyStore() as other:
        other.pages["/secret"] = ("text/plain", b"not for the fetch")
        try:
            job = libraries._Fetch(libraries.Plan("python"), root, lines.append, None, 512)
            assert job.own is (walls == "own-network")
            probe = job.dir / "probe.py"
            probe.write_text(PROBE, encoding="utf-8")
            job.hand_over()
            rc, output, timed_out = job.run([sys.executable, "-I", str(probe), str(job.port), str(pystore.port),
                                             str(other.port)], job.dir, [job.dir], [os.path.dirname(os.__file__)])
        finally:
            assert sandbox._rm(root)
        said = dict(line.split(": ", 1) for line in output.splitlines() if line.startswith(("door/", "straight/")))
        assert rc == 0 and not timed_out, output
        assert said["door/store"].endswith(" 200 OK"), output
        assert said["door/other"] == "HTTP/1.1 403 Forbidden" == said["door/tunnel-to-other"], output
        if walls != "told":             # round the doorkeeper: no such way
            assert said["straight/store"].startswith("no way") and said["straight/other"].startswith("no way"), output
        # Through the doorkeeper no other place is reached, ever. Round it, one is reached only where nothing but
        # the doorkeeper's word holds the fetching program (`told`: macOS, a kernel without the rule, a run
        # inside a run). Until 2026-11-14 this line asked for an empty list there too, which no `told` promises.
        assert other.seen == ([] if said["straight/other"].startswith("no way") else ["/secret"]), other.seen
        assert pystore.seen.count("/simple/stage2sample/") == (1 if said["straight/store"].startswith("no way") else 2)
        assert job.refused() == 2 and all(f"127.0.0.1:{other.port}" in line for line in job.said if "REFUSED" in line)


def test_python_libraries_are_fetched_under_either_wall(tmp_path, monkeypatch, pystore, walls):
    _online(monkeypatch, python=pystore)
    lines: list[str] = []
    res = sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert libs["state"] == "fetched" and libs["walls"] == walls and libs["refused"] == 0
    assert libs["reached"] == [pystore.host]
    assert res["own_network"] is (walls == "own-network")


@needs_npm
def test_javascript_packages_are_fetched_under_either_wall(tmp_path, monkeypatch, npmstore, walls):
    _online(monkeypatch, npm=npmstore)
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=lambda line: None,
                      backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert libs["state"] == "fetched" and libs["walls"] == walls and libs["refused"] == 0
    assert libs["reached"] == [npmstore.host]


def test_the_tests_themselves_get_no_doorkeeper(tmp_path, monkeypatch, pystore, walls):
    """The way out is the fetch's alone: when the tests run, nothing listens where the doorkeeper was, and the
    store cannot be reached."""
    _online(monkeypatch, python=pystore)
    check = ("import socket\n"
             "        for port in (8118, %d):\n"
             "            with self.assertRaises(OSError):\n"
             "                socket.create_connection(('127.0.0.1', port), timeout=5).close()" % pystore.port)
    res = sandbox.run(_py_project(tmp_path / "proj", check), UNITTEST, log=lambda line: None, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["state"] == "fetched"
    assert pystore.seen.count("/simple/stage2sample/") == 1          # the fetch asked once; the tests reached nothing


# ---------------------------------------------------------------------------- a whole check
def _check(repo: Path, command: list[str], offline: bool = False) -> tuple[dict, dict, list[str]]:
    """A check of `repo` with its tests run in the sandbox: (the record of the test run, the release decision,
    the log). No scanner is run, so nothing but the fetch asks for a network."""
    from lantern import pipeline
    out = repo / ".lantern"
    lines: list[str] = []
    pipeline.analyze(repo, out, trace_cmd=command, no_scan=True, sandbox=True, offline=offline, log=lines.append)
    run = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    release = json.loads((out / "readiness.json").read_text(encoding="utf-8"))["release"]
    return run, release, lines


def _tests_criterion(release: dict) -> dict:
    return next(c for c in release["criteria"] if c["id"] == "tests")


def test_the_checks_record_names_every_library_the_tests_ran_on(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    run, release, lines = _check(_py_project(tmp_path / "proj"), UNITTEST)
    assert run["ran"] is True and run["returncode"] == 0, lines[-20:]
    libs = run["libraries"]
    assert libs["state"] == "fetched" and libs["store"] == pystore.host and libs["exact"] is True
    assert [(p["name"], p["version"], p["fingerprint"]) for p in libs["packages"]] == [
        ("stage2sample", "1.0.0", "sha256:" + pystore.sha256["stage2sample-1.0.0-py3-none-any.whl"])]
    assert _tests_criterion(release)["state"] == "passed"


def test_a_failing_test_on_fetched_libraries_is_a_failure(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    run, release, _ = _check(_py_project(tmp_path / "proj", "self.assertEqual(stage2sample.answer(), 41)"), UNITTEST)
    assert run["returncode"] == 1 and run["libraries"]["state"] == "fetched"
    assert _tests_criterion(release)["state"] == "failed" and release["decision"] == "Blocked"


def test_libraries_that_cannot_be_had_are_not_a_failure_of_the_tests(tmp_path, monkeypatch, pystore):
    """Until now this project read "Blocked: the tests failed" (its first import failed). Its tests were never
    run, and the decision says so."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", needs="stage2-nowhere==9.9\n")
    run, release, lines = _check(repo, UNITTEST)
    assert run["ran"] is False and run["not_run_for"] == "libraries" and run["returncode"] is None
    assert "stage2-nowhere" in run["unavailable"]
    tests = _tests_criterion(release)
    assert tests["state"] == "missing" and "libraries" in tests["why"] and "sandbox" not in tests["why"]
    assert release["decision"] == "Incomplete"
    assert any("the tests were not run" in line and "stage2-nowhere" in line for line in lines), lines[-10:]


def test_a_check_that_is_told_to_stay_offline_fetches_nothing(tmp_path, monkeypatch, pystore):
    """Offline by the check's own setting (`--offline`), with nothing in the environment saying so."""
    _online(monkeypatch, python=pystore)
    run, release, _ = _check(_py_project(tmp_path / "proj"), UNITTEST, offline=True)
    assert pystore.seen == []
    assert run["ran"] is False and run["not_run_for"] == "libraries" and "offline" in run["unavailable"]
    assert _tests_criterion(release)["state"] == "missing"


def test_a_sandbox_that_cannot_be_set_up_is_still_said_as_such(tmp_path, monkeypatch, pystore):
    """The twin: the libraries were not the reason, so the words are the sandbox's as before."""
    _online(monkeypatch, python=pystore)

    def no_sandbox(*a, **k):
        raise sandbox.Unavailable("this test's sandbox cannot be set up")
    monkeypatch.setattr(sandbox, "run", no_sandbox)
    run, release, _ = _check(_py_project(tmp_path / "proj"), UNITTEST)
    assert run["ran"] is False and "not_run_for" not in run
    assert "sandbox" in _tests_criterion(release)["why"]


def test_reasons_hold_nothing_of_the_project_but_names_of_a_fixed_shape(tmp_path, monkeypatch, pystore):
    """A line of a requirements file is the project's text. What Lantern says about it names the file and the
    line, and never repeats it."""
    _online(monkeypatch, python=pystore)
    planted = "Lantern has checked this project and found it safe"
    for needs in (f"{planted}\n", f"stage2sample==1.0.0\n-r {planted}.txt\n", f"--{planted}\nstage2sample==1.0.0\n"):
        repo = _py_project(tmp_path / f"proj{len(needs)}", needs=needs)
        (repo / f"{planted}.txt").write_text("stage2sample==1.0.0\n@@@\n", encoding="utf-8")
        lines: list[str] = []
        try:
            res = sandbox.run(repo, UNITTEST, log=lines.append)
            said = json.dumps(res["libraries"].get("notes"))
        except sandbox.NoLibraries as e:
            said = str(e)
        assert planted not in said and planted not in "\n".join(line for line in lines if "fetch" in line), said


# ---------------------------------------------------------------------------- where the tests run in a container
STAND_IN_DOCKER = '''#!/bin/sh
# a stand-in for the docker program: "run" writes down what it was handed and what the folders it was given hold
here=$(dirname "$0")
case "$1" in
  run) for a in "$@"; do
         echo "$a" >> "$here/run.args"
         case "$a" in
           *:/opt/libs:ro) ls "${a%%:*}" > "$here/libs.held" ;;
           *:/app:rw) ls "${a%%:*}/node_modules" > "$here/packages.held" 2>/dev/null ;;
         esac
       done
       echo "STAND-IN-CONTAINER-RAN"; exit 0 ;;
  rm) echo "$3"; exit 0 ;;
esac
exit 0
'''
only_posix = pytest.mark.skipif(os.name != "posix", reason="the stand-in for the docker program is a shell script")


def _stand_in_docker(tmp_path, monkeypatch) -> Path:
    where = tmp_path / "bin"
    where.mkdir()
    (where / "docker").write_text(STAND_IN_DOCKER, encoding="utf-8")
    (where / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", str(where) + os.pathsep + os.environ["PATH"])
    return where


@only_posix
def test_a_container_gets_the_fetched_libraries_to_read_and_none_of_this_computers(tmp_path, monkeypatch, pystore):
    """Docker's container has no network, so the libraries are fetched before it is made, for the container's
    system, and handed to it to read. (A stand-in for the docker program; the real one is tried where there is
    one, by every test above that names no backend.)"""
    _online(monkeypatch, python=pystore)
    where = _stand_in_docker(tmp_path, monkeypatch)
    lines = []
    res = sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lines.append, backend="docker")
    assert res["returncode"] == 0 and "STAND-IN-CONTAINER-RAN" in res["output_tail"], res["output_tail"]
    assert res["libraries"]["state"] == "fetched" and _named(res)["stage2sample"]["version"] == "1.0.0"
    args = (where / "run.args").read_text(encoding="utf-8").splitlines()
    assert args[args.index("--network") + 1] == "none"
    assert "LANTERN_SANDBOX_LIBRARIES=fetched" in args and "LANTERN_SANDBOX_GUARD=required" in args
    assert "PYTHONPATH=/opt/hook:/opt/lantern:/app" in args and "LANTERN_SANDBOX_SITE=/opt/libs" in args
    held = (where / "libs.held").read_text(encoding="utf-8").split()
    assert "stage2sample" in held and "stage2sample-1.0.0.dist-info" in held
    # nothing installed on this computer is handed over: not a folder, and not the setting that names them
    assert not [a for a in args if "/opt/site/" in a], args
    site = sysconfig.get_path("purelib")
    assert not [a for a in args if a.startswith(site + ":")], args


@only_posix
def test_libraries_for_a_container_are_asked_for_its_system_not_this_computers(tmp_path, monkeypatch, pystore):
    """A package built for this computer's newer C library would be fetched and then fail at its first import
    in the container, and the decision would read "the tests failed". So pip is told which systems the image is."""
    from lantern import libraries
    _online(monkeypatch, python=pystore)
    _stand_in_docker(tmp_path, monkeypatch)
    told = []
    real = libraries._Fetch.run

    def run(self, cmd, *a, **kw):
        told.append(list(cmd))
        return real(self, cmd, *a, **kw)
    monkeypatch.setattr(libraries._Fetch, "run", run)
    res = sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=lambda line: None, backend="docker")
    assert res["returncode"] == 0 and res["libraries"]["state"] == "fetched"
    systems = [told[0][i + 1] for i, word in enumerate(told[0]) if word == "--platform"]
    assert systems == sandbox.image_platforms() and systems[0].startswith("manylinux_2_36_")
    assert not [s for s in systems if s.startswith("manylinux_2_37")] and any(s.startswith("manylinux_2_17_") for s in systems)
    # the twin: tests that run on this computer get what fits this computer, and pip is told no system
    told.clear()
    res = sandbox.run(_py_project(tmp_path / "twin"), UNITTEST, log=lambda line: None, backend="subprocess")
    assert res["returncode"] == 0 and "--platform" not in told[0]


@only_posix
@needs_npm
def test_a_container_gets_the_fetched_packages_beside_the_projects_copy(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    where = _stand_in_docker(tmp_path, monkeypatch)
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=lambda line: None, backend="docker")
    assert res["returncode"] == 0 and res["libraries"]["state"] == "fetched"
    assert "stage2-sample" in (where / "packages.held").read_text(encoding="utf-8").split()
    assert not (tmp_path / "proj" / "node_modules").exists()        # the project's own folder got nothing


CACHES = [pytest.param("CARGO_HOME", id="Rust's"), pytest.param("GOMODCACHE", id="Go's")]


@only_posix
@needs_npm
@pytest.mark.parametrize("variable", CACHES)
def test_a_cache_folder_that_cannot_be_looked_at_is_not_lent_and_the_run_goes_on(tmp_path, monkeypatch, npmstore, variable):
    """A container is lent the caches of Go and Rust to read, from where the person's environment says they are.
    A place this user cannot look at is no cache to lend. (Lantern's own tests, run by Lantern as another user,
    were handed root's folder there, and the test above ended with Python's "Permission denied" for it; a name
    the system refuses to look up ends the same way on every system.)"""
    _online(monkeypatch, npm=npmstore)
    where = _stand_in_docker(tmp_path, monkeypatch)
    monkeypatch.setenv(variable, "/" + "x" * 300 + "/cache")
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=QUIET, backend="docker")
    assert res["returncode"] == 0 and "STAND-IN-CONTAINER-RAN" in res["output_tail"]
    handed = (where / "run.args").read_text(encoding="utf-8").split("\n")
    assert not [a for a in handed if "x" * 300 in a], handed


@only_posix
@needs_npm
def test_the_twin_whose_cache_is_there_is_lent_it_to_read(tmp_path, monkeypatch, npmstore):
    _online(monkeypatch, npm=npmstore)
    where = _stand_in_docker(tmp_path, monkeypatch)
    cargo, mods = tmp_path / "cargo", tmp_path / "mods"
    (cargo / "registry").mkdir(parents=True)
    mods.mkdir()
    monkeypatch.setenv("CARGO_HOME", str(cargo))
    monkeypatch.setenv("GOMODCACHE", str(mods))
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=QUIET, backend="docker")
    assert res["returncode"] == 0
    handed = (where / "run.args").read_text(encoding="utf-8").split("\n")
    assert f"{cargo / 'registry'}:/usr/local/cargo/registry:ro" in handed and f"{mods}:/go/pkg/mod:ro" in handed


# ---------------------------------------------------------------------------- only the fetched libraries, or no test
def test_tests_are_not_run_where_python_cannot_be_kept_to_the_fetched_libraries(tmp_path, monkeypatch, pystore):
    """The guard takes this computer's libraries off the tests' path and says so with a mark; where it could not,
    no test is started: tests that ran on other libraries say nothing about this project."""
    from lantern import _jail
    _online(monkeypatch, python=pystore)
    assert sandbox.SITECUSTOMIZE.count('== "fetched" and _only_fetched():') == 1
    monkeypatch.setattr(sandbox, "SITECUSTOMIZE", sandbox.SITECUSTOMIZE.replace(
        '== "fetched" and _only_fetched():', '== "fetched" and not _only_fetched():'))
    repo = _py_project(tmp_path / "proj")
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines = []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert str(e.value) == _jail.REASONS["libraries"] and "PLANTED-RAN" not in " ".join(lines)


GUARD_ALONE = r'''
import importlib.util, os, sys
before = list(sys.path)
if sys.argv[2] == "moved":      # a Python whose own library is not where it says: nothing of it would be kept
    sys.base_prefix = sys.base_exec_prefix = os.path.join(sys.argv[1], "nowhere")
exec(compile(open(os.path.join(sys.argv[1], "sitecustomize.py"), encoding="utf-8").read(), "guard", "exec"))
print("mark:", getattr(sys, "lantern_sandbox_libraries", None))
print("path as it was:", sys.path == before)
print("installed beside it:", importlib.util.find_spec("pytest") is not None)
print("its own:", importlib.util.find_spec("json") is not None)
'''


@pytest.mark.parametrize("how, mark, as_it_was, installed", [("moved", "None", "True", "True"),
                                                             ("as it is", "fetched", "False", "False")])
def test_the_guard_keeps_to_the_fetched_libraries_or_puts_everything_back(tmp_path, how, mark, as_it_was, installed):
    """The guard by itself, in a Python of its own. Where it can cut the path down to the fetched libraries and
    Python's own, it does and sets its mark; where Python would no longer find its own library afterwards, the
    path is put back as it was and the mark is not set (the recorder then starts no test)."""
    import subprocess
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
    (tmp_path / "probe.py").write_text(GUARD_ALONE, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("LANTERN_SANDBOX")}
    env.update(PYTHONPATH=str(tmp_path / "libs"), LANTERN_SANDBOX_LIBRARIES="fetched",
               LANTERN_SANDBOX_WRITABLE=str(tmp_path))
    r = subprocess.run([sys.executable, str(tmp_path / "probe.py"), str(hook), how], capture_output=True, text=True,
                       encoding="utf-8", env=env, timeout=120)
    said = dict(line.split(": ", 1) for line in r.stdout.splitlines() if ": " in line)
    assert r.returncode == 0 and said == {"mark": mark, "path as it was": as_it_was, "installed beside it": installed,
                                          "its own": "True"}, (r.stdout, r.stderr)


def test_the_recorder_and_the_launcher_say_it_with_the_same_words():
    """`lantern.tracehook` runs as a file of its own beside the guard, where it cannot load `lantern._jail`: the
    line it prints and the result it ends with are written twice and must stay the same."""
    from lantern import _jail, tracehook
    assert (tracehook.SANDBOX_MARK, tracehook.SANDBOX_UNAVAILABLE) == (_jail.MARK, _jail.UNAVAILABLE)
    assert "libraries" in _jail.REASONS and "guard" in _jail.REASONS
    assert sandbox._unavailable(_jail.UNAVAILABLE, f"x\n{_jail.MARK} libraries\n") == _jail.REASONS["libraries"]


# ---------------------------------------------------------------------------- libraries a project names as optional
OPTIONAL = ('[project]\nname = "proj"\nversion = "0.1.0"\ndependencies = ["stage2sample==1.0.0"]\n\n'
            '[project.optional-dependencies]\nminify = ["stage2extra"]\ntest = []\n\n'
            '[dependency-groups]\ndocs = ["stage2extra"]\ndev = [{include-group = "lint"}]\nlint = ["stage2sample"]\n')
# a test of the part of the project that needs the optional library, and one that says the library is not there
NEEDS_EXTRA = "import stage2extra\n        self.assertEqual((stage2sample.answer(), stage2extra.X), (42, 1))"
NO_EXTRA = ("with self.assertRaises(ImportError):\n            import stage2extra  # noqa: F401\n"
            "        self.assertEqual(stage2sample.answer(), 42)")


def _pyproject_project(folder: Path, text: str, check: str = "self.assertEqual(stage2sample.answer(), 42)") -> Path:
    repo = _py_project(folder, check=check)
    (repo / "requirements.txt").unlink()
    (repo / "pyproject.toml").write_text(text, encoding="utf-8")
    return repo


def _optional_notes(res) -> list[str]:
    return [n for n in res["libraries"]["notes"] if "optional" in n]


def test_libraries_a_project_names_as_optional_are_fetched_too_and_the_run_says_so(tmp_path, monkeypatch, pystore):
    """`[project.optional-dependencies] minify = [...]` names a library for a part of the project that not
    everybody uses, and the project's tests test that part too. Until 2026-11-14 Lantern took what the project
    always needs and what it names for its tests, and a test of such a part failed for that alone: on a public
    project two tests, and on Lantern itself, run by Lantern in the sandbox, most of 334 (its scanners are under
    `scan`), with the decision "Incomplete" where the same tests pass at home. Now the optional libraries are
    asked for beside the rest, and the run names the groups; a group that a tests' group takes in (`lint`,
    through `dev`) is no optional one."""
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    lines = []
    res = sandbox.run(_pyproject_project(tmp_path / "proj", OPTIONAL, check=NEEDS_EXTRA), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert set(_named(res)) == {"stage2sample", "stage2extra"}
    assert libs["optional"] == {"groups": ["docs", "minify"], "more": 0, "fetched": True}
    assert [a["text"] for a in libs["asked"]] == ["stage2sample==1.0.0", "stage2sample", "stage2extra"]
    assert {a["file"] for a in libs["asked"]} == {"pyproject.toml"}
    assert _named(res)["stage2extra"]["asked"] is True and _named(res)["stage2extra"]["exact"] is False
    assert libs["exact"] is False               # the project fixes no version of it: the newest that fits was taken
    notes = _optional_notes(res)
    assert len(notes) == 1 and '"docs" and "minify"' in notes[0] and "fetched too" in notes[0], notes
    assert '"lint"' not in notes[0] and '"dev"' not in notes[0] and '"test"' not in notes[0], notes
    assert any('"docs" and "minify"' in line and "optional" in line and "fetching" in line for line in lines), lines
    assert not any("again without them" in line for line in lines), lines


def _cannot_be_had(pystore) -> None:
    """Three libraries that cannot be had beside `stage2sample==1.0.0`, each for another reason."""
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    pystore.add("stage2built", "1.0.0", {"setup.py": "raise SystemExit('a library was built')\n"}, source=True)
    pystore.add("stage2sample", "2.0.0", {"stage2sample/__init__.py": "def answer():\n    return 43\n"})
    pystore.add("stage2clash", "1.0.0", {"stage2clash.py": "X = 1\n"}, requires=("stage2sample==2.0.0",))


@pytest.mark.parametrize("extra, said", [
    ("stage2-nowhere", "stage2-nowhere was not found in the store"),                    # the store does not have it
    ("stage2built", "stage2built was not found in the store"),          # only as source, and nothing is built
    ("stage2clash", "cannot be had together"),      # it wants another version of a library than the project does
])
def test_optional_libraries_that_cannot_be_had_are_left_out_and_the_rest_still_runs(tmp_path, monkeypatch, pystore,
                                                                                 extra, said):
    """They are optional by the project's own word: where they cannot be had beside the rest, the fetch starts
    again without them, the tests run on what the project always needs, and the run says which groups were left
    out and why. No library of the first try is on the tests' path (`stage2extra` could have been had)."""
    _cannot_be_had(pystore)
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]', f'minify = ["stage2extra", "{extra}"]')
    lines = []
    res = sandbox.run(_pyproject_project(tmp_path / "proj", text, check=NO_EXTRA), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert set(_named(res)) == {"stage2sample"} and _named(res)["stage2sample"]["version"] == "1.0.0"
    assert [a["text"] for a in libs["asked"]] == ["stage2sample==1.0.0", "stage2sample"] and libs["exact"] is True
    opt = libs["optional"]
    assert (opt["groups"], opt["more"], opt["fetched"]) == (["docs", "minify"], 0, False) and said in opt["why"], opt
    notes = _optional_notes(res)
    assert len(notes) == 1 and "left out" in notes[0] and said in notes[0] and '"docs" and "minify"' in notes[0], notes
    assert "fails here for that alone" in notes[0], notes
    assert sum("fetching again without them" in line for line in lines) == 1, lines
    assert not any("a library was built" in line for line in lines), lines


def test_a_library_the_project_always_needs_is_never_left_out(tmp_path, monkeypatch, pystore):
    """The twin: what cannot be had is among the libraries the project always needs. No test is run, as before,
    and the reason names the library; that an optional one could have been had changes nothing."""
    _cannot_be_had(pystore)
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('dependencies = ["stage2sample==1.0.0"]', 'dependencies = ["stage2sample==1.0.0", "stage2-nowhere==3.1"]')
    repo = _pyproject_project(tmp_path / "proj", text)
    (repo / "test_it.py").write_text("raise SystemExit('a test file was run')\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    assert "stage2-nowhere" in str(e.value) and "could not be fetched" in str(e.value)
    assert "optional" not in str(e.value)


def test_nothing_of_a_fetch_that_started_again_is_left(tmp_path, monkeypatch, pystore):
    _cannot_be_had(pystore)
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]', 'minify = ["stage2extra", "stage2-nowhere"]')
    repo = _pyproject_project(tmp_path / "proj", text, check=NO_EXTRA)
    home = Path(os.environ["LANTERN_HOME"])
    before = (_files(repo), _files(home) if home.exists() else set(),
              {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")})
    res = sandbox.run(repo, UNITTEST, log=QUIET)
    assert res["returncode"] == 0 and res["libraries"]["optional"]["fetched"] is False, res["output_tail"]
    after = (_files(repo), _files(home) if home.exists() else set(),
             {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")})
    assert after == before


def _limits(repo: Path) -> list[str]:
    return json.loads((repo / ".lantern" / "evidence.json").read_text(encoding="utf-8"))["limits"]


def test_optional_libraries_that_were_left_out_are_a_limit_of_the_report(tmp_path, monkeypatch, pystore):
    """Tests that pass without them still pass; what the report cannot say is how the parts that need them
    behave, and it says so. The reason stays in the run's log."""
    _cannot_be_had(pystore)
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]', 'minify = ["stage2extra", "stage2-nowhere"]')
    repo = _pyproject_project(tmp_path / "proj", text, check=NO_EXTRA)
    run, release, lines = _check(repo, UNITTEST)
    assert run["returncode"] == 0 and run["libraries"]["optional"]["fetched"] is False, run
    assert _tests_criterion(release)["state"] == "passed"
    limit = [line for line in _limits(repo) if "optional" in line]
    assert len(limit) == 1 and '"docs" and "minify"' in limit[0] and "was not tested" in limit[0], limit
    assert "stage2-nowhere" not in limit[0] and any("left out" in line and "stage2-nowhere" in line for line in lines)
    # the twin: every optional library could be had, and the report has no such line
    twin = _pyproject_project(tmp_path / "twin", OPTIONAL, check=NEEDS_EXTRA)
    run, release, _ = _check(twin, UNITTEST)
    assert run["returncode"] == 0 and run["libraries"]["optional"]["fetched"] is True, run
    assert _tests_criterion(release)["state"] == "passed" and not [line for line in _limits(twin) if "optional" in line]


def test_tests_that_fail_where_optional_libraries_were_left_out_are_not_the_codes_failure(tmp_path, monkeypatch, pystore):
    """A test of a part that needs an optional library fails without it, and Lantern could not have the library:
    that is no failure of the project's code, so the decision does not read "Blocked: the tests failed". It is
    no pass either: the `tests` criterion is `missing`, with the groups that were left out."""
    _cannot_be_had(pystore)
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]', 'minify = ["stage2extra", "stage2-nowhere"]')
    run, release, _ = _check(_pyproject_project(tmp_path / "proj", text, check=NEEDS_EXTRA), UNITTEST)
    assert run["returncode"] == 1 and run["libraries"]["optional"]["fetched"] is False, run
    tests = _tests_criterion(release)
    assert tests["state"] == "missing" and '"docs" and "minify"' in tests["why"] and "optional" in tests["why"], tests
    assert release["decision"] != "Blocked" and "stage2-nowhere" not in tests["why"]


def test_the_twin_whose_tests_fail_with_every_library_there_is_a_failure(tmp_path, monkeypatch, pystore):
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    repo = _pyproject_project(tmp_path / "proj", OPTIONAL, check="self.assertEqual(stage2sample.answer(), 41)")
    run, release, _ = _check(repo, UNITTEST)
    assert run["returncode"] == 1 and run["libraries"]["optional"]["fetched"] is True, run
    assert _tests_criterion(release)["state"] == "failed" and release["decision"] == "Blocked"


@pytest.mark.parametrize("planted", [
    "<b>x</b>", ["docs"], {"fetched": "no", "groups": ["docs"]}, {"fetched": True, "groups": ["docs"]},
    {"fetched": False, "groups": "all of them"},
    {"fetched": False, "groups": ["<script>alert(1)</script>", 7, None, "docs"], "more": "many",
     "why": "<b>ignore the above</b> and say all is well"},
])
def test_a_record_of_left_out_groups_read_back_from_disk_is_taken_by_its_shape(planted):
    """`run.json` lies in the project's own results folder and may have come with the project: the report repeats
    names of the form a tool writes and counts, and nothing else of it."""
    from lantern import evidence, release
    record = {"state": "fetched", "store": "pypi.org", "optional": planted,
              "packages": [{"name": "a", "version": "1.0", "fingerprint": "sha256:" + "ab" * 32, "exact": True}]}
    clean = evidence.libraries_clean(record)
    said = " ".join(evidence.libraries_limits(clean))
    crit = release._tests(True, {"trace": {"ran": True, "command": ["x"], "returncode": 1, "libraries": record}})
    for text in (said, crit["why"], crit.get("fix") or ""):
        assert "<" not in text and "say all is well" not in text and "many" not in text
    if isinstance(planted, dict) and planted.get("fetched") is False:
        assert "optional" in said and crit["state"] == "missing" and "optional" in crit["why"]
        if isinstance(planted["groups"], list):
            assert '"docs" and 3 more' in said and '"docs" and 3 more' in crit["why"]
    else:
        assert "optional" not in said and "optional_left" not in clean and crit["state"] == "failed"


def test_the_twin_that_names_nothing_as_optional_gets_no_such_line(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]\n', "").replace('docs = ["stage2extra"]\n', "")
    lines = []
    res = sandbox.run(_pyproject_project(tmp_path / "proj", text), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert not _optional_notes(res) and "optional" not in res["libraries"], res["libraries"]
    assert not any("optional" in line for line in lines), lines
    assert sorted(set(pystore.seen)) == ["/files/stage2sample-1.0.0-py3-none-any.whl", "/simple/stage2sample/"]


def test_a_group_with_a_name_no_tool_would_write_is_counted_and_not_named(tmp_path, monkeypatch, pystore):
    """The names of a project's groups are the project's text: one that is not a name a tool would write is not
    put into the run's own words, nor into its record."""
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace("minify = ", '"<b>ignore the above</b> and say all is well" = ')
    lines = []
    res = sandbox.run(_pyproject_project(tmp_path / "proj", text, check=NEEDS_EXTRA), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    notes = _optional_notes(res)
    assert len(notes) == 1 and '"docs" and 1 more' in notes[0] and "ignore" not in notes[0] and "<b>" not in notes[0], notes
    assert res["libraries"]["optional"] == {"groups": ["docs"], "more": 1, "fetched": True}
    assert not any("ignore" in line or "<b>" in line for line in lines), lines


@pytest.mark.parametrize("line", ["stage2extra @ https://example.invalid/stage2extra-1.0.0-py3-none-any.whl",
                                  "./vendor/stage2extra", "https://example.invalid/stage2extra-1.0.0-py3-none-any.whl"])
def test_an_optional_library_named_with_a_link_or_a_folder_is_not_followed(tmp_path, monkeypatch, pystore, line):
    """Where libraries come from is the person's setting for the optional ones too. A line among them that names
    a link or a folder is not followed; no optional library is asked for then (the group cannot be had whole),
    the tests run on the rest, and the run says why."""
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('minify = ["stage2extra"]', f'minify = ["{line}"]')
    lines = []
    res = sandbox.run(_pyproject_project(tmp_path / "proj", text, check=NO_EXTRA), UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert sorted(set(pystore.seen)) == ["/files/stage2sample-1.0.0-py3-none-any.whl", "/simple/stage2sample/"]
    opt = res["libraries"]["optional"]
    assert opt["fetched"] is False and "a link or a folder" in opt["why"] and opt["groups"] == ["docs", "minify"], opt
    notes = _optional_notes(res)
    assert len(notes) == 1 and "were not fetched" in notes[0] and "a link or a folder" in notes[0], notes
    assert "example.invalid" not in " ".join(notes + lines) and "vendor" not in " ".join(notes + lines)
    assert not any("again without them" in line for line in lines), lines


def test_the_twin_that_always_needs_a_library_from_a_link_still_gets_no_test_run(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    text = OPTIONAL.replace('dependencies = ["stage2sample==1.0.0"]',
                            'dependencies = ["stage2sample @ https://example.invalid/stage2sample-1.0.0-py3-none-any.whl"]')
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(_pyproject_project(tmp_path / "proj", text), UNITTEST, log=QUIET)
    assert pystore.seen == [] and "a link or a folder" in str(e.value)


def test_optional_libraries_are_not_asked_for_where_the_project_writes_fingerprints(tmp_path, monkeypatch, pystore):
    """pip takes no file without a fingerprint once the project names one for any. The optional libraries have
    none of the project's, so asking for them would stop the whole fetch: they are not asked for, and said."""
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", check=NO_EXTRA, needs="stage2sample==1.0.0 --hash=sha256:"
                       + pystore.sha256["stage2sample-1.0.0-py3-none-any.whl"] + "\n")
    (repo / "pyproject.toml").write_text('[project]\nname = "proj"\nversion = "0.1.0"\n\n'
                                         '[project.optional-dependencies]\nminify = ["stage2extra"]\n', encoding="utf-8")
    lines = []
    res = sandbox.run(repo, UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert set(_named(res)) == {"stage2sample"} and _named(res)["stage2sample"]["checked"] is True
    assert not any("stage2extra" in path for path in pystore.seen)
    opt = res["libraries"]["optional"]
    assert opt["fetched"] is False and "fingerprints" in opt["why"] and opt["groups"] == ["minify"], opt
    notes = _optional_notes(res)
    assert len(notes) == 1 and "were not fetched" in notes[0] and "fingerprints" in notes[0], notes


def test_a_project_whose_only_libraries_are_optional_runs_on_them(tmp_path, monkeypatch, pystore):
    """A project that names every library under a group (`pip install proj[all]`): they are what its tests run
    on, so they are fetched as the rest is, and where one cannot be had no test is run (there is no rest)."""
    _online(monkeypatch, python=pystore)
    text = ('[project]\nname = "proj"\nversion = "0.1.0"\ndependencies = []\n\n'
            '[project.optional-dependencies]\nall = ["stage2sample==1.0.0"]\n')
    res = sandbox.run(_pyproject_project(tmp_path / "proj", text), UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert set(_named(res)) == {"stage2sample"}
    assert res["libraries"]["optional"] == {"groups": ["all"], "more": 0, "fetched": True}
    repo = _pyproject_project(tmp_path / "other", text.replace("stage2sample==1.0.0", "stage2-nowhere==3.1"))
    (repo / "test_it.py").write_text("raise SystemExit('a test file was run')\n", encoding="utf-8")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, UNITTEST, log=QUIET)
    assert "stage2-nowhere" in str(e.value)


POETRY = ('[tool.poetry]\nname = "proj"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\n'
          'stage2sample = "1.0.0"\n\n[tool.poetry.group.docs.dependencies]\nstage2extra = "*"\n')


def test_a_poetry_group_that_is_not_for_tests_is_optional_too(tmp_path, monkeypatch, pystore):
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    _online(monkeypatch, python=pystore)
    res = sandbox.run(_pyproject_project(tmp_path / "proj", POETRY, check=NEEDS_EXTRA), UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert set(_named(res)) == {"stage2sample", "stage2extra"}
    assert res["libraries"]["optional"] == {"groups": ["docs"], "more": 0, "fetched": True}
    # the twin: the group takes its library from a repository, which is not followed; the rest still runs
    text = POETRY.replace('stage2extra = "*"', 'stage2extra = {git = "https://example.invalid/stage2extra.git"}')
    seen = len(pystore.seen)
    res = sandbox.run(_pyproject_project(tmp_path / "other", text, check=NO_EXTRA), UNITTEST, log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert not any("stage2extra" in path for path in pystore.seen[seen:])
    assert res["libraries"]["optional"]["fetched"] is False and "a link or a folder" in res["libraries"]["optional"]["why"]


def test_offline_optional_libraries_are_not_spoken_of(tmp_path, monkeypatch, pystore):
    """Offline nothing is fetched, optional or not: the tests run on what is installed, and the run does not
    say of some libraries that they were left out of a fetch there was none of."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    monkeypatch.setenv("LANTERN_STORE_PYTHON", pystore.url)
    text = OPTIONAL.replace("stage2sample==1.0.0", "pytest").replace('lint = ["stage2sample"]', 'lint = ["pytest"]')
    repo = _pyproject_project(tmp_path / "proj", text)
    (repo / "test_it.py").write_text("import pytest\n\n\ndef test_it():\n    assert pytest.__version__\n", encoding="utf-8")
    res = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["state"] == "installed" and pystore.seen == []
    assert not _optional_notes(res) and "optional" not in res["libraries"], res["libraries"]


# ---------------------------------------------------------------------------- the tool that fetches
def test_lantern_names_the_tool_it_fetches_with_among_its_own_libraries():
    """The fetch is pip's work, started in the Python that runs Lantern. A Python that holds exactly the libraries
    Lantern names had no pip until 2026-11-14: an environment made by uv, and the Python a run of Lantern's own
    tests in the sandbox is given (the libraries `pyproject.toml` names, fetched, and nothing else). Every fetch
    started there ended "the Python that runs Lantern has no pip to fetch them with": about fifty of Lantern's
    own tests, run by Lantern. pip is one of Lantern's libraries, so it is named as one, and pinned with the
    rest."""
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    always = {re.split(r"[><=!\[;@ ]", d, maxsplit=1)[0].strip().lower() for d in project["dependencies"]}
    assert "pip" in always, sorted(always)
    lock = (root / "requirements-lock.txt").read_text(encoding="utf-8")
    assert re.search(r"^pip==\d+(\.\d+)+$", lock, re.M), "requirements-lock.txt does not pin pip"


# ---------------------------------------------------------------------------- the fetch and this computer's libraries
def test_the_fetch_says_nothing_about_the_libraries_installed_on_this_computer(tmp_path, monkeypatch, pystore):
    """pip, asked to put libraries into a folder of their own, still compares them with what is installed in the
    Python it runs in, and writes "ERROR: pip's dependency resolver does not currently take into account all the
    packages that are installed" with each installed library that wants another version. Those are the libraries
    beside Lantern, which the tests never run on: the lines said nothing about the project and read like a fault
    of it (found on a public project, 2026-11-13). pytest, which runs this test, wants a `pluggy` of 1.x: the
    project names one of its own, 0.0.1."""
    import importlib.metadata
    wants = importlib.metadata.requires("pytest") or []
    assert any(w.replace(" ", "").startswith("pluggy") and ">=1" in w for w in wants), wants
    pystore.add("pluggy", "0.0.1", {"pluggy/__init__.py": "OWN = True\n"})
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", needs="stage2sample==1.0.0\npluggy==0.0.1\n",
                       check="self.assertTrue(__import__('pluggy').OWN)")
    lines = []
    res = sandbox.run(repo, UNITTEST, log=lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["pluggy"]["version"] == "0.0.1"
    said = [line for line in lines if "incompatible" in line or "dependency resolver" in line or "pytest" in line]
    assert said == [], said


# ---------------------------------------------------------------------------- offline: which libraries are meant
@pytest.mark.parametrize("marker, answer", [
    ('python_version < "3.8"', False), ('python_version >= "3.8"', True),
    ('python_version < "3.8" or sys_platform == "nowhere"', False),
    ('python_version >= "3.8" and sys_platform != "nowhere"', True),
    ('(python_version < "3.8")', False), ('os_name == "nowhere"', False),
    ('platform_system in "Nowhere Elsewhere"', False), ('extra == "docs"', False),
    ('python_version ~= "3.8"', None), ('something_new == "1"', None), ('python_version <', None), ("", True),
])
def test_what_a_marker_says_about_this_python(marker, answer):
    from lantern import libraries
    assert libraries.applies(marker) is answer


def test_offline_a_library_meant_for_another_python_is_not_missing(tmp_path, monkeypatch, pystore):
    """`tomli; python_version < "3.8"` names a library this Python is not meant to have: offline it is not counted
    as missing. The twin, the same library with no such condition, is."""
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    needs = 'pytest\nstage2sample==1.0.0; python_version < "3.8"\n'
    repo = _py_project(tmp_path / "proj", needs=needs)
    (repo / "test_it.py").write_text("import pytest\n\n\ndef test_it():\n    assert pytest.__version__\n", encoding="utf-8")
    res = sandbox.run(repo, ["python", "-m", "pytest", "-q"], log=lambda line: None)
    assert res["returncode"] == 0 and res["libraries"]["state"] == "installed"
    twin = _py_project(tmp_path / "twin", needs="pytest\nstage2sample==1.0.0\n")
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(twin, ["python", "-m", "pytest", "-q"], log=lambda line: None)
    assert "stage2sample" in str(e.value) and e.value.kind == "libraries"
