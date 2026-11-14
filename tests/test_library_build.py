"""A library that has to be built is built in the sandbox, with the network off (a firm pass or fail, stage 2).

Until this step only ready-built files were taken. A library whose one version the project fixes, and that the
store has for this system as source only, meant "no test was run": found by the stage's finish check, on a public
project whose lock file fixes a version that is ready-built for another system only, so that the Python half of its
tests could not be run from its link.

Building a library runs code it brings, and nobody who runs the tests has read that code. So the build gets what a
library's code gets when the tests run, and no more: the kernel's walls of the tests' run (no network, the person's
own folders closed to reads, writes only in the build's own folders, everything it started ended with it), a time
limit and the run's memory. Only what Lantern's own program does needs a way out (the source package and the tools
the build asks for, each fetched through the doorkeeper as the libraries are), and that program runs no line of the
library. What the build may hand back is one package of the name and version asked for.

Here are honest builds beside hostile ones: a build that looks for keys, reads and writes what is the person's
own, reaches for the store and for another address, leaves a program running, never ends, eats memory, hands back
another package than the one asked for; a source package that is not the one the project names, that holds a
link or a name that leaves its folder; build tools named by a link. Where no library is built (macOS, Windows, a
container, a sandbox inside a sandbox) the reason says so, and those cases run on every system.

No test here reaches the internet: the store is a stand-in on this computer (`tests/stores.py`), the address
"outside" is one that is nobody's (192.0.2.1), the name one that never exists (`example.invalid`)."""
import hashlib
import io
import json
import os
import re
import shutil
import sys
import sysconfig
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from stores import PyStore, sdist
from test_libraries import (NO_EXTRA, OPTIONAL, UNITTEST, WALLS, _check, _files, _named, _online, _pyproject_project,
                            _stand_in_docker, only_posix)
from test_library_versions import FILES_NAMED, _for_another_system, _lock_text

from lantern import _builder, evidence, libraries, sandbox

LINUX = sys.platform.startswith("linux")
QUIET = lambda line: None       # noqa: E731
WHEEL = "stage2sample-1.0.0-py3-none-any.whl"
builds = pytest.mark.skipif(bool(libraries.cannot_build()),
                            reason="no library is built on this system (what Lantern says there is tested below)")
KINDS = ["uv.lock", "Pipfile.lock", "pins", "hashed"]    # how a project fixes the one version of a library


@pytest.fixture()
def pystore():
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        yield store


@pytest.fixture()
def other():
    """A server on this computer that is none of the run's: it writes down every call."""
    with PyStore() as server:
        server.pages["/secret"] = ("text/plain", b"not for the build")
        yield server


@pytest.fixture(params=WALLS)
def walls(request, monkeypatch):
    """Both ways a run is held (`tests/test_libraries.py`): with a network of its own, and without one."""
    if request.param == "doorkeeper":
        monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
    return request.param


@pytest.fixture()
def person(monkeypatch):
    """What is the person's own on this computer (`tests/test_library_hostile.py`): a home folder with a key file
    every user may read, and a folder anybody may write into with a file of theirs in it."""
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


# ---------------------------------------------------------------------------- a source package and its build
# The build of a test library: what a build tool does, with the standard library only. `BODY` is what its
# `build_wheel` does, the one function a build has to have.
BACKEND = r'''import base64
import hashlib
import os
import zipfile


def about():
    name = version = None
    for line in open("PKG-INFO", encoding="utf-8"):
        if line.startswith("Name: "):
            name = line[6:].strip()
        if line.startswith("Version: "):
            version = line[9:].strip()
    return name, version


def sources():
    found = {}
    for folder, _, names in os.walk("."):
        for n in sorted(names):
            path = os.path.relpath(os.path.join(folder, n), ".").replace(os.sep, "/")
            if n.endswith(".py") and path not in ("own_backend.py", "setup.py"):
                found[path] = open(path, encoding="utf-8").read()
    return found


def wheel(folder, files, name=None, version=None, tag="py3-none-any", inside=None):
    known = about()
    name, version = name or known[0], version or known[1]
    dist = name.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    parts = {path: data if isinstance(data, bytes) else data.encode() for path, data in files.items()}
    parts[f"{info}/METADATA"] = f"Metadata-Version: 2.1\nName: {inside or name}\nVersion: {version}\n".encode()
    parts[f"{info}/WHEEL"] = f"Wheel-Version: 1.0\nGenerator: lantern-tests\nRoot-Is-Purelib: true\nTag: {tag}\n".encode()
    record = []
    for path, data in parts.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(data)}")
    parts[f"{info}/RECORD"] = ("\n".join(record + [f"{info}/RECORD,,"]) + "\n").encode()
    fname = f"{dist}-{version}-{tag}.whl"
    with zipfile.ZipFile(os.path.join(folder, fname), "w", zipfile.ZIP_DEFLATED) as z:
        for path, data in parts.items():
            z.writestr(zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0)), data)
    return fname


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
BODY
'''
HONEST = "    return wheel(wheel_directory, sources())"
OWN = '[build-system]\nrequires = []\nbuild-backend = "own_backend"\nbackend-path = ["."]\n'


def source(name: str, version: str, files: dict[str, str], body: str = HONEST, pyproject: str | None = OWN):
    """(file name, bytes) of a source package of `name` whose build is `body`, the lines of its `build_wheel`."""
    parts = {**files, "own_backend.py": BACKEND.replace("BODY", body)}
    if pyproject is not None:
        parts["pyproject.toml"] = pyproject
    return sdist(name, version, parts)


def _project(folder: Path, store: PyStore, kind: str, digest: str, name: str = "stage2mac", version: str = "3.0.0",
             check: str = "self.assertEqual(stage2mac.N, 3)") -> Path:
    """A project that names `stage2sample`, which the store has ready-built, and `name`, of which the project fixes
    the one version in the way of `kind`: a lock file with the source's fingerprint, an exact version, an exact
    version with the fingerprint beside it. Its one test imports both."""
    folder.mkdir(parents=True)
    ready = store.sha256[WHEEL]
    if kind in ("pins", "hashed"):
        marks = (f" --hash=sha256:{ready}", f" --hash=sha256:{digest}") if kind == "hashed" else ("", "")
        (folder / "requirements.txt").write_text(f"stage2sample==1.0.0{marks[0]}\n{name}=={version}{marks[1]}\n",
                                                 encoding="utf-8")
    else:
        entries = [("stage2sample", "1.0.0", ready), (name, version, [(f"{name}-{version}.tar.gz", digest)])]
        (folder / kind).write_text(_lock_text(kind, entries), encoding="utf-8")
        if kind == "Pipfile.lock":
            (folder / "Pipfile").write_text(
                '[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\nverify_ssl = true\n\n[packages]\n\n'
                f'[dev-packages]\nstage2sample = "*"\n{name} = "*"\n', encoding="utf-8")
        else:
            (folder / "pyproject.toml").write_text(
                f'[project]\nname = "proj"\nversion = "0.1.0"\ndependencies = ["stage2sample", "{name}"]\n',
                encoding="utf-8")
    (folder / "test_it.py").write_text(
        "import json\nimport unittest\n\nimport stage2sample\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        import {name}\n        self.assertEqual(stage2sample.answer(), 42)\n        {check}\n", encoding="utf-8")
    return folder


def _run(repo: Path, log=QUIET, **more):
    """The project's tests on this computer, not in a container: where Docker answers a run would take it, and
    nothing is built for a container (a case of its own below)."""
    return sandbox.run(repo, UNITTEST, log=log, backend="subprocess", **more)


def _refused(repo: Path, **more) -> tuple[str, list[str]]:
    """(the reason, the log) of a run whose libraries could not be had; the project's test file would say if it ran."""
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines: list[str] = []
    with pytest.raises(sandbox.NoLibraries) as e:
        _run(repo, lines.append, **more)
    said = str(e.value)
    assert "tests were not run" in said and "PLANTED-RAN" not in " ".join(lines), (said, lines)
    return said, lines


def _sources_asked(store: PyStore) -> list[str]:
    return [path for path in store.seen if path.endswith(".tar.gz")]


def _going(mark: str) -> list[int]:
    """The programs on this computer that were started with `mark` among their words."""
    found = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                if mark.encode() in Path("/proc", name, "cmdline").read_bytes():
                    found.append(int(name))
            except OSError:
                pass
    return found


# ---------------------------------------------------------------------------- an honest build
@builds
@pytest.mark.parametrize("kind", KINDS)
def test_a_library_that_is_there_as_source_only_is_built_and_the_tests_run_on_it(tmp_path, monkeypatch, pystore, kind,
                                                                                walls):
    """The store has the version the project fixes as source only. It is built, in the sandbox with the network
    off, and the tests run on what the build handed back. The record says so: which file it was built from, that
    file's fingerprint, and whether that fingerprint is one the project names."""
    _online(monkeypatch, python=pystore)
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}))
    lines: list[str] = []
    res = _run(_project(tmp_path / "proj", pystore, kind, digest), lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    built = _named(res)["stage2mac"]
    assert built["version"] == "3.0.0" and built["exact"] is True and built["checked"] is (kind != "pins")
    assert built["built"] == {"from": "stage2mac-3.0.0.tar.gz", "source_fingerprint": "sha256:" + digest, "with": []}
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", built["fingerprint"]) and built["fingerprint"] != "sha256:" + digest
    assert res["libraries"]["built"] == 1 and "built" not in _named(res)["stage2sample"]
    assert _named(res)["stage2sample"]["fingerprint"] == "sha256:" + pystore.sha256[WHEEL]
    assert _sources_asked(pystore) == ["/files/stage2mac-3.0.0.tar.gz"]
    log = " | ".join(lines)
    assert "building it from its source" in log and "with the network off" in log, lines
    assert any("stage2mac 3.0.0" in note and "built" in note for note in res["libraries"]["notes"]), res["libraries"]


@builds
@pytest.mark.parametrize("older", [True, False], ids=["an older one fits", "no version fits"])
@pytest.mark.parametrize("kind", FILES_NAMED)
def test_a_version_that_is_ready_built_for_another_system_only_is_built_from_its_source(tmp_path, monkeypatch, pystore,
                                                                                       kind, older):
    """What the stage's finish check met on a public project: the lock file fixes a version that the store has
    ready-built for another system only, and as source. pip's word for it is "conflicting dependencies" where an
    older version would fit. It is the version the lock file fixes that is built, and the tests run on it."""
    _online(monkeypatch, python=pystore)
    name, data = source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"})
    repo = _for_another_system(tmp_path / "proj", pystore, kind, older=older, source=data)
    (repo / "test_it.py").write_text(
        "import unittest\n\nimport stage2mac\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        "        self.assertEqual(stage2mac.N, 3)\n", encoding="utf-8")
    res = _run(repo)
    assert res["returncode"] == 0, res["output_tail"]
    built = _named(res)["stage2mac"]
    assert built["version"] == "3.0.0" and built["checked"] is True and built["built"]["from"] == name
    assert built["built"]["source_fingerprint"] == "sha256:" + pystore.sha256[name]


@builds
def test_the_twin_whose_test_fails_on_a_built_library_still_fails(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}))
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest, check="self.assertEqual(stage2mac.N, 4)"))
    assert res["returncode"] not in (0, None) and "AssertionError" in res["output_tail"]
    assert res["libraries"]["built"] == 1


def test_the_twin_that_is_ready_built_is_not_built(tmp_path, monkeypatch, pystore):
    """A library the store has ready-built for this system is taken as that, also where its source lies beside
    it: the source is not asked for, and the record says nothing of a build."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"})
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 4\n"},
                                              body="    raise SystemExit('PLANTED-BUILT')"))
    lines: list[str] = []
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest), lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert "built" not in res["libraries"] and "built" not in _named(res)["stage2mac"]
    assert _sources_asked(pystore) == [] and "PLANTED" not in " ".join(lines)


def test_a_version_the_project_does_not_fix_is_not_built(tmp_path, monkeypatch, pystore):
    """Which source to build is the project's word: with no exact version, Lantern would have to pick one. Then
    nothing is built, the source is not asked for, and the reason is the one it was."""
    _online(monkeypatch, python=pystore)
    pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"},
                                     body="    raise SystemExit('PLANTED-BUILT')"))
    repo = _project(tmp_path / "proj", pystore, "pins", "")
    (repo / "requirements.txt").write_text("stage2sample==1.0.0\nstage2mac>=3\n", encoding="utf-8")
    said, lines = _refused(repo)
    assert "stage2mac was not found in the store" in said and "ready-built" in said, said
    assert _sources_asked(pystore) == [] and "PLANTED-BUILT" not in " ".join(lines)


# ---------------------------------------------------------------------------- the tools a build asks for
TOOL = '[build-system]\nrequires = ["stage2backend>=1"]\nbuild-backend = "stage2backend"\n'


def _tool(store: PyStore, body: str = HONEST, more: str = "") -> None:
    """A build tool in the store, ready-built: `stage2backend` 1.2.0."""
    store.add("stage2backend", "1.2.0", {"stage2backend.py": BACKEND.replace("BODY", body) + more})


@builds
def test_the_tools_a_build_asks_for_are_fetched_ready_built_and_are_not_the_tests(tmp_path, monkeypatch, pystore):
    """A source package names the tools its build needs. They are fetched from the store as the libraries are
    (ready-built only, through the doorkeeper), the record names them, and the tests do not get them."""
    _online(monkeypatch, python=pystore)
    _tool(pystore)
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": TOOL, "stage2mac.py": "N = 3\n"}))
    check = ("with self.assertRaises(ImportError):\n            import stage2backend  # noqa: F401\n"
             "        self.assertEqual(stage2mac.N, 3)")
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest, check=check))
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2mac"]["built"]["with"] == ["stage2backend 1.2.0"]
    assert set(_named(res)) == {"stage2mac", "stage2sample"}


@builds
def test_a_build_may_ask_for_more_tools_once_it_has_looked_at_its_source(tmp_path, monkeypatch, pystore):
    """A build tool may say what else it needs after a look at the source (with the network off, like the build).
    Those are fetched the same way, once, and named in the record too."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2helper", "0.5.0", {"stage2helper.py": "X = 5\n"})
    _tool(pystore, body="    import stage2helper\n    return wheel(wheel_directory, sources())",
          more="\n\ndef get_requires_for_build_wheel(config_settings=None):\n    return ['stage2helper==0.5.0']\n")
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": TOOL, "stage2mac.py": "N = 3\n"}))
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest))
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2mac"]["built"]["with"] == ["stage2backend 1.2.0", "stage2helper 0.5.0"]


@builds
def test_a_source_that_says_nothing_about_its_build_is_built_the_older_way(tmp_path, monkeypatch, pystore):
    """A source package with no `pyproject.toml`, or with none that names a build, is built by setuptools: the rule
    every tool follows. (A stand-in for setuptools in the store; nothing of the real one is fetched.)"""
    _online(monkeypatch, python=pystore)
    legacy = BACKEND.replace("BODY", HONEST) + ("\n\nclass _Legacy:\n    build_wheel = staticmethod(build_wheel)\n\n\n"
                                                "__legacy__ = _Legacy()\n")
    pystore.add("setuptools", "99.0.0", {"setuptools/__init__.py": "", "setuptools/build_meta.py": legacy})
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {
        "setup.py": "raise SystemExit('PLANTED-BUILT: setup.py was run by something else than the build tool')\n",
        "stage2mac.py": "N = 3\n"}))
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest))
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2mac"]["built"]["with"] == ["setuptools 99.0.0"]


C_SOURCE = '''#include <Python.h>
static PyObject *answer(PyObject *self, PyObject *args) { return PyLong_FromLong(42); }
static PyMethodDef methods[] = {{"answer", answer, METH_NOARGS, ""}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "stage2c", NULL, -1, methods};
PyMODINIT_FUNC PyInit_stage2c(void) { return PyModule_Create(&module); }
'''
C_BUILD = '''    import subprocess
    import sysconfig
    built = "stage2c" + sysconfig.get_config_var("EXT_SUFFIX")
    subprocess.run(["cc", "-shared", "-fPIC", "-I" + sysconfig.get_config_var("INCLUDEPY"), "stage2c.c", "-o", built],
                   check=True)
    system = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    return wheel(wheel_directory, {built: open(built, "rb").read()}, tag="py3-none-" + system)'''
C_READY = bool(shutil.which("cc")) and os.path.exists(os.path.join(sysconfig.get_config_var("INCLUDEPY") or "-", "Python.h"))


@builds
@pytest.mark.skipif(not C_READY, reason="needs a C compiler and Python's own header files on this computer")
def test_a_library_written_in_c_is_built_with_this_computers_compiler(tmp_path, monkeypatch, pystore):
    """What a library that has to be built usually is: a part written in C. The compiler is this computer's own
    (no program is fetched), started by the build inside the walls."""
    _online(monkeypatch, python=pystore)
    digest = pystore.put("stage2c", *source("stage2c", "1.0.0", {"stage2c.c": C_SOURCE}, body=C_BUILD))
    res = _run(_project(tmp_path / "proj", pystore, "uv.lock", digest, name="stage2c", version="1.0.0",
                        check="self.assertEqual(stage2c.answer(), 42)"))
    assert res["returncode"] == 0, res["output_tail"]
    assert _named(res)["stage2c"]["built"]["from"] == "stage2c-1.0.0.tar.gz"


# ---------------------------------------------------------------------------- a hostile build
HOSTILE = '''    import socket
    import subprocess
    import sys
    import tempfile
    said = {}

    def attempt(name, fn):
        try:
            said[name] = "got " + repr(fn())[:70]
        except BaseException as e:      # whatever the sandbox answers with
            said[name] = "refused " + type(e).__name__

    def up(*names):
        at = os.getcwd()
        for _ in range(12):
            at = os.path.dirname(at)
            if os.path.lexists(os.path.join(at, *names)):
                return os.path.join(at, *names)
        return os.path.join(os.sep, "nowhere", *names)

    def tcp(host, port):
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(b"GET /secret HTTP/1.0\\r\\n\\r\\n")
            return s.recv(100)

    def udp(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return s.sendto(b"x", (host, port))
        finally:
            s.close()

    words = ("KEY", "TOKEN", "SECRET", "PASSW")
    attempt("names", lambda: sorted(k for k in os.environ if any(w in k.upper() for w in words)))
    attempt("the person's key file", lambda: open(KEY).read())
    attempt("the names in the person's home folder", lambda: os.listdir(os.path.dirname(os.path.dirname(KEY))))
    attempt("a file of the project", lambda: open(os.path.join(REPO, ".env")).read())
    attempt("the copy the tests run on", lambda: open(up("app", ".env")).read())
    attempt("a change to the tests", lambda: open(up("app", "test_it.py"), "a").write("# changed\\n"))
    attempt("a file among the tests' libraries", lambda: open(up("libs", "stage2planted.py"), "w").write("X = 1\\n"))
    attempt("the store", lambda: tcp("127.0.0.1", STORE))
    attempt("where the doorkeeper was", lambda: tcp("127.0.0.1", 8118))
    attempt("another server on this computer", lambda: tcp("127.0.0.1", OTHER))
    attempt("an address outside", lambda: tcp("192.0.2.1", 80))
    attempt("a datagram to an address outside", lambda: udp("192.0.2.1", 9))
    attempt("a name", lambda: socket.getaddrinfo("example.invalid", 80))
    attempt("a file where anybody may write", lambda: open(os.path.join(DROP, "built.txt"), "w").write("x"))
    attempt("a file in the project", lambda: open(os.path.join(REPO, "built.txt"), "w").write("x"))
    attempt("twin: a file in its own source", lambda: open("made-here.txt", "w").write("x"))
    attempt("twin: a file in the temp folder", lambda: open(os.path.join(tempfile.gettempdir(), "t.txt"), "w").write("x"))
    attempt("twin: its own files", lambda: open("PKG-INFO").read()[:14])
    attempt("twin: a program", lambda: subprocess.run([sys.executable, "-c", "print(6 * 7)"], capture_output=True,
                                                      text=True, timeout=60).stdout.strip())
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)", MARK], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return wheel(wheel_directory, {"stage2hostile.py": "SAID = " + repr(said) + "\\n"})'''
PLANTED_NAMES = ("ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "LANTERN_TOKEN", "PIP_INDEX_URL")


@builds
def test_what_a_hostile_build_gets(tmp_path, monkeypatch, pystore, other, person, walls):
    """A build that does what a planted one would. It finds no key in its environment, reads nothing of the
    person's own, not the project and not the copy the tests run on, changes neither the tests nor their
    libraries, reaches no address, writes nowhere but in its own folders, and what it left running is ended. What
    an honest build needs works beside all of it, and the tests then run on what was built."""
    for name in PLANTED_NAMES:
        monkeypatch.setenv(name, person.secret)
    _online(monkeypatch, python=pystore)
    mark = "stage2-left-" + os.urandom(6).hex()
    repo = tmp_path / "proj"
    body = HOSTILE
    for word, value in (("KEY", str(person.key)), ("REPO", str(repo)), ("DROP", str(person.drop)), ("MARK", mark),
                        ("STORE", pystore.port), ("OTHER", other.port)):
        body = re.sub(rf"\b{word}\b(?!\")", lambda m, value=value: repr(value), body)
    digest = pystore.put("stage2hostile", *source("stage2hostile", "1.0.0", {}, body=body))
    _project(repo, pystore, "pins", digest, name="stage2hostile", version="1.0.0",
             check="print('SAID ' + json.dumps(stage2hostile.SAID))")
    (repo / ".env").write_text("DATABASE_PASSWORD=" + person.secret + "\n", encoding="utf-8")
    before = _files(repo)
    res = _run(repo)
    assert res["returncode"] == 0, res["output_tail"]
    lines = [line for line in res["output_tail"].splitlines() if line.startswith("SAID ")]
    assert len(lines) == 1, res["output_tail"]
    said = json.loads(lines[0][5:])
    assert said.pop("names") == "got []", said
    got = {k: v for k, v in said.items() if not k.startswith("twin: ") and not v.startswith("refused ")}
    assert not got, got
    assert person.secret not in json.dumps(said)
    twins = {k: v for k, v in said.items() if k.startswith("twin: ")}
    assert len(twins) == 4 and all(v.startswith("got ") for v in twins.values()), twins
    assert twins["twin: a program"] == "got '42'"
    # and the world outside the run: nobody was called, nothing was written, nothing is left running
    assert other.seen == [] and _going(mark) == []
    assert sorted(set(pystore.seen)) == ["/files/stage2hostile-1.0.0.tar.gz", "/files/" + WHEEL,
                                         "/simple/stage2hostile/", "/simple/stage2sample/"]
    assert _files(person.drop) == {"kept.txt"} and _files(repo) == before
    assert "changed" not in (repo / "test_it.py").read_text(encoding="utf-8")
    assert set(_named(res)) == {"stage2hostile", "stage2sample"}


@builds
def test_a_build_that_never_ends_is_ended_and_no_test_is_run(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    monkeypatch.setattr(libraries, "BUILD_SECONDS", 3)
    mark = "stage2-left-" + os.urandom(6).hex()
    body = (f"    import subprocess, sys, time\n    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)', "
            f"{mark!r}])\n    time.sleep(600)")
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=body))
    said, _ = _refused(_project(tmp_path / "proj", pystore, "pins", digest))
    assert "stage2mac 3.0.0" in said and "was not through after" in said, said
    assert _going(mark) == []


@builds
def test_a_build_that_takes_more_memory_than_the_run_has_is_ended(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    body = ("    import time\n    held = bytearray(700 << 20)\n    for at in range(0, len(held), 4096):\n"
            "        held[at] = 1\n    time.sleep(60)\n    return wheel(wheel_directory, sources())")
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=body))
    said, _ = _refused(_project(tmp_path / "proj", pystore, "pins", digest), memory=300)
    assert "stage2mac 3.0.0" in said and "more memory than" in said and "300 MB" in said, said


@builds
def test_a_build_that_fails_is_said_in_lanterns_words(tmp_path, monkeypatch, pystore):
    """The reason is Lantern's sentence, never text of the build; the build's own last lines are in the log."""
    _online(monkeypatch, python=pystore)
    body = "    print('PLANTED-SAID: <b>what the build printed</b>')\n    raise SystemExit('PLANTED-BUILT: no compiler')"
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=body))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "uv.lock", digest))
    assert "stage2mac 3.0.0" in said and "ended with an error" in said and "PLANTED" not in said, said
    assert any("PLANTED-SAID" in line and line.startswith("sandbox: build: ") for line in lines), lines


LEAVES = {
    "a package of another name": ("    return wheel(wheel_directory, sources(), name='stage2other')", "another name or version"),
    "a package of another version": ("    return wheel(wheel_directory, sources(), version='9.9.9')", "another name or version"),
    "a package that says another name inside": ("    return wheel(wheel_directory, sources(), inside='stage2other')",
                                                "another name or version"),
    "two packages": ("    wheel(wheel_directory, sources(), tag='py2-none-any')\n    return wheel(wheel_directory, sources())",
                     "exactly one package"),
    "no package": ("    return 'stage2mac-3.0.0-py3-none-any.whl'", "exactly one package"),
    "a link under the package's name": ("    os.symlink('/etc/hostname', os.path.join(wheel_directory, "
                                        "'stage2mac-3.0.0-py3-none-any.whl'))\n    return 'stage2mac-3.0.0-py3-none-any.whl'",
                                        "exactly one package"),
    "a folder under the package's name": ("    os.mkdir(os.path.join(wheel_directory, 'stage2mac-3.0.0-py3-none-any.whl'))\n"
                                          "    return 'stage2mac-3.0.0-py3-none-any.whl'", "exactly one package"),
}


@builds
@pytest.mark.parametrize("left", sorted(LEAVES))
def test_what_a_build_hands_back_has_to_be_the_one_package_asked_for(tmp_path, monkeypatch, pystore, left):
    _online(monkeypatch, python=pystore)
    body, words = LEAVES[left]
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=body))
    said, _ = _refused(_project(tmp_path / "proj", pystore, "pins", digest))
    assert "stage2mac 3.0.0" in said and words in said, said


# ---------------------------------------------------------------------------- a source package that is not what it should be
def _tar(entries) -> bytes:
    """A .tar.gz of `entries`: (name, text) is a file, (name, None) a folder, (name, (kind, target)) a link
    ("link", "hard") or what is neither file nor folder ("pipe", "device")."""
    kinds = {"link": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE, "pipe": tarfile.FIFOTYPE, "device": tarfile.CHRTYPE}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as t:
        for name, what in entries:
            item = tarfile.TarInfo(name)
            item.mode = 0o644
            if what is None:
                item.type, item.mode = tarfile.DIRTYPE, 0o755
                t.addfile(item)
            elif isinstance(what, tuple):
                item.type, item.linkname = kinds[what[0]], what[1]
                t.addfile(item)
            else:
                data = what.encode()
                item.size = len(data)
                t.addfile(item, io.BytesIO(data))
    return out.getvalue()


TOP = "stage2mac-3.0.0"
WHOLE = [(f"{TOP}/PKG-INFO", "Metadata-Version: 2.1\nName: stage2mac\nVersion: 3.0.0\n"), (f"{TOP}/pyproject.toml", OWN),
         (f"{TOP}/own_backend.py", BACKEND.replace("BODY", HONEST)), (f"{TOP}/stage2mac.py", "N = 3\n")]
ODD = {
    "a link": ([(f"{TOP}/notes.txt", ("link", "/etc/hostname"))], "link"),
    "a link to a file of its own": ([(f"{TOP}/again.py", ("link", "stage2mac.py"))], "link"),
    "a second name for a file": ([(f"{TOP}/again.py", ("hard", f"{TOP}/stage2mac.py"))], "link"),
    "a name that leaves its folder": ([(f"{TOP}/../../../../../../ESCAPED.txt", "x")], "outside"),
    "a name from the top of the disk": ([("/tmp/ESCAPED.txt", "x")], "outside"),
    "a second folder at its top": ([("beside/x.py", "X = 1\n")], "top"),
    "a file at its top": ([("x.py", "X = 1\n")], "top"),
    "a pipe": ([(f"{TOP}/p", ("pipe", ""))], "kind"),
    "a device": ([(f"{TOP}/d", ("device", ""))], "kind"),
}


@pytest.mark.parametrize("odd", sorted(ODD))
def test_what_is_refused_of_a_source_package(tmp_path, odd):
    """Lantern's own unpacking, which runs in the sandbox too: files and folders only, all beneath the one folder
    at the top, and nothing is written for a package that holds anything else."""
    more, why = ODD[odd]
    archive, into = tmp_path / "in.tar.gz", tmp_path / "src"
    archive.write_bytes(_tar(WHOLE + more))
    into.mkdir()
    with pytest.raises(_builder.Refused) as e:
        _builder.unpack(archive, into)
    assert e.value.why == why
    assert not (tmp_path / "ESCAPED.txt").exists() and not Path("/tmp/ESCAPED.txt").exists()
    assert not [p for p in into.rglob("*") if p.is_symlink()]


def test_the_twin_that_holds_files_and_folders_is_unpacked_whole(tmp_path):
    archive, into = tmp_path / "in.tar.gz", tmp_path / "src"
    archive.write_bytes(_tar(WHOLE + [(f"{TOP}/pkg", None), (f"{TOP}/pkg/deep/more.py", "Y = 2\n")]))
    into.mkdir()
    assert _builder.unpack(archive, into) == TOP
    assert _files(into) == {TOP, *(name for name, _ in WHOLE), f"{TOP}/pkg", f"{TOP}/pkg/deep", f"{TOP}/pkg/deep/more.py"}
    assert (into / TOP / "pkg" / "deep" / "more.py").read_text(encoding="utf-8") == "Y = 2\n"


@pytest.mark.parametrize("what, why", [("text that is no archive", "broken"), ("cut short", "broken"),
                                       ("more files than the limit", "count"), ("more bytes than the limit", "size")])
def test_a_source_package_that_is_broken_or_too_large_is_refused(tmp_path, monkeypatch, what, why):
    whole = _tar(WHOLE)
    data = {"text that is no archive": b"<html>not found</html>", "cut short": whole[:len(whole) // 2]}.get(what, whole)
    if what == "more files than the limit":
        monkeypatch.setattr(_builder, "MOST_FILES", 3)
    if what == "more bytes than the limit":       # what it holds when it is unpacked, which is not what it weighs
        data = _tar(WHOLE + [(f"{TOP}/big.py", "#" * 200_000)])
        assert len(data) < 5_000
        monkeypatch.setattr(_builder, "MOST_UNPACKED", 100_000)
    archive, into = tmp_path / "in.tar.gz", tmp_path / "src"
    archive.write_bytes(data)
    into.mkdir()
    with pytest.raises(_builder.Refused) as e:
        _builder.unpack(archive, into)
    assert e.value.why == why


@builds
@pytest.mark.parametrize("odd, words", [("a link", "holds a link"), ("a name that leaves its folder", "leaves its folder"),
                                        ("a second folder at its top", "one folder at its top")])
def test_a_source_package_that_holds_a_link_or_a_way_out_is_not_built(tmp_path, monkeypatch, pystore, odd, words):
    _online(monkeypatch, python=pystore)
    digest = pystore.put("stage2mac", "stage2mac-3.0.0.tar.gz", _tar(WHOLE + ODD[odd][0]))
    said, _ = _refused(_project(tmp_path / "proj", pystore, "uv.lock", digest))
    assert "stage2mac 3.0.0" in said and words in said, said
    assert not (Path(tempfile.gettempdir()) / "ESCAPED.txt").exists()


PLANTED = "    raise SystemExit('PLANTED-BUILT: the source of a library was run')"


@builds
@pytest.mark.parametrize("kind", ["uv.lock", "Pipfile.lock", "hashed"])
def test_a_source_that_is_not_the_one_the_project_names_is_not_built(tmp_path, monkeypatch, pystore, kind):
    """The project names the fingerprint of the source. The store hands out another file under that name: nothing
    of it is unpacked or run."""
    _online(monkeypatch, python=pystore)
    pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=PLANTED))
    said, lines = _refused(_project(tmp_path / "proj", pystore, kind, "cd" * 32))
    assert "stage2mac 3.0.0" in said and "fingerprint" in said and "PLANTED" not in " ".join(lines), (said, lines)
    assert not any("unpack" in line for line in lines), lines


@builds
def test_a_source_that_is_not_the_file_the_stores_page_names_is_not_built(tmp_path, monkeypatch, pystore):
    """With no fingerprint of the project's own, the one the store's page names still has to be the file's."""
    _online(monkeypatch, python=pystore)
    name, data = source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=PLANTED)
    pystore.put("stage2mac", name, data, says="ab" * 32)
    said, lines = _refused(_project(tmp_path / "proj", pystore, "pins", ""))
    assert "stage2mac 3.0.0" in said and "fingerprint" in said and "PLANTED" not in " ".join(lines), (said, lines)


@builds
def test_a_source_package_over_the_size_limit_is_not_taken(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    monkeypatch.setattr(libraries, "MOST_SOURCE", 2000)
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n",
                                                                     "filler.txt": os.urandom(4000).hex()}, body=PLANTED))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "uv.lock", digest))
    assert "stage2mac 3.0.0" in said and "larger than" in said and "PLANTED" not in " ".join(lines), (said, lines)


@builds
def test_a_version_whose_source_the_store_does_not_have_is_said_as_that(tmp_path, monkeypatch, pystore):
    """Ready-built for another system, and no source: there is nothing to build from."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, tag="py3-none-win_amd64")
    said, _ = _refused(_project(tmp_path / "proj", pystore, "pins", ""))
    assert "stage2mac" in said and "3.0.0" in said and "no source package" in said, said


# ---------------------------------------------------------------------------- build tools that are not what they should be
@builds
@pytest.mark.parametrize("asks", ["stage2backend @ http://127.0.0.1:{other}/stage2backend-1.2.0-py3-none-any.whl",
                                  "--index-url http://127.0.0.1:{other}/simple/", "./tools", "stage2backend; import os",
                                  "-r ../../../../requirements.txt"])
def test_the_tools_of_a_build_are_asked_for_by_name_and_of_the_store_only(tmp_path, monkeypatch, pystore, other, asks):
    """What a source package names as its tools is a stranger's text. A link, another store, a folder or anything
    else that is not a library's name with versions is not followed, and nothing of the package is run."""
    _online(monkeypatch, python=pystore)
    _tool(pystore, body=PLANTED)
    pyproject = TOOL.replace('"stage2backend>=1"', json.dumps(asks.format(other=other.port)))
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": pyproject, "stage2mac.py": "N = 3\n"}))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "pins", digest))
    assert "stage2mac 3.0.0" in said and "names a tool" in said and "PLANTED" not in " ".join(lines), (said, lines)
    assert other.seen == [] and "/simple/stage2backend/" not in pystore.seen


@builds
def test_a_build_tool_that_is_there_as_source_only_is_not_built(tmp_path, monkeypatch, pystore):
    """One build, of the library the project names. A tool that would have to be built first is not: the reason
    names it, its source is not asked for, and nothing of it runs."""
    _online(monkeypatch, python=pystore)
    pystore.put("stage2backend", *source("stage2backend", "1.2.0", {"stage2backend.py": "X = 1\n"}, body=PLANTED))
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": TOOL, "stage2mac.py": "N = 3\n"}))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "pins", digest))
    assert "stage2mac 3.0.0" in said and "stage2backend" in said and "ready-built" in said, said
    assert _sources_asked(pystore) == ["/files/stage2mac-3.0.0.tar.gz"] and "PLANTED" not in " ".join(lines)


@builds
@pytest.mark.parametrize("names, words", [
    ('[".."]', "outside its source"), ('["/usr/lib"]', "outside its source"), ('["../../../../app"]', "outside its source"),
    ('"."', "cannot follow"), ('[7]', "cannot follow"),
    ('["."]\nbuild-backend = "os:system"', "cannot follow"),          # TOML takes no key twice
    ('["."]\nrequires = "stage2backend"', "cannot follow"),
])
def test_a_build_whose_own_code_is_named_outside_its_source_is_not_run(tmp_path, monkeypatch, pystore, names, words):
    """`backend-path` names folders of the source that hold the build's own code. One that leads out of the
    source would run whatever lies there. And a table about the build that is not of the shape every tool reads
    is not guessed at."""
    _online(monkeypatch, python=pystore)
    pyproject = OWN.replace('["."]', names)
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=PLANTED,
                                              pyproject=pyproject))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "pins", digest))
    assert "stage2mac 3.0.0" in said and words in said and "PLANTED" not in " ".join(lines), (said, lines)


# ---------------------------------------------------------------------------- more than one
def _two(store: PyStore, folder: Path) -> Path:
    digest = store.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}))
    store.put("stage2two", *source("stage2two", "1.0.0", {"stage2two.py": "N = 2\n"}))
    repo = _project(folder, store, "pins", digest, check="import stage2two\n        self.assertEqual("
                                                         "(stage2mac.N, stage2two.N), (3, 2))")
    with open(repo / "requirements.txt", "a", encoding="utf-8") as f:
        f.write("stage2two==1.0.0\n")
    return repo


@builds
def test_each_library_that_has_to_be_built_is_built(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    res = _run(_two(pystore, tmp_path / "proj"))
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["built"] == 2 and sorted(n for n, p in _named(res).items() if "built" in p) == [
        "stage2mac", "stage2two"]


@builds
def test_no_more_libraries_are_built_than_the_limit(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    monkeypatch.setattr(libraries, "MOST_BUILT", 1)
    said, _ = _refused(_two(pystore, tmp_path / "proj"))
    assert "more than 1" in said and "built" in said, said


@builds
def test_an_optional_library_whose_build_fails_is_left_out_and_the_rest_still_runs(tmp_path, monkeypatch, pystore):
    """Optional libraries that cannot be had are left out (`tests/test_libraries.py`); one whose build fails is
    such a library, and the tests run on what the project always needs."""
    _online(monkeypatch, python=pystore)
    pystore.add("stage2extra", "1.0.0", {"stage2extra.py": "X = 1\n"})
    pystore.put("stage2built", *source("stage2built", "1.0.0", {"stage2built.py": "X = 1\n"}, body=PLANTED))
    text = OPTIONAL.replace('minify = ["stage2extra"]', 'minify = ["stage2extra", "stage2built==1.0.0"]')
    lines: list[str] = []
    res = _run(_pyproject_project(tmp_path / "proj", text, check=NO_EXTRA), lines.append)
    assert res["returncode"] == 0, res["output_tail"]
    assert set(_named(res)) == {"stage2sample"} and "built" not in res["libraries"]
    assert res["libraries"]["optional"]["fetched"] is False and "ended with an error" in res["libraries"]["optional"]["why"]
    assert sum("fetching again without them" in line for line in lines) == 1, lines


# ---------------------------------------------------------------------------- the walls of the build
def _started(monkeypatch) -> list[tuple[dict, list[str]]]:
    """Every program the run starts through the sandbox's launcher: (the launcher's rules, the program's words)."""
    seen: list[tuple[dict, list[str]]] = []
    real = sandbox._stream

    def stream(cmd, *a, **kw):
        if "--" in cmd and len(cmd) > 4 and str(cmd[4]).startswith("{"):
            seen.append((json.loads(cmd[4]), [str(w) for w in cmd[cmd.index("--") + 1:]]))
        return real(cmd, *a, **kw)
    monkeypatch.setattr(sandbox, "_stream", stream)
    return seen


@builds
def test_the_build_runs_behind_the_walls_of_the_tests(tmp_path, monkeypatch, pystore, walls):
    """Each step of a build that looks at the source package or runs its code is started under the rules the
    tests are started under, with no way out. Only the steps that fetch (Lantern's own code and pip) get the
    doorkeeper."""
    _online(monkeypatch, python=pystore)
    _tool(pystore, more="\n\ndef get_requires_for_build_wheel(config_settings=None):\n    return []\n")
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": TOOL, "stage2mac.py": "N = 3\n"}))
    seen = _started(monkeypatch)
    res = _run(_project(tmp_path / "proj", pystore, "pins", digest))
    assert res["returncode"] == 0, res["output_tail"]
    tests = seen[-1][0]
    assert tests["python"] is True and "door" not in tests and "tcp_ports" not in tests
    steps = {}
    for rules, words in seen[:-1]:
        at = next((i for i, w in enumerate(words) if w.endswith("_lantern_builder.py")), None)
        if at is not None:
            steps[words[at + 1]] = rules
    assert set(steps) == {"source", "unpack", "needs", "build"}, sorted(steps)
    for name in ("unpack", "needs", "build"):
        rules = steps[name]
        assert "door" not in rules and "tcp_ports" not in rules, name
        for key in ("net", "own_net", "must", "nobody", "sockets", "shm"):
            assert rules.get(key) == tests.get(key), (name, key, rules.get(key), tests.get(key))
        assert rules["must"] is True and rules["net"] is True and rules["python"] is False
        assert rules["read"] and set(tests["read"]["closed"]) <= set(rules["read"]["closed"]), name
        # what it may write, and what it may read of the run's folder, is neither the tests' copy nor their
        # libraries, their temp folder, their guard or their Python
        run = Path(os.path.realpath(os.path.commonpath(tests["writable"])))
        theirs = [run / n for n in ("app", "tmp", "libs", "hook", "py")]
        of_run = [Path(os.path.realpath(w)) for w in [*rules["writable"], *rules["read"]["open"]]
                  if run in Path(os.path.realpath(w)).parents or Path(os.path.realpath(w)) == run]
        assert of_run and len(of_run) >= len(rules["writable"]), (name, rules)
        for place in of_run:
            assert place != run and not any(place == t or t in place.parents or place in t.parents for t in theirs), place
        assert rules["memory"] == tests["memory"]
    way_out = [name for name, rules in steps.items() if "door" in rules or "tcp_ports" in rules]
    assert way_out in (["source"], []), way_out      # none where a sandbox around this one makes the connections


@builds
def test_nothing_of_a_build_is_left(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    _tool(pystore)
    digest = pystore.put("stage2mac", *sdist("stage2mac", "3.0.0", {"pyproject.toml": TOOL, "stage2mac.py": "N = 3\n"}))
    repo = _project(tmp_path / "proj", pystore, "pins", digest)
    home = Path(os.environ["LANTERN_HOME"])
    site = Path(sysconfig.get_path("purelib"))

    def held():
        return (_files(repo), _files(home) if home.exists() else set(), set(os.listdir(site)),
                {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")})
    before = held()
    res = _run(repo)
    assert res["returncode"] == 0, res["output_tail"]
    assert held() == before
    # and after a build that failed
    pystore.put("stage2two", *source("stage2two", "1.0.0", {}, body=PLANTED))
    (repo / "requirements.txt").write_text("stage2two==1.0.0\n", encoding="utf-8")
    before = held()
    with pytest.raises(sandbox.NoLibraries):
        _run(repo)
    assert held() == before


# ---------------------------------------------------------------------------- where no library is built
def test_where_no_library_is_built_the_reason_says_why(tmp_path, monkeypatch, pystore):
    """On macOS and Windows, inside another sandbox, and on a Linux whose kernel has no rule Lantern can set,
    nothing holds a program that is not Python to the tests' walls, and a build is such a program. There the
    source is not asked for, nothing of it runs, and the reason says that no library is built here, and why."""
    _online(monkeypatch, python=pystore)
    monkeypatch.setattr(sandbox, "held_below_python", lambda: False)
    why = libraries.cannot_build()
    assert why and why == libraries.cannot_build(platforms=())
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=PLANTED))
    said, lines = _refused(_project(tmp_path / "proj", pystore, "uv.lock", digest))
    assert "stage2mac 3.0.0" in said and "as source only" in said, said
    assert "does not build a library here" in said and why in said, said
    assert _sources_asked(pystore) == [] and "PLANTED" not in " ".join(lines)


def test_why_no_library_is_built_here(monkeypatch):
    """One reason at a time, in words for the person; none where every wall of the tests' run stands."""
    container = libraries.cannot_build(platforms=("manylinux_2_36_x86_64",))
    assert "container" in container and "LANTERN_SANDBOX=subprocess" in container
    monkeypatch.setattr(sandbox, "held_below_python", lambda: False)
    assert libraries.cannot_build() and sandbox.not_held_how() in libraries.cannot_build()
    monkeypatch.setattr(sandbox, "held_below_python", lambda: True)
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 0)
    assert "folders" in libraries.cannot_build()
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 7)
    assert bool(libraries.cannot_build()) is not LINUX       # with every wall of the tests' run: Linux, and no other system


@only_posix
def test_nothing_is_built_for_a_container(tmp_path, monkeypatch, pystore):
    """Where the tests run in a container, a library would have to be built in one too, for the container's
    system. That is not done yet: the reason says so and how the tests can be run on this computer."""
    _online(monkeypatch, python=pystore)
    _stand_in_docker(tmp_path, monkeypatch)
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}, body=PLANTED))
    repo = _project(tmp_path / "proj", pystore, "uv.lock", digest)
    (repo / "test_it.py").write_text("raise SystemExit('PLANTED-RAN: a test file was run')\n", encoding="utf-8")
    lines: list[str] = []
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, UNITTEST, log=lines.append, backend="docker")
    said = str(e.value)
    assert "does not build a library here" in said and "container" in said and "LANTERN_SANDBOX=subprocess" in said, said
    assert _sources_asked(pystore) == [] and "PLANTED" not in " ".join(lines)


# ---------------------------------------------------------------------------- which file is the source
PAGE = '''<!DOCTYPE html><html><body>
<a href="/files/stage2_mac-3.0.0-py3-none-win_amd64.whl#sha256={a}">stage2_mac-3.0.0-py3-none-win_amd64.whl</a>
<a href="https://files.example.invalid/packages/aa/bb/stage2-mac-2.0.0.tar.gz#sha256={b}">stage2-mac-2.0.0.tar.gz</a>
<a data-requires-python="&gt;=3.8" href="../../files/Stage2_Mac-3.0.0.tar.gz#sha256={c}" >Stage2_Mac-3.0.0.tar.gz</a><br/>
<a href="/files/stage2_mac-3.0.0.post1.tar.gz#sha256={d}">stage2_mac-3.0.0.post1.tar.gz</a>
<a href="/files/stage2_mac_extra-3.0.0.tar.gz#sha256={e}">stage2_mac_extra-3.0.0.tar.gz</a>
<a href="/files/stage2_mac-3.0.0.zip#sha256={d}">stage2_mac-3.0.0.zip</a>
<a href='/files/stage2_mac-4.0.0.tar.gz'>stage2_mac-4.0.0.tar.gz</a>
</body></html>'''.format(a="a" * 64, b="b" * 64, c="c" * 64, d="d" * 64, e="e" * 64)


@pytest.mark.parametrize("name, version, found", [
    ("stage2-mac", "3.0.0", ("../../files/Stage2_Mac-3.0.0.tar.gz", "c" * 64)),
    ("Stage2.Mac", "3.0.0", ("../../files/Stage2_Mac-3.0.0.tar.gz", "c" * 64)),
    ("stage2_mac", "2.0.0", ("https://files.example.invalid/packages/aa/bb/stage2-mac-2.0.0.tar.gz", "b" * 64)),
    ("stage2-mac", "3.0.0.post1", ("/files/stage2_mac-3.0.0.post1.tar.gz", "d" * 64)),
    ("stage2-mac", "4.0.0", ("/files/stage2_mac-4.0.0.tar.gz", "")),       # the page names no fingerprint for it
    ("stage2-mac-extra", "3.0.0", ("/files/stage2_mac_extra-3.0.0.tar.gz", "e" * 64)),
    ("stage2-mac", "3.0", None), ("stage2-mac", "3.0.0.post2", None), ("stage2-mac", "5.0.0", None),
    ("stage2", "3.0.0", None), ("stage2-mac-extra", "4.0.0", None), ("mac", "3.0.0", None),
])
def test_which_file_of_a_stores_page_is_the_source_of_a_version(name, version, found):
    """The source package of exactly that version, by the name a store gives it (`<name>-<version>.tar.gz`, the
    name written any way a store may write it), with the fingerprint the page names for it. Not a ready-built
    file, not another version, not another library whose name begins the same, not a `.zip`."""
    assert _builder.pick(PAGE, name, version) == found


def test_a_page_that_is_no_page_names_no_source():
    for page in ("", "<a href=", "\x00\xff" * 50, "<a href='/files/stage2mac-3.0.0.tar.gz'>" * 3 + "<" * 100_000):
        assert _builder.pick(page, "stage2mac", "3.0.0") in (None, ("/files/stage2mac-3.0.0.tar.gz", ""))


# ---------------------------------------------------------------------------- the record of a whole check
@builds
def test_the_evidence_says_which_library_was_built(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    digest = pystore.put("stage2mac", *source("stage2mac", "3.0.0", {"stage2mac.py": "N = 3\n"}))
    repo = _project(tmp_path / "proj", pystore, "uv.lock", digest)
    run, release, _ = _check(repo, UNITTEST)
    assert run["returncode"] == 0 and run["libraries"]["built"] == 1
    assert next(c for c in release["criteria"] if c["id"] == "tests")["state"] == "passed"
    ev = json.loads((repo / ".lantern" / "evidence.json").read_text(encoding="utf-8"))
    libs = ev["provenance"]["libraries"]
    built = next(p for p in libs["packages"] if p["name"] == "stage2mac")
    assert libs["built"] == 1 and built["built_from"] == "sha256:" + digest and built["checked"] is True
    assert "built_from" not in next(p for p in libs["packages"] if p["name"] == "stage2sample")
    limit = [line for line in ev["limits"] if "built" in line and "stage2mac" in line]
    assert len(limit) == 1 and "source" in limit[0], ev["limits"]
    page = (repo / ".lantern" / "evidence.html").read_text(encoding="utf-8")
    assert digest in page and "built" in page


def _record(packages) -> dict:
    return {"ran": True, "command": ["x"], "returncode": 0, "libraries": {
        "state": "fetched", "language": "python", "store": "pypi.org", "exact": True, "checked": 0, "built": 1,
        "packages": packages}}


def test_a_built_library_is_a_limit_of_the_report_and_its_twin_is_none():
    print_of = "sha256:" + hashlib.sha256(b"x").hexdigest()
    ready = {"name": "stage2sample", "version": "1.0.0", "fingerprint": "sha256:" + "ab" * 32, "file": WHEEL,
             "asked": True, "exact": True, "checked": False}
    built = {**ready, "name": "stage2mac", "version": "3.0.0", "built": {
        "from": "stage2mac-3.0.0.tar.gz", "source_fingerprint": print_of, "with": ["setuptools 99.0.0"]}}
    got = evidence.libraries_shown(_record([ready, built]))
    assert got["built"] == 1 and [p.get("built_from") for p in got["packages"]] == [None, print_of]
    lines = evidence.libraries_limits(got)
    assert len(lines) == 1 and "stage2mac" in lines[0] and "built" in lines[0] and "stage2sample" not in lines[0]
    twin = evidence.libraries_shown(_record([ready]))
    assert "built" not in twin and evidence.libraries_limits(twin) == []


@pytest.mark.parametrize("planted", ["<b>x</b>", ["sha256:" + "ab" * 32], {"source_fingerprint": "<script>x</script>"},
                                     {"source_fingerprint": "sha256:" + "z" * 64}, {"from": "x"}, 7, True])
def test_what_a_record_read_back_says_of_a_build_is_taken_by_its_shape(planted):
    """`run.json` lies in the project's own results folder and may have come with the project."""
    got = evidence.libraries_shown(_record([{"name": "stage2mac", "version": "3.0.0", "fingerprint": "sha256:" + "ab" * 32,
                                             "exact": True, "checked": True, "built": planted}]))
    assert "<" not in json.dumps(got) and len(json.dumps(got)) < 600
    assert got["packages"][0].get("built_from", "") == "" and "built" not in got
