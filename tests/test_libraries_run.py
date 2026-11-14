"""The tests run on exactly the libraries fetched for them, with the network off (a firm pass or fail, stage 2).

"Exactly" has to hold for everything the tests start, not only for the Python Lantern starts. A test that starts a
second Python, with the environment it was handed, with one of its own making or with Python's isolated mode, has
that Python find the project's libraries at home, because there they are installed in the Python itself. Here
they were found through the tests' environment alone: a second Python that was handed another environment ran on
whatever is installed beside Lantern, and the record named libraries it had not run on. A fetched library's own
command-line program was not found by its name either.

So the tests get a Python of the run's own (`sandbox._own_python`): this computer's Python under another name, in
a folder of the run where the only libraries are the fetched ones. For JavaScript the packages are in the copy
the tests run in, as at home; a folder of packages that lies above the run's folder, which Node would look in
too, is said.

No test here reaches the internet: the stores are stand-ins on this computer (`tests/stores.py`)."""
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest
from stores import NpmStore, PyStore
from test_libraries import UNITTEST, _js_project, _online, _py_project, needs_npm

from lantern import programs, sandbox

QUIET = lambda line: None       # noqa: E731
posix = pytest.mark.skipif(os.name != "posix", reason="needs POSIX (how a program names the Python that runs it)")


@pytest.fixture()
def pystore():
    """A library, and one that brings a command-line program of its own."""
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        store.add("stage2tool", "1.0.0", {
            "stage2tool/__init__.py": "import stage2sample\n\n\ndef main():\n    print('the tool says', stage2sample.answer())\n",
            "stage2tool-1.0.0.dist-info/entry_points.txt": "[console_scripts]\nstage2tool = stage2tool:main\n"},
            requires=("stage2sample",))
        yield store


@pytest.fixture()
def npmstore():
    with NpmStore() as store:
        yield store


@pytest.fixture()
def open_folder():
    """A folder every user may enter, for a temp folder of the test's own: pytest's are their owner's alone, and
    where Lantern is root the tests run as another user."""
    folder = Path(tempfile.mkdtemp(prefix="lantern-test-above-"))
    os.chmod(folder, 0o755)
    try:
        yield folder
    finally:
        assert sandbox._rm(folder) is True


# What a second Python says of itself: does it find the fetched library, and is a library that is installed
# beside Lantern, and that the project does not name, out of its reach?
SEES = ("import importlib.util as u; "
        "print(u.find_spec('stage2sample') is not None, u.find_spec('pytest') is None)")
OWN_ENV = "{k: os.environ[k] for k in ('PATH', 'SYSTEMROOT') if k in os.environ}"
SECOND = {
    "handed the tests' environment": "[sys.executable, '-c', SEES]",
    "handed an environment the test made": f"[sys.executable, '-c', SEES], env={OWN_ENV}",
    "in isolated mode": "[sys.executable, '-I', '-c', SEES]",
    "told to pass its environment over": "[sys.executable, '-E', '-c', SEES]",
    "started by the name python": f"['python', '-c', SEES], env={OWN_ENV}",
    "started in another folder": "[sys.executable, '-c', SEES], cwd=tempfile.gettempdir()",
}


def _starts(folder: Path, how: str) -> Path:
    repo = _py_project(folder)
    (repo / "test_it.py").write_text(
        "import os\nimport subprocess\nimport sys\nimport tempfile\nimport unittest\n\n"
        f"SEES = {SEES!r}\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        got = subprocess.run({how}, capture_output=True, text=True)\n"
        "        self.assertEqual(got.stdout.strip(), 'True True', got.stderr)\n", encoding="utf-8")
    return repo


def test_what_the_cases_below_stand_on():
    """`pytest` is installed beside Lantern, and the project names only `stage2sample`."""
    assert importlib.util.find_spec("pytest") is not None and importlib.util.find_spec("stage2sample") is None
    assert programs.find("stage2tool") is None


@pytest.mark.parametrize("how", list(SECOND))
def test_a_python_the_tests_start_themselves_runs_on_the_fetched_libraries_too(tmp_path, monkeypatch, pystore, how):
    """On Windows one of these ways leads to the computer's own Python, and the run's log says which (found on
    GitHub's Windows machine, 2026-11-14, not fixed: `sandbox._own_python_words`). This test says so on Windows
    itself, so that the day it is fixed there this line fails and is taken out."""
    _online(monkeypatch, python=pystore)
    lines: list[str] = []
    res = sandbox.run(_starts(tmp_path / "proj", SECOND[how]), UNITTEST, log=lines.append, backend="subprocess")
    assert res["libraries"]["state"] == "fetched"
    assert any("started by a Python of the run's own" in line for line in lines), lines
    if sys.platform == "win32":
        assert any("by the bare name `python`" in line and "the computer's own Python" in line for line in lines), lines
        if how == "started by the name python":
            assert res["returncode"] == 1 and "!= 'True True'" in res["output_tail"], res["output_tail"]
            return
    assert res["returncode"] == 0, res["output_tail"]


def test_where_no_python_of_the_runs_own_can_be_made_the_guard_still_keeps_to_the_fetched_libraries(
        tmp_path, monkeypatch, pystore):
    """The older way stays as the second net: the guard takes this computer's libraries off the path of every
    Python that is handed the tests' environment, and the log says which way it is."""
    import venv
    _online(monkeypatch, python=pystore)

    def refuse(self, folder):
        raise OSError(28, "no room")
    monkeypatch.setattr(venv.EnvBuilder, "create", refuse)
    lines: list[str] = []
    res = sandbox.run(_starts(tmp_path / "proj", SECOND["handed the tests' environment"]), UNITTEST, log=lines.append,
                      backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert not any("started by a Python of the run's own" in line for line in lines)
    assert any("could not be made" in line and "another environment" in line for line in lines), lines


def test_the_python_of_the_runs_own_is_not_the_tests_to_change(tmp_path, monkeypatch, pystore):
    """Where its libraries come from is written in a file of the run's own Python. A test that could change that
    file would choose the libraries of every Python started after it."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj")
    (repo / "test_it.py").write_text(
        "import os\nimport sys\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        "        self.assertNotEqual(sys.prefix, sys.base_prefix)\n"
        "        for folder, names, files in os.walk(sys.prefix):\n"
        "            for name in files:\n"
        "                if name.endswith('.pth'):\n"
        "                    with self.assertRaises(OSError):\n"
        "                        open(os.path.join(folder, name), 'a').close()\n"
        "        with self.assertRaises(OSError):\n"
        "            open(os.path.join(sys.prefix, 'pyvenv.cfg'), 'a').close()\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]


def test_a_project_file_named_like_the_recorder_is_not_run_in_its_place(tmp_path, monkeypatch, pystore):
    """`python -m` looks in the current folder first, and the tests' current folder is the project's copy: a
    file there with the recorder's name ran instead of it, no test was run, and the run ended as tests that
    passed."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", check="self.assertEqual(stage2sample.answer(), 41)")
    (repo / "_lantern_tracer.py").write_text("print('the project ran this in place of the recorder')\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert "in place of the recorder" not in res["output_tail"]
    assert res["returncode"] == 1 and "42 != 41" in res["output_tail"]


def test_a_project_folder_named_lantern_is_not_taken_for_lanterns_own(tmp_path, monkeypatch):
    """The same for a project that names no library, whose tests are started through Lantern's recorder by its
    own name: a project with a folder named `lantern` (Lantern's own code, a fork of it, or anybody's project
    of that name) had its file run in place of the recorder."""
    monkeypatch.delenv("LANTERN_OFFLINE", raising=False)
    repo = tmp_path / "proj"
    (repo / "lantern").mkdir(parents=True)
    (repo / "lantern" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "lantern" / "tracehook.py").write_text("print('the project ran this in place of the recorder')\n",
                                                   encoding="utf-8")
    (repo / "test_it.py").write_text(
        "import unittest\n\nimport lantern\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        "        self.assertFalse(hasattr(lantern, 'sandbox'), 'the tests see the project folder of that name')\n"
        "        self.assertEqual(1, 2)\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert "in place of the recorder" not in res["output_tail"]
    assert res["returncode"] == 1 and "1 != 2" in res["output_tail"], res["output_tail"]


def test_a_module_beside_the_tests_is_still_found(tmp_path, monkeypatch, pystore):
    """The twin: the folder the tests are started in is on their path, as `python -m` has it at home."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj")
    (repo / "tests").mkdir()
    (repo / "tests" / "helper_beside.py").write_text("VALUE = 42\n", encoding="utf-8")
    (repo / "tests" / "test_it.py").write_text(
        "import os\nimport sys\nimport unittest\n\nimport helper_beside\nimport stage2sample\n\n\n"
        "class T(unittest.TestCase):\n    def test_it(self):\n"
        "        self.assertEqual(stage2sample.answer(), helper_beside.VALUE)\n"
        "        self.assertEqual(os.path.realpath(sys.path[1]), os.path.realpath(os.getcwd()))\n", encoding="utf-8")
    (repo / "test_it.py").unlink()
    res = sandbox.run(repo, ["python", "-m", "unittest", "discover", "-s", "tests", "-v"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]


# ---------------------------------------------------------------------------- the project's own code, not in its top folder
FINDS = ("import json\nimport os\nimport unittest\n\nimport inner\n\n\nclass T(unittest.TestCase):\n"
         "    def test_it(self):\n"
         "        self.assertEqual(inner.VALUE, 42)\n"
         "        self.assertTrue(hasattr(json, 'dumps'), 'a file of the project stood in for a part of Python')\n"
         "        print('FOUND ' + os.path.realpath(inner.__file__))\n")


def _kept_in(repo: Path, folder: str, needs: str = "") -> Path:
    """A project whose own code is in `folder`, beside a file there that is named like a part of Python."""
    (repo / folder / "inner").mkdir(parents=True)
    (repo / folder / "inner" / "__init__.py").write_text("VALUE = 42\n", encoding="utf-8")
    (repo / folder / "json.py").write_text("raise SystemExit('a file of the project stood in for a part of Python')\n",
                                           encoding="utf-8")
    if needs:
        (repo / "requirements.txt").write_text(needs, encoding="utf-8")
    (repo / "test_it.py").write_text(FINDS, encoding="utf-8")
    return repo


def _found(res, repo: Path) -> None:
    assert res["returncode"] == 0, res["output_tail"]
    found = [line[6:] for line in res["output_tail"].splitlines() if line.startswith("FOUND ")]
    assert len(found) == 1 and not found[0].startswith(os.path.realpath(repo) + os.sep), found      # the copy's


@pytest.mark.parametrize("needs", ["", "stage2sample==1.0.0\n", "stage2sample==1.0.0\n#\n"],
                         ids=["no library named", "libraries fetched", "libraries fetched, the guard alone"])
def test_code_a_project_keeps_in_src_is_found_in_the_copy(tmp_path, monkeypatch, pystore, needs):
    """At home such a project is installed for editing in place, which puts its own `src` at the end of
    Python's path: the project's folder, not the copy, and a folder the tests can no longer read where the
    person's own folders are closed to them. A run has the copy's `src` there, at the end as well: a file in it
    that is named like a part of Python's own library does not stand in for that part."""
    import venv
    _online(monkeypatch, python=pystore)
    if needs.endswith("#\n"):          # where no Python of the run's own can be made
        monkeypatch.setattr(venv.EnvBuilder, "create", lambda self, folder: (_ for _ in ()).throw(OSError(28, "no room")))
    repo = _kept_in(tmp_path / "proj", "src", needs)
    _found(sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess"), repo)


@pytest.mark.parametrize("own", [True, False], ids=["a Python of the run's own", "the guard alone"])
def test_a_fetched_library_does_not_stand_in_for_a_part_of_python(tmp_path, monkeypatch, pystore, own):
    """A library may bring a module named like one of Python's own (old back-ports do: `typing`, `asyncio`,
    `dataclasses`). At home it is installed behind Python's own library and is never loaded; in a run the
    fetched libraries stood in front of it, and tests that pass at home ended with an error."""
    import venv
    pystore.add("stage2backport", "1.0.0", {
        "stage2backport/__init__.py": "VALUE = 42\n",
        "json.py": "raise SystemExit('a fetched library stood in for a part of Python')\n"})
    _online(monkeypatch, python=pystore)
    if not own:
        def refuse(self, folder):
            raise OSError(28, "no room")
        monkeypatch.setattr(venv.EnvBuilder, "create", refuse)
    repo = _py_project(tmp_path / "proj", needs="stage2sample==1.0.0\nstage2backport==1.0.0\n",
                       check="self.assertEqual((__import__('stage2backport').VALUE, hasattr(__import__('json'), 'dumps')), (42, True))")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert res["libraries"]["state"] == "fetched"


def test_a_folder_of_the_project_that_this_python_has_on_its_path_is_the_copys_in_a_run(tmp_path, monkeypatch):
    """The same for a folder of any other name: this Python was told to look in the project's `lib` (as an
    install for editing in place tells it), so the tests look in the copy's `lib`."""
    monkeypatch.delenv("LANTERN_OFFLINE", raising=False)
    repo = _kept_in(tmp_path / "proj", "lib")
    monkeypatch.setattr(sys, "path", [*sys.path, str(repo / "lib")])
    _found(sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess"), repo)


def test_a_folder_this_python_was_not_told_about_is_not_on_the_tests_path(tmp_path, monkeypatch):
    """The twin: a folder of the project that nothing put on Python's path is not looked in (only `src` is, by
    its name), so the same project fails here as it would at home."""
    monkeypatch.delenv("LANTERN_OFFLINE", raising=False)
    repo = _kept_in(tmp_path / "proj", "lib")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 1 and "No module named 'inner'" in res["output_tail"], res["output_tail"]


def test_nothing_of_the_runs_own_python_is_left(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    before = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")}
    res = sandbox.run(_py_project(tmp_path / "proj"), UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("lantern-")} == before


# ---------------------------------------------------------------------------- a library's own program
@posix
@pytest.mark.parametrize("env", ["", f", env={OWN_ENV}"], ids=["the tests' environment", "an environment the test made"])
def test_a_fetched_librarys_own_program_is_found_by_its_name_and_runs_on_the_fetched_libraries(
        tmp_path, monkeypatch, pystore, env):
    """`subprocess.run(["flask", ...])`, as tests of a command-line tool do: the program a library brings is found
    by its name, and it is run by the Python of the run's own, whatever environment the test hands it."""
    _online(monkeypatch, python=pystore)
    repo = _py_project(tmp_path / "proj", needs="stage2tool==1.0.0\n")
    (repo / "test_it.py").write_text(
        "import os\nimport subprocess\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
        f"        got = subprocess.run(['stage2tool'], capture_output=True, text=True{env})\n"
        "        self.assertEqual(got.stdout.strip(), 'the tool says 42', got.stderr)\n", encoding="utf-8")
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]


@posix
def test_a_program_file_that_is_a_link_or_names_another_python_is_left_as_it_is(tmp_path):
    """Only the line pip wrote is rewritten: the full path of the Python that fetched. A link is not followed and
    a file that starts another way is not touched."""
    libs, outside = tmp_path / "libs", tmp_path / "outside.txt"
    (libs / "bin").mkdir(parents=True)
    outside.write_text(f"#!{sys.executable}\nkept\n", encoding="utf-8")
    (libs / "bin" / "linked").symlink_to(outside)
    (libs / "bin" / "shell").write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    (libs / "bin" / "ours").write_text(f"#!{sys.executable}\nprint(1)\n", encoding="utf-8")
    (libs / "bin" / "nearly").write_text(f"#!{sys.executable}-other\nprint(1)\n", encoding="utf-8")
    sandbox._programs_run_by(libs, "/the/run's/python")
    assert outside.read_text(encoding="utf-8") == f"#!{sys.executable}\nkept\n"
    assert (libs / "bin" / "linked").is_symlink()
    assert (libs / "bin" / "shell").read_text(encoding="utf-8") == "#!/bin/sh\necho hello\n"
    assert (libs / "bin" / "nearly").read_text(encoding="utf-8") == f"#!{sys.executable}-other\nprint(1)\n"
    assert (libs / "bin" / "ours").read_text(encoding="utf-8") == "#!/the/run's/python\nprint(1)\n"


# ---------------------------------------------------------------------------- JavaScript
@needs_npm
def test_javascript_tests_reach_neither_the_doorkeeper_nor_the_store_or_the_run_says_they_are_not_held(
        tmp_path, monkeypatch, npmstore):
    """The way out was the fetch's alone, for a program that is not Python too, wherever something below Python
    holds such a program (`sandbox.held_below_python`: Linux, in a network of the run's own, behind its doorman
    or under the kernel's rule). Where nothing does (Windows and macOS; a run inside a run, where the sandbox
    around it decides), the run says so and does not say the network is off. Until 2026-11-14 this test asked
    for a closed network everywhere: on GitHub's Windows machine the test reached the store's stand-in, and the
    sheet still said "nothing on this computer is let through"."""
    _online(monkeypatch, npm=npmstore)
    repo = _js_project(tmp_path / "proj", npmstore)
    (repo / "test.js").write_text(
        "const net = require('net');\nrequire('stage2-sample');\nlet left = 2;\n"
        f"for (const port of [8118, {npmstore.port}]) {{\n"
        "  const s = net.connect(port, '127.0.0.1');\n"
        "  s.setTimeout(5000, () => s.destroy(new Error('no answer')));\n"
        "  s.on('connect', () => { console.error('reached ' + port); process.exit(1); });\n"
        "  s.on('error', () => { if (--left === 0) { console.log('ok'); } });\n}\n", encoding="utf-8")
    asked = len(npmstore.seen)
    lines: list[str] = []
    res = sandbox.run(repo, ["npm", "test"], log=lines.append, backend="subprocess")
    assert res["libraries"]["state"] == "fetched"
    if not sandbox.held_below_python():
        assert any("These tests are not Python" in line and "not kept from the network" in line for line in lines), lines
        assert not any("nothing on this computer is let through" in line for line in lines), lines
        return
    assert res["returncode"] == 0, res["output_tail"]
    assert not any("not kept from the network" in line for line in lines), lines
    assert all("stage2-sample" in path for path in npmstore.seen[asked:]), npmstore.seen      # the fetch's own questions


@needs_npm
def test_javascript_tests_are_not_handed_a_folder_of_packages_through_the_environment(tmp_path, monkeypatch, npmstore):
    """NODE_PATH names folders Node looks for packages in: the person's own is not the tests'."""
    _online(monkeypatch, npm=npmstore)
    stray = tmp_path / "global"
    (stray / "stray-package").mkdir(parents=True)
    (stray / "stray-package" / "index.js").write_text("exports.x = 1;\n", encoding="utf-8")
    monkeypatch.setenv("NODE_PATH", str(stray))
    repo = _js_project(tmp_path / "proj", npmstore)
    (repo / "test.js").write_text(
        "require('stage2-sample');\nlet found = true;\ntry { require('stray-package'); } catch (e) { found = false; }\n"
        "if (found || process.env.NODE_PATH) { console.error('a package nobody named'); process.exit(1); }\n",
        encoding="utf-8")
    res = sandbox.run(repo, ["npm", "test"], log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]


@needs_npm
@pytest.mark.parametrize("stray", [True, False], ids=["a folder of packages above", "none above"])
def test_a_folder_of_packages_above_the_runs_folder_is_said(tmp_path, monkeypatch, npmstore, open_folder, stray):
    """Node looks for a package in `node_modules` of every folder above the one it runs in, up to the top. One
    that lies above the folder Lantern makes for a run (a stray `npm install` in the home folder, with the temp
    folder beneath it) is in reach of the tests, and Lantern cannot take it out of Node's way: the record says how
    many there are."""
    _online(monkeypatch, npm=npmstore)
    temp = open_folder / "home" / "temp"
    temp.mkdir(parents=True)
    if stray:
        (open_folder / "home" / "node_modules" / "stray-package").mkdir(parents=True)
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    lines: list[str] = []
    res = sandbox.run(_js_project(tmp_path / "proj", npmstore), ["npm", "test"], log=lines.append, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    libs = res["libraries"]
    assert libs["state"] == "fetched"
    assert libs.get("above", 0) == (1 if stray else 0)
    assert libs["exact"] is True                        # the versions are the lock file's either way
    assert any("above the folder the tests run in" in line for line in lines) is stray
    assert str(open_folder) not in json.dumps(libs)     # the record says that there is one, never where


def test_the_evidence_says_a_folder_of_packages_was_in_reach():
    from lantern import evidence
    record = {"state": "fetched", "language": "node", "store": "registry.npmjs.org", "exact": False, "checked": 1,
              "above": 2, "packages": [{"name": "left-pad", "version": "1.3.0", "fingerprint": "sha512-" + "A" * 86 + "==",
                                        "exact": True, "checked": True}]}
    clean = evidence.libraries_clean(record)
    assert clean["above"] == 2
    said = " ".join(evidence.libraries_limits(clean))
    assert "above the folder the tests ran in" in said and "Node" in said
    assert evidence.libraries_clean({**record, "above": "<script>"}).get("above") in (None, 0)
    assert not any("above the folder" in line for line in evidence.libraries_limits(evidence.libraries_clean(
        {**record, "above": 0, "exact": True})))
