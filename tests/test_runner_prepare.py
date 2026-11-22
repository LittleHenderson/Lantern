"""The website's side of a check's tests (a firm pass or fail, stage 3, step 5, part (c)).

The website never runs a project's tests itself. For a check that asks for them it fetches the libraries the project
names, ready-built for the test machine (Linux, Python 3.12) and for nothing else, and packs them with the project
into the archive the machine takes (`runner.prepare`, a step of the check's own user). The machine's result comes back
and is read by its shape into the report (`runner.handed`, through `LANTERN_TESTS_FROM`, in a check of the website
only). Where the tests could not run there, the report says so in Lantern's own words, and the release decision is
Incomplete.

Each refusal stands beside an honest twin. No test here reaches the internet: the stores are stand-ins on this
computer (`tests/stores.py`)."""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path

import pytest
from stores import NpmStore, PyStore
from test_libraries import UNITTEST, _js_project, _online, _py_project, needs_npm

from lantern import cli, pipeline, runner, sandbox, trace

QUIET = lambda line: None       # noqa: E731
linux = pytest.mark.skipif(not sys.platform.startswith("linux"),
                           reason="the website that prepares a check's tests runs on Linux")
ARCH = platform.machine()
NATIVE = {"stage2native/__init__.py": "KIND = 'native'\n"}


@pytest.fixture()
def pystore():
    with PyStore() as store:
        store.add("stage2sample", "1.0.0", {"stage2sample/__init__.py": "def answer():\n    return 42\n"})
        yield store


def _prepare(project: Path, out: Path, words=UNITTEST, **kw):
    lines: list[str] = []
    said = runner.prepare(project, out, words, log=lines.append, **{"minutes": 3, "memory": 512, **kw})
    return said, lines


def _packed(out: Path, work: Path) -> dict:
    return runner.take(out / runner.ARCHIVE, work)


# ---------------------------------------------------------------------------- the libraries, fetched for the machine
@linux
def test_the_libraries_are_fetched_for_the_machine_and_packed_with_the_project(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    project = _py_project(tmp_path / "p")
    said, _ = _prepare(project, tmp_path / "pack")
    assert said["state"] == "packed", said
    assert said == runner.prepared((tmp_path / "pack" / runner.PREPARED).read_bytes())
    assert (said["libraries"], said["language"], said["command"], said["cwd"]) == (1, "python", UNITTEST, "")
    taken = _packed(tmp_path / "pack", tmp_path / "work")
    s = taken["settings"]
    assert (s["command"], s["minutes"], s["memory"], s["cwd"]) == (UNITTEST, 3, 512, "")
    assert s["libraries"]["state"] == "fetched" and s["fetched_with"] == sys.executable
    assert [(p["name"], p["version"], p["exact"]) for p in s["libraries"]["packages"]] == [("stage2sample", "1.0.0", True)]
    assert (taken["libraries"] / "stage2sample" / "__init__.py").is_file()
    assert (taken["project"] / "test_it.py").is_file() and (taken["project"] / "requirements.txt").is_file()
    # nothing of the fetch is left beside the archive and its record
    assert sorted(p.name for p in (tmp_path / "pack").iterdir()) == sorted([runner.ARCHIVE, runner.PREPARED])


@linux
def test_the_package_taken_is_the_one_built_for_the_machine_and_not_for_this_computer(tmp_path, monkeypatch):
    with PyStore() as store:
        store.add("stage2native", "1.0.0", NATIVE, tag=f"cp313-cp313-manylinux_2_17_{ARCH}")     # another Python
        store.add("stage2native", "1.0.0", NATIVE, tag=f"py3-none-manylinux_2_99_{ARCH}")        # a newer system
        machines = store.add("stage2native", "1.0.0", NATIVE, tag=f"cp312-cp312-manylinux_2_36_{ARCH}")
        _online(monkeypatch, python=store)
        project = _py_project(tmp_path / "p", needs="stage2native==1.0.0\n")
        said, _ = _prepare(project, tmp_path / "pack")
    assert said["state"] == "packed", said
    row = _packed(tmp_path / "pack", tmp_path / "work")["settings"]["libraries"]["packages"][0]
    assert row["file"] == f"stage2native-1.0.0-cp312-cp312-manylinux_2_36_{ARCH}.whl"
    assert row["fingerprint"] == "sha256:" + machines


@linux
def test_a_library_with_no_package_for_the_machine_is_not_built_and_no_test_is_run(tmp_path, monkeypatch):
    with PyStore() as store:
        store.add("stage2native", "1.0.0", NATIVE, tag=f"cp313-cp313-manylinux_2_17_{ARCH}")
        store.add("stage2native", "1.0.0", NATIVE, tag=f"py3-none-manylinux_2_99_{ARCH}")
        store.add("stage2native", "1.0.0", NATIVE, source=True)      # a build could start from this
        _online(monkeypatch, python=store)
        project = _py_project(tmp_path / "p", needs="stage2native==1.0.0\n")
        said, lines = _prepare(project, tmp_path / "pack")
    assert said["state"] == "not_run" and said["kind"] == "libraries", said
    assert "stage2native" in said["why_not"] and runner.MACHINE_WORDS in said["why_not"]
    assert runner.NO_BUILD in said["why_not"]
    assert not any("from its source" in line for line in lines)        # nothing was built
    assert not (tmp_path / "pack" / runner.ARCHIVE).exists()
    assert said == runner.prepared((tmp_path / "pack" / runner.PREPARED).read_bytes())


@linux
def test_a_project_that_names_no_library_gets_the_test_runner_its_command_needs(tmp_path, monkeypatch):
    with PyStore() as store:
        store.add("pytest", "8.3.0", {"pytest/__init__.py": "", "pytest/__main__.py": "raise SystemExit(0)\n"})
        _online(monkeypatch, python=store)
        project = tmp_path / "p"
        project.mkdir()
        (project / "test_it.py").write_text("def test_it():\n    assert True\n", encoding="utf-8")
        said, _ = _prepare(project, tmp_path / "pack", ["python", "-m", "pytest", "-q"])
        assert said["state"] == "packed", said
        lib = _packed(tmp_path / "pack", tmp_path / "work")["settings"]["libraries"]
        assert lib["state"] == "fetched" and lib["added"] == ["pytest"]
        assert [p["name"] for p in lib["packages"]] == ["pytest"]
        # the twin: unittest is Python's own, so nothing is fetched for it
        seen = len(store.seen)
        said, _ = _prepare(project, tmp_path / "pack2")
        assert said["state"] == "packed" and said["libraries"] == 0, said
        assert _packed(tmp_path / "pack2", tmp_path / "work2")["settings"]["libraries"] == \
            {"state": "none", "language": "python"}
        assert len(store.seen) == seen


@pytest.mark.parametrize("words", [["python", "app.py"], ["pnpm", "test"], ["go", "test", "./..."],
                                   ["cargo", "test"]], ids=["no test runner", "pnpm", "go", "rust"])
def test_a_command_the_machine_does_not_run_fetches_nothing(tmp_path, monkeypatch, pystore, words):
    _online(monkeypatch, python=pystore)
    project = _py_project(tmp_path / "p")
    said, _ = _prepare(project, tmp_path / "pack", words)
    assert said["state"] == "not_run" and said["kind"] == "machine" and said["why_not"], said
    assert pystore.seen == [] and not (tmp_path / "pack" / runner.ARCHIVE).exists()


@linux
def test_a_project_that_names_another_store_fetches_nothing(tmp_path, monkeypatch, pystore):
    _online(monkeypatch, python=pystore)
    project = _py_project(tmp_path / "p", needs="--index-url https://elsewhere.example/simple/\nstage2sample==1.0.0\n")
    said, _ = _prepare(project, tmp_path / "pack")
    assert said["state"] == "not_run" and said["kind"] == "libraries", said
    assert "elsewhere" not in said["why_not"]       # the place is never repeated
    assert pystore.seen == [] and not (tmp_path / "pack" / runner.ARCHIVE).exists()


@linux
@needs_npm
def test_a_javascript_projects_packages_go_in_as_npm_laid_them_out(tmp_path, monkeypatch):
    with NpmStore() as store:
        _online(monkeypatch, npm=store)
        project = _js_project(tmp_path / "p", store)
        brought = project / "node_modules" / "brought"         # what the project brought: the fetched take its place
        brought.mkdir(parents=True)
        (brought / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        said, _ = _prepare(project, tmp_path / "pack", ["npm", "test"])
    assert said["state"] == "packed", said
    taken = _packed(tmp_path / "pack", tmp_path / "work")
    s = taken["settings"]
    assert s["language"] == "node" and s["libraries"]["state"] == "fetched" and s["fetched_with"] == ""
    assert [p["name"] for p in s["libraries"]["packages"]] == ["stage2-sample"]
    assert (taken["libraries"] / "stage2-sample" / "index.js").is_file()
    assert not (taken["project"] / "node_modules").exists()
    assert (taken["project"] / "package-lock.json").is_file()


@linux
def test_packages_the_project_brought_are_no_fetch_for_the_machine(tmp_path, monkeypatch):
    with NpmStore() as store:
        _online(monkeypatch, npm=store)
        project = tmp_path / "p"
        (project / "node_modules" / "stage2-sample").mkdir(parents=True)
        (project / "package.json").write_text(json.dumps({"name": "p", "version": "1.0.0", "scripts": {"test": "node t.js"},
                                                          "dependencies": {"stage2-sample": "1.0.0"}}), encoding="utf-8")
        (project / "yarn.lock").write_text("# yarn\n", encoding="utf-8")
        said, _ = _prepare(project, tmp_path / "pack", ["npm", "test"])
    assert said["state"] == "not_run" and said["kind"] == "libraries", said
    assert "yarn" in said["why_not"] and not (tmp_path / "pack" / runner.ARCHIVE).exists()


@linux
def test_the_packing_steps_command_line_takes_its_settings_and_the_command_after_the_dashes(tmp_path):
    project = _project(tmp_path / "p")
    out = tmp_path / "pack"
    assert runner.main(["prepare", str(project), str(out), "--minutes", "3", "--memory", "512", "--cwd", "", "--",
                        *UNITTEST]) == 0
    said = runner.prepared((out / runner.PREPARED).read_bytes())
    assert (said["state"], said["command"], said["minutes"], said["memory"], said["cwd"]) == ("packed", UNITTEST, 3,
                                                                                                512, "")
    # the same of the step that only packs (the image's cases, by hand)
    assert runner.main(["pack", str(project), str(tmp_path / "c.zip"), "--minutes", "3", "--memory", "512", "--",
                        *UNITTEST]) == 0
    s = runner.take(tmp_path / "c.zip", tmp_path / "work")["settings"]
    assert (s["command"], s["minutes"], s["memory"]) == (UNITTEST, 3, 512)
    for argv in (["prepare", str(project), str(tmp_path / "p2")], ["run", "x.zip", "--out", "o", "--", *UNITTEST]):
        with pytest.raises(SystemExit) as e:
            runner.main(argv)
        assert e.value.code == 2


# ---------------------------------------------------------------------------- a check that names no command (step 6)
# The website's tick box names no command: the packing step finds it in the project the way the app does
# (`sandbox.detect`), and starts no machine where there are no tests to run.
def _files(folder: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(text, encoding="utf-8")
    return folder


SCRIPT = json.dumps({"name": "p", "version": "1.0.0", "scripts": {"test": "node add.test.js"}})


@linux
def test_a_python_projects_command_is_found_and_its_runner_fetched(tmp_path, monkeypatch):
    with PyStore() as store:
        store.add("pytest", "8.3.0", {"pytest/__init__.py": "", "pytest/__main__.py": "raise SystemExit(0)\n"})
        _online(monkeypatch, python=store)
        project = _files(tmp_path / "p", {"app.py": "X = 1\n", "test_it.py": "def test_it():\n    assert True\n"})
        lines: list[str] = []
        said = runner.prepare(project, tmp_path / "pack", None, log=lines.append, minutes=3, memory=512, find=True)
    assert said["state"] == "packed", said
    assert (said["command"], said["cwd"]) == (["python", "-m", "pytest", "-q"], "")
    s = _packed(tmp_path / "pack", tmp_path / "work")["settings"]
    assert (s["command"], s["cwd"], s["minutes"], s["memory"]) == (["python", "-m", "pytest", "-q"], "", 3, 512)
    assert s["libraries"]["added"] == ["pytest"]
    assert "prepare: the tests' command, found in the project: python -m pytest -q" in lines


@linux
@pytest.mark.parametrize("files, cwd", [
    ({"README.md": "x\n", "web/package.json": SCRIPT, "web/add.test.js": "console.log(1)\n"}, "web"),
    ({"package.json": SCRIPT, "add.test.js": "console.log(1)\n"}, "")], ids=["in a folder", "at the top"])
def test_a_javascript_projects_test_script_is_found_with_its_folder(tmp_path, files, cwd):
    project = _files(tmp_path / "p", files)
    lines: list[str] = []
    said = runner.prepare(project, tmp_path / "pack", None, log=lines.append, minutes=3, memory=512, find=True)
    assert said["state"] == "packed", said
    assert (said["command"], said["cwd"]) == (["npm", "test"], cwd)
    s = _packed(tmp_path / "pack", tmp_path / "work")["settings"]
    assert (s["command"], s["cwd"], s["language"]) == (["npm", "test"], cwd, "node")
    assert any(ln.startswith("prepare: the tests' command, found in the project: npm test") for ln in lines)


@linux
@pytest.mark.parametrize("lock", ["pnpm-lock.yaml", "yarn.lock"])
def test_a_test_script_meant_for_pnpm_or_yarn_is_run_with_npm(tmp_path, lock):
    # the machine has npm, which runs the same test script; the explicit command keeps its refusal (the twin)
    project = _files(tmp_path / "p", {"package.json": SCRIPT, "add.test.js": "console.log(1)\n", lock: "# lock\n"})
    said = runner.prepare(project, tmp_path / "pack", None, log=QUIET, minutes=3, memory=512, find=True)
    assert said["state"] == "packed" and said["command"] == ["npm", "test"], said
    said, _ = _prepare(project, tmp_path / "pack2", [lock.split("-")[0].split(".")[0], "test"])
    assert said["state"] == "not_run" and "npm" in said["why_not"], said


@pytest.mark.parametrize("files, why", [
    ({"app.py": "X = 1\n", "requirements.txt": ""}, "NO_TESTS"),
    ({"composer.json": "{}", "src/User.php": "<?php\n", "tests/UserTest.php": "<?php\n"}, "NO_WAY"),
    ({"go.mod": "module x\n\ngo 1.22\n", "x.go": "package x\n", "x_test.go": "package x\n"},
     "The test machine runs the tests of Python and JavaScript projects for now, so nothing was run.")],
    ids=["no tests", "tests it does not start", "go"])
def test_where_there_is_nothing_to_start_no_machine_is_asked_for_and_the_reason_is_said(tmp_path, monkeypatch,
                                                                                       pystore, files, why):
    why = getattr(runner, why) if why.isupper() else why       # the program's own sentence, by its name
    _online(monkeypatch, python=pystore)
    project = _files(tmp_path / "p", files)
    said = runner.prepare(project, tmp_path / "pack", None, log=QUIET, minutes=3, memory=512, find=True)
    assert (said["state"], said["why_not"]) == ("not_run", why), said
    assert pystore.seen == [] and not (tmp_path / "pack" / runner.ARCHIVE).exists()


def test_the_packing_steps_find_takes_neither_a_command_nor_a_folder(tmp_path, capsys):
    project = _files(tmp_path / "p", {"package.json": SCRIPT, "add.test.js": "console.log(1)\n"})
    base = ["prepare", str(project), str(tmp_path / "out"), "--minutes", "3", "--memory", "512", "--find"]
    for argv in (base + ["--", *UNITTEST], base + ["--cwd=web"], base + ["--cwd", ""]):
        with pytest.raises(SystemExit) as e:
            runner.main(argv)
        assert e.value.code == 2
    assert not (tmp_path / "out").exists()
    assert runner.main(base) == 0                   # the twin: alone, it finds the command and packs
    said = json.loads((tmp_path / "out" / runner.PREPARED).read_text(encoding="utf-8"))
    assert (said["state"], said["command"], said["cwd"]) == ("packed", ["npm", "test"], "")


# ---------------------------------------------------------------------------- the record of a prepared check
GOOD = {"version": 1, "state": "packed", "why_not": "", "kind": "", "language": "python", "command": UNITTEST,
        "cwd": "", "minutes": 3, "memory": 512, "files": 3, "bytes": 100, "links": 0, "left_out": 0, "libraries": 1}
NOT_RUN = {"version": 1, "state": "not_run", "why_not": "The tests were not run.", "kind": "libraries"}


def test_the_record_of_a_prepared_check_is_taken_by_shape():
    assert runner.prepared(json.dumps(GOOD).encode()) == GOOD
    assert runner.prepared(json.dumps(NOT_RUN).encode()) == NOT_RUN
    for bad in ({**GOOD, "version": 2}, {**GOOD, "state": "done"}, {**GOOD, "files": -1}, {**GOOD, "files": True},
                {**GOOD, "command": "python -m unittest"}, {**GOOD, "minutes": 0}, {**GOOD, "memory": 1},
                {**GOOD, "cwd": "../up"}, {**GOOD, "language": "go"}, {**GOOD, "more": 1}, {**NOT_RUN, "why_not": ""},
                {**NOT_RUN, "kind": "sandbox"}, {**NOT_RUN, "why_not": "x" * 5000}, [GOOD]):
        with pytest.raises(runner.Refused):
            runner.prepared(json.dumps(bad).encode())
    for raw in (b"not json", b'{"version": 1, "version": 1}', b"\xff", b"NaN"):
        with pytest.raises(runner.Refused):
            runner.prepared(raw)


# ---------------------------------------------------------------------------- the folder the tests start in
def _folders(tmp_path: Path) -> Path:
    project = tmp_path / "p"
    (project / "web" / "tests").mkdir(parents=True)
    (project / "node_modules" / "lib").mkdir(parents=True)
    (project / ".git").mkdir()
    (project / "notes.txt").write_text("a file\n", encoding="utf-8")
    (project / "test_it.py").write_text("import unittest\n", encoding="utf-8")
    (tmp_path / "outside").mkdir()
    return project


NOT_THE_PROJECTS = ["../outside", "/tmp", "web/../..", "web\\tests", "c:web", "./web", "web/", "web//tests", "missing",
                    "notes.txt", "node_modules/lib", ".git", "web/missing", "x" * 5000]


def test_the_folder_the_tests_start_in_is_one_of_the_projects_own(tmp_path):
    project = _folders(tmp_path)
    assert runner.test_folder(project, "") == ""
    assert runner.test_folder(project, "web") == "web"
    assert runner.test_folder(project, "web/tests") == "web/tests"
    for bad in [*NOT_THE_PROJECTS, None, 3, ["web"]]:
        with pytest.raises(ValueError):
            runner.test_folder(project, bad)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs symbolic links")
def test_a_folder_reached_through_a_link_is_not_where_the_tests_start(tmp_path):
    project = _folders(tmp_path)
    (project / "out").symlink_to(tmp_path / "outside", target_is_directory=True)
    (project / "web" / "same").symlink_to(project / "web" / "tests", target_is_directory=True)   # inside, still a link
    for bad in ("out", "web/same", "out/x"):
        with pytest.raises(ValueError):
            runner.test_folder(project, bad)
    assert runner.test_folder(project, "web/tests") == "web/tests"        # the same folder by its own name
    said, _ = _prepare(project, tmp_path / "pack", cwd="web/same")
    assert said["state"] == "not_run" and not (tmp_path / "pack" / runner.ARCHIVE).exists(), said


@pytest.fixture()
def analyzed(monkeypatch):
    """The folder `lantern analyze` hands the analysis for its tests, written down in place of an analysis."""
    asked: list[str] = []

    def analyze(repo, out, *args, test_cwd="", **kw):
        asked.append(test_cwd)
        return {"counts": {}, "incomplete": [], "release": "Passed"}
    monkeypatch.setattr(pipeline, "analyze", analyze)
    return asked


def test_lantern_analyze_starts_the_tests_in_the_folder_named(tmp_path, monkeypatch, analyzed):
    project = _folders(tmp_path)
    monkeypatch.setattr(sandbox, "detect", lambda repo: {"language": "python", "cwd": "web", "command": UNITTEST})
    base = ["analyze", str(project), "--out", str(tmp_path / "out"), "--trace", "--sandbox"]
    assert cli.main([*base, "--", *UNITTEST]) == 0                          # not named: the folder Lantern finds
    assert cli.main([*base, "--test-cwd", "web/tests", "--", *UNITTEST]) == 0
    assert cli.main([*base, "--test-cwd", "", "--", *UNITTEST]) == 0       # the top, as named, though another is found
    assert analyzed == ["web", "web/tests", ""]


@pytest.mark.parametrize("folder", ["../outside", "/tmp", "node_modules/lib", "missing", "notes.txt", "web\\tests"])
def test_lantern_analyze_refuses_a_folder_that_is_not_the_projects_own(tmp_path, analyzed, capsys, folder):
    project = _folders(tmp_path)
    argv = ["analyze", str(project), "--out", str(tmp_path / "out"), "--trace", "--sandbox", "--test-cwd", folder,
            "--", *UNITTEST]
    assert cli.main(argv) == 2
    assert analyzed == [] and not (tmp_path / "out").exists()            # said before anything is read or written
    assert "--test-cwd" in capsys.readouterr().err


def test_the_folder_is_named_only_for_tests_in_the_sandbox(tmp_path, analyzed):
    project = _folders(tmp_path)
    for argv in (["--trace", "--test-cwd", "web", "--", *UNITTEST], ["--sandbox", "--test-cwd", "web"],
                 ["--test-cwd", "web"]):
        with pytest.raises(SystemExit) as e:
            cli.main(["analyze", str(project), "--out", str(tmp_path / "out"), *argv])
        assert e.value.code == 2
    assert analyzed == []


# ---------------------------------------------------------------------------- the machine's result, read back
def _project(folder: Path) -> Path:
    folder.mkdir()
    (folder / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (folder / "test_it.py").write_text("import unittest\n\nfrom app import add\n\n\nclass T(unittest.TestCase):\n"
                                       "    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n",
                                       encoding="utf-8")
    return folder


def _machine_result(**tests) -> dict:
    """What the website keeps of a check the machine ran: the machine's program's result (`runner.check`) and the
    machine it ran on (`machines.Machines.run`)."""
    t = {"pairs": [{"caller": ["test_it.py", 1, "T.test_add", 8], "callee": ["app.py", 1, "add", 2]}],
         "returncode": 0, "timed_out": False, "over_memory": False, "over_processes": False, "processes_limit": 4096,
         "blocked": [], "not_ended": [], "own_network": True, "own_sockets": True, "off_network": True,
         "windows_wall": False, "libraries": {"state": "none", "language": "python"}, "traced": True,
         "language": "python", "backend": "subprocess", "stderr_tail": "Ran 1 test\n\nOK\n",
         "output_tail": "Ran 1 test\n\nOK\n", "cancelled": False, "memory_limit": 512}
    t.update(tests)
    walls = ("the tests' own network", "a doorman for every connection", "the memory watch",
             "a limit on the tests' programs", "an ordinary user for the tests")
    return {"version": 1, "state": "done", "why_not": "",
            "runner": {"lantern": "0.11.0", "commit": "a" * 40, "python": "3.12.8", "system": "Linux 6.12",
                       "walls": [{"wall": w, "stands": True, "why": ""} for w in walls]},
            "taken": {"files": 3, "bytes": 300, "links": 0},
            "check": {"command": UNITTEST, "cwd": "", "minutes": 3, "memory": 512, "language": "python",
                      "processes": 4096},
            "tests": t,
            "machine": {"image": "registry.example/lantern-runner@sha256:" + "b" * 64, "region": "sjc", "cpus": 2,
                        "memory_mb": 4096}}


def _hand(tmp_path: Path, result) -> Path:
    f = tmp_path / "machine-result.json"
    f.write_text(result if isinstance(result, str) else json.dumps(result), encoding="utf-8")
    return f


@pytest.fixture()
def nothing_runs_here(monkeypatch):
    """What would run a project's tests on this computer, written down when it is asked to."""
    ran: list[str] = []

    def sandboxed(repo, words, **kw):
        ran.append("sandbox")
        return {"pairs": [], "returncode": 0, "timed_out": False, "traced": False, "backend": "subprocess",
                "language": "python", "cancelled": False, "stderr_tail": "", "over_memory": False}

    def in_its_folder(repo, command, timeout=None):
        ran.append("in its folder")
        return {"pairs": [], "returncode": 0, "stderr_tail": ""}
    monkeypatch.setattr(sandbox, "run", sandboxed)
    monkeypatch.setattr(trace, "run_trace", in_its_folder)
    return ran


def _website(monkeypatch, handed: Path | None) -> None:
    monkeypatch.setenv("LANTERN_CLOUD_RUN", "1")
    if handed is None:
        monkeypatch.delenv("LANTERN_TESTS_FROM", raising=False)
    else:
        monkeypatch.setenv("LANTERN_TESTS_FROM", str(handed))


def _check(repo: Path, out: Path, sandboxed: bool = True) -> tuple[dict, dict, dict]:
    pipeline.analyze(repo, out, trace_cmd=UNITTEST, sandbox=sandboxed, offline=True, log=QUIET)
    run = json.loads((out / "run.json").read_text(encoding="utf-8"))
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    return run, rd, ev


def _release_tests(rd: dict) -> dict:
    return next(c for c in rd["release"]["criteria"] if c["id"] == "tests")


def _tests_pass(rd: dict) -> dict:
    return next(c for cat in rd["categories"] for c in cat["checks"] if c["id"] == "tests-pass")


def test_the_machines_result_goes_into_the_report_as_a_test_run(tmp_path, monkeypatch, nothing_runs_here):
    repo = _project(tmp_path / "p")
    _website(monkeypatch, _hand(tmp_path, _machine_result()))
    run, rd, ev = _check(repo, tmp_path / "out")
    tr = run["trace"]
    assert tr["ran"] is True and tr["returncode"] == 0 and tr["place"] == "test machine", tr
    assert tr["command"] == UNITTEST and tr["time_limit"] == 180 and tr["memory_limit"] == 512
    assert tr["processes_limit"] == 4096 and tr["over_processes"] is False
    assert tr["machine"]["lantern"] == "0.11.0" and tr["machine"]["python"] == "3.12.8"
    assert tr["machine"]["memory_mb"] == 4096 and tr["machine"]["region"] == "sjc"
    assert tr["observed_edges"] >= 1            # the call the tests made on the machine, found on this map
    assert _release_tests(rd)["state"] == "passed" and _tests_pass(rd)["status"] == "pass"
    assert any("test machine" in line for line in ev["limits"])
    assert nothing_runs_here == []
    # the twin: tests that failed there failed
    _website(monkeypatch, _hand(tmp_path, _machine_result(returncode=1)))
    run, rd, _ = _check(repo, tmp_path / "out2")
    assert run["trace"]["returncode"] == 1 and _release_tests(rd)["state"] == "failed"
    assert nothing_runs_here == []


def test_the_calls_are_named_from_this_project_and_rows_of_another_shape_are_left_out(tmp_path):
    repo = _project(tmp_path / "p")
    good = {"caller": ["test_it.py", 1, "T.test_add", 8], "callee": ["app.py", 1, "add", 2]}
    up = {"caller": ["../../etc/x.py", 1, "f", 1], "callee": ["app.py", 1, "add", 2]}
    outside = {"caller": ["/usr/lib/python3.12/unittest/case.py", 1, "run", 1], "callee": ["app.py", 1, "add", 2]}
    back = {"caller": ["sub\\test_it.py", 1, "f", 1], "callee": ["app.py", 1, "add", 2]}
    here = {"caller": ["./test_it.py", 1, "f", 1], "callee": ["app.py", 1, "add", 2]}
    rows = [good, up, outside, back, here, {"caller": "test_it.py", "callee": ["app.py", 1, "add", 2]}, "row", None]
    data = runner.handed(_hand(tmp_path, _machine_result(pairs=rows)), repo, UNITTEST, "")
    assert len(data["pairs"]) == 2, data["pairs"]    # a name that is not one of the machine's own shape is no call
    assert data["pairs"][0]["caller"][0] == os.path.join(str(repo), "test_it.py")
    assert data["pairs"][0]["callee"][0] == os.path.join(str(repo), "app.py")
    assert data["pairs"][1]["caller"][0] == "/usr/lib/python3.12/unittest/case.py"     # outside: kept as it was
    assert data["pairs"] == trace.well_formed(data)["pairs"]


SHAPES = {
    "another version": lambda r: r.update(version=2),
    "a state of its own": lambda r: r.update(state="finished"),
    "done with no tests": lambda r: r.pop("tests"),
    "tests not a table": lambda r: r.update(tests=[1]),
    "another command": lambda r: r["check"].update(command=["python", "-m", "pytest"]),
    "another folder": lambda r: r["check"].update(cwd="sub"),
    "a result in words": lambda r: r["tests"].update(returncode="0"),
    "a stop in words": lambda r: r["tests"].update(timed_out="yes"),
    "a reason too long": lambda r: r.update(state="unable", why_not="x" * 5000),
    "no reason": lambda r: r.update(state="unable", why_not=""),
    "stopped part-way": lambda r: r["tests"].update(cancelled=True),
    "minutes out of range": lambda r: r["check"].update(minutes=10_000),
}


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_a_result_of_another_shape_is_not_used(tmp_path, name):
    repo = _project(tmp_path / "p")
    result = _machine_result()
    SHAPES[name](result)
    with pytest.raises(runner.NotRun) as got:
        runner.handed(_hand(tmp_path, result), repo, UNITTEST, "")
    assert got.value.kind == "machine" and str(got.value)
    assert "x" * 100 not in str(got.value)
    # the twin: the result as the machine writes it is taken
    assert runner.handed(_hand(tmp_path, _machine_result()), repo, UNITTEST, "")["returncode"] == 0


@pytest.mark.parametrize("text", ["not json", "[]", '{"version": 1, "version": 1}', ""])
def test_a_result_that_is_no_json_table_is_not_used(tmp_path, text):
    repo = _project(tmp_path / "p")
    with pytest.raises(runner.NotRun) as got:
        runner.handed(_hand(tmp_path, text), repo, UNITTEST, "")
    assert got.value.kind == "machine"


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs symbolic links")
def test_a_result_that_is_a_link_is_not_followed(tmp_path):
    repo = _project(tmp_path / "p")
    real = _hand(tmp_path, _machine_result())
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(runner.NotRun):
        runner.handed(link, repo, UNITTEST, "")
    assert runner.handed(real, repo, UNITTEST, "")["returncode"] == 0


def test_a_check_of_the_website_runs_no_tests_on_the_website_itself(tmp_path, monkeypatch, nothing_runs_here):
    repo = _project(tmp_path / "p")
    _website(monkeypatch, None)
    for sandboxed in (True, False):
        run, rd, ev = _check(repo, tmp_path / f"out-{sandboxed}", sandboxed)
        tr = run["trace"]
        assert tr["ran"] is False and tr["not_run_for"] == "machine" and tr["unavailable"] == runner.NOT_HERE, tr
        assert _release_tests(rd)["state"] == "missing" and "test machine" in _release_tests(rd)["why"]
        assert _tests_pass(rd)["status"] == "skip" and "test machine" in _tests_pass(rd)["evidence"]
        assert any("test machine" in line for line in ev["limits"])
    assert nothing_runs_here == []
    # the twins: on a person's own computer the sandbox runs them, whatever the website's variable says there
    monkeypatch.delenv("LANTERN_CLOUD_RUN")
    monkeypatch.setenv("LANTERN_TESTS_FROM", str(_hand(tmp_path, _machine_result())))
    run, _, _ = _check(repo, tmp_path / "own")
    assert nothing_runs_here == ["sandbox"] and "place" not in run["trace"]


def test_tests_the_machine_did_not_run_say_why_and_are_no_pass(tmp_path, monkeypatch, nothing_runs_here):
    repo = _project(tmp_path / "p")
    why = "The website's test machines are off, so the tests were not run."
    _website(monkeypatch, _hand(tmp_path, runner.not_run(why)))
    run, rd, ev = _check(repo, tmp_path / "out")
    tr = run["trace"]
    assert tr["ran"] is False and tr["not_run_for"] == "machine" and tr["unavailable"] == why
    assert _release_tests(rd)["state"] == "missing" and rd["release"]["decision"] != "Passed"
    assert any(why.rstrip(".").lower() in line.lower() for line in ev["limits"])
    # the libraries could not be had for the machine: said as that
    _website(monkeypatch, _hand(tmp_path, runner.not_run("the project's libraries could not be fetched: stage2sample "
                                                        "was not found in the store", "libraries")))
    run, rd, _ = _check(repo, tmp_path / "out2")
    assert run["trace"]["not_run_for"] == "libraries" and "libraries" in _release_tests(rd)["why"]
    assert nothing_runs_here == []


def test_tests_the_machine_stopped_at_their_programs_limit_did_not_finish(tmp_path, monkeypatch, nothing_runs_here):
    repo = _project(tmp_path / "p")
    _website(monkeypatch, _hand(tmp_path, _machine_result(returncode=None, over_processes=True)))
    run, rd, _ = _check(repo, tmp_path / "out")
    tr = run["trace"]
    assert tr["over_processes"] is True and tr["processes_limit"] == 4096 and tr["returncode"] is None
    assert _release_tests(rd)["state"] == "missing" and "programs" in _release_tests(rd)["why"]
    assert _tests_pass(rd)["status"] == "skip"
    assert nothing_runs_here == []
