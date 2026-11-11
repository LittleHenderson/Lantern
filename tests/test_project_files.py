"""One way to open a file of the project, one way to read a result file back, and one word for where the project
is (2026-11-10, directive stage 7; the link fix before it is in tests/test_links_out.py).

1. A file of the project is opened through `python_frontend.project_text` / `project_bytes` and in no other way.
   The readers that walk a project already asked `inside_repo`; the files opened by their name (`package.json`,
   `go.mod`, a notebook, an Xcode project, a path kept in an earlier result) did not, so a link under such a name
   was read wherever it led, and a pipe under it held the analysis up for good. The sweep `bench/links.py` found
   them (17 files read through a link, 29 held up, 3 that told whether an outside path exists); the cases it found
   run here on every CI run, each beside the same link kept inside the project, which is read as before.
2. A result file (`.lantern/*.json`, `report.html`) is read back only as a plain file (`results.plain`): the
   results folder lies in the project, so what is in it may have come with the project.
3. The project folder is the one the caller was given. The saved map names a folder too (`repo_root`), and until
   this date `lantern report`, `explain` and `evidence` read the functions' lines there: a project that brought
   its own `.lantern/graph.json` chose which folder of the computer was read, shown in the report and sent to the
   model.
"""
import ast
import json
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from lantern import ask, depaudit, evidence, learn, pipeline, remote, results, sandbox, scanresult, security
from lantern.cli import main
from lantern.graph import Graph
from lantern.providers import FixtureProvider
from lantern.python_frontend import project_bytes, project_text
from lantern.report import read_bundle
from lantern.server import App, Store, result_page

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "bench"))
import links as sweep  # noqa: E402  (bench/links.py: the sweep that found the cases below)

only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links, pipes)")
PRIVATE = "PRIVATE-LINE-7341"
OWN = "OWN-LINE-1234"
APP = f"def run():\n    return '{OWN}'\n"
OTHER = f"def run():\n    return '{PRIVATE}'\n"


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _without_bandit(monkeypatch) -> None:
    """Bandit is another program and takes a second and a half of each analysis (tests/test_links_out.py has its
    tests)."""
    monkeypatch.setattr(security, "run_bandit", lambda repo, applicable=True: ([], scanresult.record(
        "bandit", "unavailable", "left out of this test", applicable=False, version=None,
        role="Python code patterns", exclusions=[])))


def _analyze(repo: Path, out: Path | None = None) -> Path:
    out = out or repo / ".lantern"
    out.mkdir(parents=True, exist_ok=True)
    pipeline.analyze(repo, out, log=lambda line: None, offline=True)
    return out


def _in_time(fn, pipe: Path, seconds: int = 30):
    """What `fn()` gives, from a thread: a reader that opens the pipe waits there for good, and the test must not.
    When it is still waiting after `seconds` the pipe is opened for writing, which lets the reader go, and the test
    fails."""
    done: list = []

    def run():
        try:
            done.append(("gave", fn()))
        except BaseException as e:  # noqa: BLE001 - handed to the test's own thread below
            done.append(("raised", e))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if not done:
        try:
            os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:
            pass
        t.join(5)
        pytest.fail(f"still waiting on {pipe.name}, a pipe nobody writes to")
    how, value = done[0]
    if how == "raised":
        raise value
    return value


# ---------------------------------------------------------------------------- 1. the one way to open a project's file

def test_a_file_of_the_project_is_read_whole_or_up_to_a_limit(tmp_path):
    repo = _write(tmp_path / "project", {"app.py": APP, "pkg/data.bin": "abcdef"})
    assert project_text(repo / "app.py", repo) == APP
    assert project_text(repo / "app.py", repo, 7) == APP[:7]
    assert project_bytes(repo / "pkg" / "data.bin", repo) == b"abcdef"
    assert project_bytes(repo / "pkg" / "data.bin", repo, 2) == b"ab"
    assert project_text(str(repo / "app.py"), str(repo)) == APP        # paths as text are taken too


def test_a_path_that_leaves_the_project_is_a_file_that_is_not_there(tmp_path):
    """A path kept in an earlier result (a function's file in graph.json, a finding's file in security.json) is put
    behind the project's folder and opened. `..` and a path from the top of the disk lead anywhere."""
    repo = _write(tmp_path / "project", {"app.py": APP, "pkg/mod.py": "x = 1\n"})
    other = _write(tmp_path / "other", {"app.py": OTHER})
    for path in (repo / ".." / "other" / "app.py", repo / str(other / "app.py"), repo / "pkg" / ".." / ".." / "other" / "app.py",
                 repo / "missing.py", repo / "pkg", repo / "app.py\x00.txt"):
        for read in (project_text, project_bytes):
            with pytest.raises(FileNotFoundError):                    # an OSError: every reader passes it over
                read(path, repo)
    assert project_text(repo / "pkg" / ".." / "app.py", repo) == APP    # `..` that stays inside is the project's
    assert project_text(repo / str(repo / "app.py"), repo) == APP       # and so is its own file by its whole path


@only_posix
def test_a_link_out_a_pipe_and_a_file_behind_a_linked_folder_are_not_there(tmp_path):
    repo = _write(tmp_path / "project", {"app.py": APP, "pkg/mod.py": "x = 1\n"})
    other = _write(tmp_path / "other", {"app.py": OTHER, "dir/inner.py": OTHER})
    os.symlink(other / "app.py", repo / "out.py")
    os.symlink(other / "dir", repo / "vendor")
    os.symlink(other / "nowhere", repo / "broken.py")
    os.mkfifo(repo / "pipe.py")
    for name in ("out.py", "vendor/inner.py", "broken.py", "pipe.py"):
        for read in (project_text, project_bytes):
            with pytest.raises(FileNotFoundError):
                _in_time(lambda read=read, name=name: read(repo / name, repo), repo / "pipe.py", 10)
    os.symlink("app.py", repo / "same.py")                           # the twins: a link that stays in the project,
    os.symlink(repo / "pkg", repo / "alias")                         # a folder link that stays in it,
    os.symlink(repo, tmp_path / "shortcut")                          # and the person's own shortcut to the project
    assert project_text(repo / "same.py", repo) == APP
    assert project_text(repo / "alias" / "mod.py", repo) == "x = 1\n"
    assert project_text(tmp_path / "shortcut" / "app.py", tmp_path / "shortcut") == APP
    with pytest.raises(FileNotFoundError):
        project_text(tmp_path / "shortcut" / "out.py", tmp_path / "shortcut")


# What Lantern itself keeps (its templates, its settings in LANTERN_HOME, its own temporary files) and the four
# openers. Everything else in `lantern/` that opens a file for reading is a find: (module, function) -> why not.
OWN_FILES = {
    ("python_frontend.py", "project_bytes"): "the opener", ("python_frontend.py", "project_text"): "the opener",
    ("results.py", "plain"): "the opener for result files", ("gitfacts.py", "_text"): "the opener for git's files",
    ("results.py", "write"): "writes", ("removal.py", "_write"): "writes", ("server.py", "FileLock.__enter__"): "a lock",
    ("_jail.py", "_landlock"): "a folder handle for Landlock", ("_jail.py", "_stat"): "/proc",
    ("removal.py", "_by_folder"): "a folder handle", ("removal.py", "_empty"): "a folder handle",
    ("removal.py", "_open_dir"): "a folder handle", ("removal.py", "_give_rights"): "a folder handle",
    ("removal.py", "_read"): "LANTERN_HOME", ("usage.py", "_read"): "LANTERN_HOME", ("usage.py", "install_id"): "LANTERN_HOME",
    ("providers.py", "load_token"): "LANTERN_HOME", ("providers.py", "has_consent"): "LANTERN_HOME",
    ("providers.py", "record_consent"): "LANTERN_HOME", ("server.py", "Store._read"): "LANTERN_HOME",
    ("packs.py", "disabled"): "LANTERN_HOME", ("packs.py", "_read_pack"): "a built-in or LANTERN_HOME pack; a project's goes through project_text",
    ("guide.py", "_template"): "a template", ("report.py", "render"): "a template", ("server.py", "Handler.do_GET"): "a template",
    ("server.py", "Handler._static"): "a file of the app itself", ("learn.py", "get"): "a starter template",
    ("learn.py", "scaffold"): "a starter template", ("learn.py", "solution_text"): "a starter template",
    ("archive.py", "unpack"): "a member of the upload, by the archive's own reader",
    ("depaudit.py", "precomputed"): "the file the cloud worker names in LANTERN_AUDITS_FROM",
    ("security.py", "_run_gitleaks"): "gitleaks' report in Lantern's own temporary folder",
    ("ask.py", "read_screenshot"): "a picture held in memory", ("cli.py", "cmd_login"): "a web page",
    ("server.py", "serve"): "a web address",
}


def _opens(tree) -> list[tuple[str, int]]:
    """(function, line) of every call that opens a file for reading: `open` without a writing mode, `os.open`,
    `.read_text`, `.read_bytes`, any other `.open`."""
    found, stack = [], []

    class Visit(ast.NodeVisitor):
        def _named(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()
        visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _named

        def visit_Call(self, node):
            f = node.func
            reads = False
            if isinstance(f, ast.Name) and f.id == "open":
                mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                mode = mode.value if isinstance(mode, ast.Constant) else "r" if mode is None else "?"
                reads = not any(c in str(mode) for c in "wax")
            elif isinstance(f, ast.Attribute) and f.attr in ("read_text", "read_bytes", "open"):
                reads = True
            if reads:
                found.append((".".join(stack) or "<module>", node.lineno))
            self.generic_visit(node)
    Visit().visit(tree)
    return found


def test_no_file_is_opened_any_other_way():
    """Every place in `lantern/` that opens a file for reading is one of the openers or opens a file of Lantern's
    own (OWN_FILES says which). A new reader that opens a project's file with a plain `open` or `read_text` fails
    here, before any sweep is run."""
    found = {}
    for path in sorted((ROOT / "lantern").glob("*.py")):
        for function, line in _opens(ast.parse(path.read_text(encoding="utf-8"))):
            found.setdefault((path.name, function), []).append(line)
    new = {f"{module}:{lines[0]} {function}" for (module, function), lines in found.items() if (module, function) not in OWN_FILES}
    assert not new, f"opened without project_text / project_bytes / results.plain: {sorted(new)}"
    gone = sorted(k for k in OWN_FILES if k not in found)
    assert not gone, f"OWN_FILES names places that open nothing any more: {gone}"


def test_the_look_for_openers_sees_each_way_of_opening():
    code = ("def a(p):\n    return open(p).read()\n"
            "def b(p):\n    return p.read_text(encoding='utf-8')\n"
            "def c(p):\n    return p.read_bytes()\n"
            "def d(p):\n    with open(p, 'rb') as f:\n        return f.read()\n"
            "def e(p):\n    return os.open(p, os.O_RDONLY)\n"
            "def w(p):\n    with open(p, 'w') as f:\n        f.write('x')\n"
            "def x(p):\n    return open(p, mode='xb')\n"
            "class K:\n    def m(self, p):\n        return p.open()\n")
    assert [name for name, _line in _opens(ast.parse(code))] == ["a", "b", "c", "d", "e", "K.m"]


# The files of the sample projects that the sweep found on the code before (bench/links_results.md): read through
# a link, held up by a pipe, or both.
FOUND = [("aiapp", "notebooks/experiments.ipynb"), ("aiapp", "web/package.json"), ("androidapp", "app/build.gradle"),
         ("androidapp", "app/src/main/res/xml/network_security_config.xml"), ("cppapp", "web/package.json"),
         ("csharpapp", "NotesApi/NotesApi.csproj"), ("csharpapp", "NotesApp/NotesApp.csproj"), ("flutterapp", "pubspec.yaml"),
         ("goapp", "go.mod"), ("goapp", "web/package.json"), ("iosapp", "Journal.xcodeproj/project.pbxproj"),
         ("iosapp", "Journal/Info.plist"), ("iosapp", "Journal/Journal.entitlements"), ("javaapp", "web/package.json"),
         ("kotlinapp", "app/build.gradle.kts"), ("nextapp", "package.json"), ("nextapp", "tsconfig.json"),
         ("phpapp", "package.json"), ("rnapp", "app.json"), ("rnapp", "package.json"), ("rubyapp", "web/package.json"),
         ("rustapp", "Cargo.toml"), ("rustapp", "web/package.json"), ("shop", "pyproject.toml"), ("shop", "web/package.json"),
         ("shop", "web/tsconfig.json")]
BY_NAME = [("extras", rel) for rel in sorted(sweep.EXTRA)]      # and every file Lantern looks for by its name


def _said(sample: str, rel: str, state: str, here: Path) -> dict:
    """What the analysis says about the sample with the file `rel` in `state` (the sweep's own states, and two more:
    `inside`, a link to where the file was moved inside the project, and `beside`, the file in its place with a
    copy where `inside` keeps it)."""
    repo = here / "p" / sample
    repo.parent.mkdir(parents=True)
    sweep.make(FIXTURES, sample, repo)
    if state in ("inside", "beside"):
        kept = repo / ".kept" / "moved"
        kept.parent.mkdir()
        shutil.copyfile(repo / rel, kept)
        if state == "inside":
            (repo / rel).unlink()
            os.symlink(kept, repo / rel)
    elif state != "whole":
        sweep.put(repo, rel, state, here / "outside")
    out = here / "out"
    out.mkdir()
    _in_time(lambda: pipeline.analyze(repo, out, log=lambda line: None, offline=True), repo / rel)
    return sweep.says(out, str(here))


@only_posix
@pytest.mark.parametrize("sample, rel", FOUND + BY_NAME, ids=lambda v: v.replace("/", "_"))
def test_a_file_looked_for_by_its_name_is_not_read_through_a_link_and_not_waited_on(sample, rel, tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    said = {state: _said(sample, rel, state, tmp_path / state)
            for state in ("link", "other", "nothing", "pipe", "loop", "inside", "beside")}
    # nothing the analysis says depends on what the outside file holds, or on whether it is there at all
    assert said["link"] == said["other"], "read through the link"
    assert said["other"] == said["nothing"], "the results tell whether the outside path exists"
    assert not [v for state in ("pipe", "loop") for v in said[state].values() if v.startswith("unreadable")]
    # the twin: the same link kept inside the project is the project's file, and is read as the file itself is
    assert said["inside"] == said["beside"]


READ_BEFORE = [("aiapp", "notebooks/experiments.ipynb"), ("androidapp", "app/build.gradle"), ("goapp", "go.mod"),
               ("iosapp", "Journal/Info.plist"), ("nextapp", "package.json"), ("rnapp", "app.json"), ("rustapp", "Cargo.toml")]


@only_posix
@pytest.mark.parametrize("sample, rel", READ_BEFORE, ids=lambda v: v.replace("/", "_"))
def test_the_comparison_can_see_a_read(sample, rel, tmp_path, monkeypatch):
    """The test above compares a link to the file with a link to an empty file. That only shows a read when the
    file matters to the results: for these it does (the project with the file differs from the project with an
    empty one), so equal results there mean the link was not read."""
    _without_bandit(monkeypatch)
    whole = _said(sample, rel, "whole", tmp_path / "whole")
    here = tmp_path / "empty"
    repo = here / "p" / sample
    repo.parent.mkdir(parents=True)
    sweep.make(FIXTURES, sample, repo)
    (repo / rel).write_bytes(b"")
    (here / "out").mkdir()
    pipeline.analyze(repo, here / "out", log=lambda line: None, offline=True)
    assert sweep.says(here / "out", str(here)) != whole


def test_the_sweep_names_each_kind_of_find():
    """`bench/links.py` judges runs it did not make here: one file per kind of find, and one that is clean."""
    def run(rel, state, **more):
        return {"project": "p", "file": rel, "state": state, **more}
    same, less = {"graph.json": "a"}, {"graph.json": "b"}
    runs = [run("", "whole", says=same), run("", "whole", says=same)]
    for rel, by_state in {
        "clean.txt": {"gone": less, "link": less, "other": less, "nothing": less, "pipe": less},
        "read.txt": {"gone": less, "link": same, "other": less, "nothing": less, "pipe": less},
        "named.txt": {"gone": less, "link": same, "other": same, "nothing": same, "pipe": less},   # named, never read
        "tells.txt": {"gone": less, "link": same, "other": same, "nothing": less, "pipe": less},
    }.items():
        runs += [run(rel, state, says=says) for state, says in by_state.items()]
    runs += [run("pipe.txt", s, says=less) for s in ("gone", "link", "other", "nothing")] + [run("pipe.txt", "pipe", held="x.py:1 f")]
    runs += [run("stop.txt", s, says=less) for s in ("gone", "link", "other", "pipe")] + [run("stop.txt", "nothing", error="E at x.py:2 g")]
    verdict = sweep.judge(runs)
    finds = {kind: [(rel, state) for _p, rel, state, _detail in rows] for kind, rows in verdict["finds"].items()}
    assert verdict["files"] == 6
    assert finds == {"read through": [("read.txt", "link")], "tells": [("tells.txt", "nothing")],
                     "held up": [("pipe.txt", "pipe")], "stopped": [("stop.txt", "nothing")], "unstable": []}
    assert sweep.judge([run("", "whole", says=same), run("", "whole", says=less)])["finds"]["unstable"]


@only_posix
def test_the_sweeps_time_limit_is_not_passed_over_by_a_reader():
    """A reader that passes over whatever goes wrong with one file and goes on to the next is still ended at the
    sweep's limit. Until 2026-11-10 the limit was an `Exception` and rang once: such a reader caught it, went on, and
    the run then either waited on the next pipe for good (the sweep of the code before never ended) or finished and
    was counted as not held up."""
    def each_file_passed_over():                  # ten files, each wait given up on whatever is raised into it
        for _ in range(10):
            try:
                time.sleep(1)
            except Exception:  # noqa: BLE001 - the reader this test is about
                pass

    def all_caught_once():                         # caught all the same, once: the limit rings again
        try:
            time.sleep(3)
        except BaseException:  # noqa: BLE001
            pass
        time.sleep(3)

    before = signal.getsignal(signal.SIGALRM)
    for reader in (each_file_passed_over, all_caught_once):
        t0 = time.monotonic()
        assert sweep.limited(0.3, reader, again=0.3)[0] == "held"
        assert time.monotonic() - t0 < 2
    assert sweep.limited(0.2, lambda: None, again=0.1) == (None, None)
    sweep._late(signal.SIGALRM, None)              # a ring that comes after the call raises nothing
    kind, what = sweep.limited(5, lambda: 1 / 0)
    assert kind == "error" and what.startswith("ZeroDivisionError")
    assert signal.getsignal(signal.SIGALRM) is before and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@only_posix
def test_the_sweeps_six_states(tmp_path):
    for state in sweep.STATES:
        repo = _write(tmp_path / state / "project", {"a.txt": "kept"})
        sweep.put(repo, "a.txt", state, tmp_path / state / "outside")
        p, there = repo / "a.txt", tmp_path / state / "outside" / "moved"
        if state == "gone":
            assert not os.path.lexists(p)
        elif state == "pipe":
            assert p.is_fifo()
        elif state == "loop":
            assert os.readlink(p) == "a.txt" and not p.exists()
        else:
            assert p.is_symlink() and os.readlink(p) == str(there)
            assert {"link": "kept", "other": "", "nothing": None}[state] == (there.read_text(encoding="utf-8") if there.exists() else None)


# -- the files the comparison above cannot see: their being read changes what the analysis says only when they hold
#    something that matters, so each gets a file that does

@only_posix
def test_an_accepted_risks_file_that_is_a_link_accepts_nothing(tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    code = {"app.js": "export function show(el, text) {\n  el.innerHTML = text\n}\n"}
    first = _analyze(_write(tmp_path / "first" / "project", code))
    finding = next(f for f in json.loads((first / "security.json").read_text(encoding="utf-8"))["findings"])
    accepted = json.dumps({"accepted": [{"id": finding["id"], "reason": "it is only used for a cache key", "by": "t"}]})
    state = {}
    for how in ("own", "link"):
        repo = _write(tmp_path / how / "project", code)
        if how == "own":
            _write(repo, {"lantern-accepted.json": accepted})
        else:
            os.symlink(_write(tmp_path / how / "outside", {"a.json": accepted}) / "a.json", repo / "lantern-accepted.json")
        sec = json.loads((_analyze(repo) / "security.json").read_text(encoding="utf-8"))
        state[how] = [bool(f.get("accepted")) for f in sec["findings"] if f["id"] == finding["id"]]
    assert state == {"own": [True], "link": [False]}


@only_posix
def test_a_project_pack_and_a_settings_file_that_are_links_are_not_used(tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    pack = json.dumps({"pack": "mine", "version": "1", "about": "a pack", "rules": [
        {"id": "LP-MINE-1", "title": "a shell is started", "pattern": r"os\.system", "severity": "MEDIUM", "files": ["*.py"]}]})
    code = {"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"}
    rules = {}
    for how in ("own", "link"):
        repo = _write(tmp_path / how / "project", code)
        if how == "own":
            _write(repo, {"lantern-packs/mine.json": pack})
        else:
            (repo / "lantern-packs").mkdir()
            os.symlink(_write(tmp_path / how / "outside", {"mine.json": pack}) / "mine.json", repo / "lantern-packs" / "mine.json")
        sec = json.loads((_analyze(repo) / "security.json").read_text(encoding="utf-8"))
        rules[how] = "LP-MINE-1" in {f["rule"] for f in sec["findings"]}
    assert rules == {"own": True, "link": False}


@only_posix
def test_the_test_command_is_not_read_from_a_package_file_that_is_a_link(tmp_path):
    """`sandbox.detect` proposes the command for "Watch my tests run" from the project's package.json."""
    pkg = json.dumps({"scripts": {"test": "jest"}})
    own = _write(tmp_path / "own", {"package.json": pkg})
    assert sandbox.detect(own)["language"] == "node"
    linked = tmp_path / "linked"
    linked.mkdir()
    os.symlink(_write(tmp_path / "outside", {"p.json": pkg}) / "p.json", linked / "package.json")
    assert sandbox.detect(linked)["supported"] is False
    piped = tmp_path / "piped"
    piped.mkdir()
    os.mkfifo(piped / "package.json")
    assert _in_time(lambda: sandbox.detect(piped), piped / "package.json", 10)["supported"] is False


NAMES_A_TEST_SETUP = ["pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "requirements.txt", "go.mod", "Cargo.toml",
                      "pom.xml", "build.gradle", "build.gradle.kts"]


@only_posix
@pytest.mark.parametrize("name", NAMES_A_TEST_SETUP)
def test_the_test_command_is_the_same_whatever_a_linked_file_leads_to(name, tmp_path):
    """`sandbox.detect` only asks whether these files are there. A link that leads out of the project is not the
    project's file, whether or not something is at its other end; the project's own file is."""
    said = {}
    for leads_to in ("a file", "nothing"):
        repo = tmp_path / leads_to / "project"
        repo.mkdir(parents=True)
        outside = _write(tmp_path / leads_to / "outside", {"there": "x\n"})
        os.symlink(outside / ("there" if leads_to == "a file" else "nowhere"), repo / name)
        said[leads_to] = sandbox.detect(repo)
    assert said["a file"] == said["nothing"] and said["a file"]["supported"] is False
    assert sandbox.detect(_write(tmp_path / "own", {name: "x\n"}))["supported"] is True


@only_posix
def test_the_gradle_and_package_manager_words_come_from_the_projects_own_files(tmp_path):
    outside = _write(tmp_path / "outside", {"there": "x\n"})
    gradle = _write(tmp_path / "gradle", {"build.gradle": "x\n"})
    os.symlink(outside / "there", gradle / "gradlew")
    assert sandbox.detect(gradle)["command"] == "gradle test --offline"
    assert sandbox.detect(_write(tmp_path / "gradle-own", {"build.gradle": "x\n", "gradlew": "x\n"}))["command"] == "./gradlew test --offline"
    node = _write(tmp_path / "node", {"package.json": json.dumps({"scripts": {"test": "jest"}})})
    os.symlink(outside / "there", node / "pnpm-lock.yaml")
    assert sandbox.detect(node)["command"] == "npm test"
    own = _write(tmp_path / "node-own", {"package.json": json.dumps({"scripts": {"test": "jest"}}), "pnpm-lock.yaml": "x\n"})
    assert sandbox.detect(own)["command"] == "pnpm test"
    tests = tmp_path / "tests-linked"
    tests.mkdir()
    os.symlink(_write(tmp_path / "outside-tests", {"test_x.py": "def test_x(): pass\n"}), tests / "tests")
    assert sandbox.detect(tests)["supported"] is False
    own_tests = sandbox.detect(_write(tmp_path / "tests-own", {"tests/test_x.py": "def test_x(): pass\n"}))
    assert own_tests["supported"] is True and own_tests["language"] == "python"
    installed = _write(tmp_path / "installed", {"node_modules/package.json": json.dumps({"scripts": {"test": "jest"}})})
    assert sandbox.detect(installed)["supported"] is False            # a package that was installed is not the project


@only_posix
def test_a_signing_key_counts_only_when_the_key_file_is_the_projects_own(tmp_path, monkeypatch):
    """`LM-SIGNING-SECRET` says more, and ranks higher, when the key file is in the repository too. A link that
    leads out of the project is not the project's key file, whether or not a file is at its other end; neither is a
    debug key, or a key under a build folder."""
    _without_bandit(monkeypatch)
    word, value = "store" + "Password", "s3cr" + "et-store"
    files = {"app/build.gradle": f'android {{\n  signingConfigs {{\n    release {{\n      {word} "{value}"\n    }}\n  }}\n}}\n',
             "app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                                                 'package="a.b"><application android:allowBackup="false"/></manifest>'}
    said = {}
    for how in ("none", "own", "debug", "built", "link to a file", "link to nothing"):
        repo = _write(tmp_path / how / "project", files)
        outside = _write(tmp_path / how / "outside", {"kept.jks": "not really a key"})
        if how == "own":
            _write(repo, {"app/release.jks": "not really a key"})
        elif how == "debug":
            _write(repo, {"app/debug.keystore": "not really a key"})
        elif how == "built":
            _write(repo, {"app/build/release.jks": "not really a key"})
        elif how != "none":
            os.symlink(outside / ("kept.jks" if how == "link to a file" else "nowhere.jks"), repo / "app" / "release.jks")
        sec = json.loads((_analyze(repo) / "security.json").read_text(encoding="utf-8"))
        said[how] = [f["category"] for f in sec["findings"] if f["rule"] == "LM-SIGNING-SECRET"]
    assert said == {"none": ["exposure"], "own": ["secret"], "debug": ["exposure"], "built": ["exposure"],
                    "link to a file": ["exposure"], "link to nothing": ["exposure"]}


def test_a_very_large_android_file_is_not_read(tmp_path, monkeypatch):
    from lantern import android
    repo = _write(tmp_path / "project", {"at.xml": "x" * 50, "over.xml": "x" * 51})
    monkeypatch.setattr(android, "MAX_XML", 50)
    assert android._read(repo / "at.xml", repo) == "x" * 50 and android._read(repo / "over.xml", repo) == ""
    assert android._read(repo / "none.xml", repo) == ""


@only_posix
@pytest.mark.parametrize("leads_to", ["a file", "nothing"])
def test_a_dependency_file_that_is_a_link_is_named_in_the_same_words_whatever_it_leads_to(leads_to, tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    outside = _write(tmp_path / "outside", {"reqs.txt": "flask==2.0.1\n"})
    os.symlink(outside / ("reqs.txt" if leads_to == "a file" else "nowhere.txt"), repo / "requirements.txt")
    _findings, info = depaudit.run_pip_audit(repo, True)
    assert info["state"] == "partial", info
    assert info["errors"] == ["requirements.txt: a link that does not lead to a file of the project, so it was not read"]


@only_posix
def test_a_dependency_file_that_is_a_link_inside_the_project_is_read(tmp_path):
    repo = _write(tmp_path / "project", {"reqs/base.txt": "flask==2.0.1\n"})
    os.symlink(repo / "reqs" / "base.txt", repo / "requirements.txt")
    pins, _unpinned, _files = depaudit.python_pins(repo)
    assert pins["flask"][0] == "2.0.1"


@only_posix
def test_a_lock_file_that_is_a_link_out_of_the_project_is_no_lock_file_for_npm(tmp_path):
    """npm reads package-lock.json itself, and would send the names in somebody else's file to the registry."""
    lock = json.dumps({"name": "x", "lockfileVersion": 3, "packages": {}})
    own = _write(tmp_path / "own", {"package.json": "{}", "package-lock.json": lock})
    assert depaudit.run_npm_audit(own, True)[1]["why"] == "offline"
    linked = _write(tmp_path / "linked", {"package.json": "{}"})
    os.symlink(_write(tmp_path / "outside", {"l.json": lock}) / "l.json", linked / "package-lock.json")
    assert depaudit.run_npm_audit(linked, True)[1]["why"].startswith("no package-lock.json")


@only_posix
def test_links_that_name_each_other_do_not_stop_the_analysis(tmp_path, monkeypatch):
    """`a.ts -> b.ts -> a.ts`, a folder that is a link to itself, a Python file that is a link to itself, and
    imports that mention each. Python 3.11 and 3.12 raise an error of their own when such a path is followed
    (`Path.resolve`), and an import of `./a` stopped the whole analysis there; 3.13 does not raise."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {
        "package.json": '{"name": "x"}', "app.py": "from loop import x\n",
        "src/index.ts": "import { a } from './a'\nimport { b } from './dir/x'\nimport { ok } from './ok'\n"
                        "export function main() { return a() + b() + ok() }\n",
        "src/ok.ts": "export function ok() { return 1 }\n"})
    os.symlink("b.ts", repo / "src" / "a.ts")
    os.symlink("a.ts", repo / "src" / "b.ts")
    os.symlink("dir", repo / "src" / "dir")
    os.symlink("loop.py", repo / "loop.py")
    g = Graph.load(_analyze(repo, tmp_path / "out") / "graph.json", repo)
    assert "js:src/ok::ok" in {e.dst for e in g.call_edges()}          # the twin: the import beside them is followed


def test_an_import_whose_path_cannot_be_followed_is_an_import_of_nothing(tmp_path, monkeypatch):
    """The same on every Python: following the path raises what 3.11 and 3.12 raise for a loop of links."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"package.json": '{"name": "x"}', "src/ok.ts": "export function ok() { return 1 }\n",
                                         "src/index.ts": "import { a } from './a'\nimport { ok } from './ok'\n"
                                                         "export function main() { return a() + ok() }\n"})
    real = Path.resolve

    def resolve(self, strict=False):
        if self.name.startswith("a"):
            raise RuntimeError(f"Symlink loop from {str(self)!r}")
        return real(self, strict)
    monkeypatch.setattr(Path, "resolve", resolve)
    g = Graph.load(_analyze(repo, tmp_path / "out") / "graph.json", repo)
    assert "js:src/ok::ok" in {e.dst for e in g.call_edges()}


# ---------------------------------------------------------------------------- 3. where the project is

def _project_that_names_another_folder(tmp_path: Path, monkeypatch, more: str = "") -> tuple[Path, Path, Path]:
    """An analysed project whose saved map says the project is the folder `other`: what a project that brings its
    own `.lantern/` can say. `other` holds the same file names with a private line, and a notes file. `more` is
    code that goes under both files' function."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP + more})
    other = _write(tmp_path / "other", {"app.py": OTHER + more, "lantern-narratives.md": f"# Notes\n\n{PRIVATE}\n"})
    out = _analyze(repo)
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert os.path.samefile(g["repo_root"], repo)
    g["repo_root"] = str(other)
    (out / "graph.json").write_text(json.dumps(g), encoding="utf-8")
    return repo, other, out


def _everything(out: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(out.iterdir()) if p.is_file())


def test_the_report_shows_the_lines_of_the_project_it_was_asked_about(tmp_path, monkeypatch, capsys):
    repo, _other, out = _project_that_names_another_folder(tmp_path, monkeypatch)
    (out / "report.html").unlink()
    assert main(["report", str(repo)]) == 0
    capsys.readouterr()
    report = (out / "report.html").read_text(encoding="utf-8")
    assert PRIVATE not in report
    assert OWN in report                                               # the twin: its own lines are shown


def test_the_evidence_report_reads_the_notes_of_the_project_it_was_asked_about(tmp_path, monkeypatch, capsys):
    repo, _other, out = _project_that_names_another_folder(tmp_path, monkeypatch)
    assert main(["evidence", str(repo)]) == 0
    capsys.readouterr()
    assert PRIVATE not in _everything(out)
    _write(repo, {"lantern-narratives.md": "# Notes\n\nthe project's own notes\n"})      # the twin
    assert main(["evidence", str(repo)]) == 0
    capsys.readouterr()
    assert "the project's own notes" in (out / "evidence.json").read_text(encoding="utf-8")


def test_the_model_is_sent_the_lines_of_the_project_it_was_asked_about(tmp_path, monkeypatch):
    repo, _other, out = _project_that_names_another_folder(tmp_path, monkeypatch)
    provider = FixtureProvider(lambda system, user: "{}")
    assert pipeline.plan_explain(out, repo, only=["py:app.run"])["nodes"] == ["py:app.run"]
    pipeline.explain(out, repo, provider, ["py:app.run"])
    sent = "\n".join(user for _system, user in provider.calls)
    assert provider.calls and PRIVATE not in sent
    assert OWN in sent                                                  # the twin: the project's own lines go out
    assert PRIVATE not in _everything(out)


def test_explain_plans_the_function_it_was_asked_for_in_the_folder_it_was_given(tmp_path, monkeypatch, capsys):
    """`lantern explain --node X` plans X alone, read in the folder on the command line. (The line that hands the
    folder over also hands over `--node`, and until 2026-11-10 no test tried that option.)"""
    repo, _other, _out = _project_that_names_another_folder(tmp_path, monkeypatch)
    assert main(["explain", str(repo), "--node", "app.run", "--estimate"]) == 0
    assert "plan    1 functions" in capsys.readouterr().out
    assert main(["explain", str(repo), "--node", "app.no_such_function", "--estimate"]) == 0
    assert "plan    0 functions" in capsys.readouterr().out


TABLE = "create table notes (id int);\n"
USES_SUPABASE = '{"dependencies": {"@supabase/supabase-js": "2"}}'
SETUP_CFG = "[options.entry_points]\nconsole_scripts =\n    tool = app:run\n"


@only_posix
def test_a_table_is_supabases_when_the_projects_own_package_file_says_so(tmp_path):
    """A table with no row-level security is a finding in a project that uses Supabase, and its package.json is
    what says so (when it has no `supabase/` folder)."""
    from lantern import websec
    own = _write(tmp_path / "own", {"package.json": USES_SUPABASE, "db/schema.sql": TABLE})
    another = _write(tmp_path / "another", {"package.json": '{"dependencies": {"react": "18"}}', "db/schema.sql": TABLE})
    linked = _write(tmp_path / "linked", {"db/schema.sql": TABLE})
    os.symlink(_write(tmp_path / "outside", {"p.json": USES_SUPABASE}) / "p.json", linked / "package.json")
    assert [f["rule"] for f in websec.database_rules(own)] == ["LW-NO-RLS"]         # the twin
    assert websec.database_rules(another) == []
    assert websec.database_rules(linked) == []


@only_posix
def test_a_script_is_an_entry_point_when_the_projects_own_setup_file_names_it(tmp_path):
    from lantern import engine
    own = _write(tmp_path / "own", {"app.py": APP, "setup.cfg": SETUP_CFG})
    without = _write(tmp_path / "without", {"app.py": APP})
    linked = _write(tmp_path / "linked", {"app.py": APP})
    os.symlink(_write(tmp_path / "outside", {"s.cfg": SETUP_CFG}) / "s.cfg", linked / "setup.cfg")
    assert engine.build_graph(own).nodes["py:app.run"].entry == {"kind": "script", "detail": "tool"}     # the twin
    assert engine.build_graph(without).nodes["py:app.run"].entry is None
    assert engine.build_graph(linked).nodes["py:app.run"].entry is None


STARTS_ITSELF = "\n\nif __name__ == '__main__':\n    run()\n"      # an entry point, so a plan with nothing asked has work
ALL_OF_IT = ["py:app.run", "py:app.<main>"]


@pytest.fixture
def the_app(tmp_path, monkeypatch):
    """`lantern serve` on this computer with a stand-in for the model. `post(path, body)` asks as the page does and
    `finish(job)` waits for the job; both give the job as it ended."""
    import urllib.request
    from http.server import ThreadingHTTPServer
    from types import SimpleNamespace

    from lantern.server import Handler
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    provider = FixtureProvider(lambda system, user: "{}")
    monkeypatch.setattr(App, "make_provider", lambda self: provider)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    app = App(Store(tmp_path / "home"), "tok-123", httpd.server_address[1])
    monkeypatch.setattr(Handler, "app", app, raising=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def finish(job: dict) -> dict:
        end = time.time() + 60
        while app.jobs.jobs[job["id"]]["status"] == "running" and time.time() < end:
            time.sleep(0.02)
        return app.jobs.jobs[job["id"]]

    def post(path: str, body: dict) -> dict:
        req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}{path}", method="POST",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers={"Cookie": "lantern_token=tok-123", "X-Lantern-Token": "tok-123"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return finish(json.loads(r.read()))
    yield SimpleNamespace(app=app, provider=provider, post=post, finish=finish)
    httpd.shutdown()
    httpd.server_close()


def _watched(monkeypatch) -> dict:
    """What the app hands to the plan and to the explanation, while both still do their work. The folder is not
    looked at here: what the model is sent tells which folder was read."""
    seen: dict = {"plans": [], "explained": []}
    plan, explain = pipeline.plan_explain, pipeline.explain

    def planned(*a, **kw):
        got = plan(*a, **kw)
        seen["plans"].append((tuple(a[-2:]), got["nodes"]))
        return got

    def explained(*a, **kw):
        seen["explained"].append((list(a[-1]), kw.get("fresh")))
        return explain(*a, **kw)
    monkeypatch.setattr(pipeline, "plan_explain", planned)
    monkeypatch.setattr(pipeline, "explain", explained)
    return seen


def test_the_apps_explain_button_reads_the_project_it_was_asked_about(the_app, tmp_path, monkeypatch):
    """The button hands the plan the folder of the project in the app's list. With nothing else asked the plan is
    three levels below the entry points and forty functions at most, and "again from nothing" (`fresh`) counts only
    for functions that were named."""
    repo, _other, out = _project_that_names_another_folder(tmp_path, monkeypatch, STARTS_ITSELF)
    pid = the_app.app.store.add_project(repo)["id"]
    seen = _watched(monkeypatch)
    for body in ({}, {"depth": 1, "limit": 1, "fresh": True}, {"nodes": ["py:app.run"], "fresh": True}):
        job = the_app.post(f"/api/projects/{pid}/explain", body)
        assert job["status"] == "done", job["error"]
    assert seen["plans"] == [((3, 40), ALL_OF_IT), ((1, 1), ["py:app.run"])]
    assert seen["explained"] == [(ALL_OF_IT, False), (["py:app.run"], False), (["py:app.run"], True)]
    sent = "\n".join(user for _system, user in the_app.provider.calls)
    assert the_app.provider.calls and PRIVATE not in sent
    assert OWN in sent                                                  # the twin: the project's own lines go out
    assert PRIVATE not in _everything(out)


def test_the_apps_explain_command_reads_the_project_it_was_asked_about(the_app, tmp_path, monkeypatch):
    """The same for `explain` typed in the app's own command drawer."""
    from lantern.server import run_terminal_command
    repo, _other, out = _project_that_names_another_folder(tmp_path, monkeypatch, STARTS_ITSELF)
    p = the_app.app.store.add_project(repo)
    seen = _watched(monkeypatch)
    for argv in (["explain"], ["explain", "--depth", "1", "--max-nodes", "1", "--fresh"],
                 ["lantern", "explain", "--node", "py:app.run", "--fresh"]):
        job = the_app.finish(run_terminal_command(the_app.app, p, repo, out, argv)["job"])
        assert job["status"] == "done", job["error"]
    assert seen["plans"] == [((3, 40), ALL_OF_IT), ((1, 1), ["py:app.run"])]
    assert seen["explained"] == [(ALL_OF_IT, False), (["py:app.run"], False), (["py:app.run"], True)]
    sent = "\n".join(user for _system, user in the_app.provider.calls)
    assert the_app.provider.calls and PRIVATE not in sent
    assert OWN in sent                                                  # the twin
    assert PRIVATE not in _everything(out)


def test_a_plan_with_nothing_asked_is_three_levels_and_forty_functions(tmp_path):
    """`plan_explain`'s own word when its caller names no depth and no number (the line that takes the project
    folder carries both, and until 2026-11-10 no test held them)."""
    from lantern.graph import Node
    repo = _write(tmp_path / "project", {"app.py": "\n"})
    out = repo / ".lantern"
    out.mkdir()
    g = Graph(str(repo))

    def fn(name: str, entry: dict | None = None) -> None:
        g.add_node(Node(f"py:app.{name}", "callable", name, f"app.{name}", "app.py", 1, 1, entry=entry))
    fn("f0", {"kind": "main", "detail": "f0"})
    for i in range(1, 6):                                               # f0 calls f1, which calls f2, … f5
        fn(f"f{i}")
        g.add_edge(f"py:app.f{i - 1}", f"py:app.f{i}")
    g.save(out / "graph.json")
    assert pipeline.plan_explain(out, repo)["nodes"] == [f"py:app.f{i}" for i in (3, 2, 1, 0)]
    for i in range(45):
        fn(f"e{i:02d}", {"kind": "main", "detail": "one of many"})
    g.save(out / "graph.json")
    assert len(pipeline.plan_explain(out, repo)["nodes"]) == 40
    assert len(pipeline.plan_explain(out, repo, limit=None)["nodes"]) == 49


def test_a_saved_map_is_loaded_for_the_folder_its_caller_names(tmp_path, monkeypatch):
    repo, other, out = _project_that_names_another_folder(tmp_path, monkeypatch)
    assert Graph.load(out / "graph.json", repo).repo_root == str(repo)
    assert Graph.load(out / "graph.json").repo_root == str(other)       # read for what it holds: the file's own word


def test_every_loader_of_a_saved_map_says_which_folder_it_means():
    """In `lantern/`, a map is loaded with the project folder beside it. A `Graph.load(path)` alone would go on to
    read wherever the file says the project is."""
    alone = []
    for path in sorted((ROOT / "lantern").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "load"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "Graph"
                    and len(node.args) + len(node.keywords) < 2):
                alone.append(f"{path.name}:{node.lineno}")
    assert not alone, alone


@pytest.mark.parametrize("how", ["dots", "whole path"])
def test_a_function_whose_saved_file_lies_outside_the_project_has_no_lines(how, tmp_path, monkeypatch, capsys):
    """The saved map also says, per function, which file holds it."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP})
    other = _write(tmp_path / "other", {"app.py": OTHER})
    out = _analyze(repo)
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    moved = 0
    for n in g["nodes"]:
        if n.get("file") == "app.py":
            n["file"] = "../other/app.py" if how == "dots" else str(other / "app.py")
            moved += 1
    assert moved
    (out / "graph.json").write_text(json.dumps(g), encoding="utf-8")
    assert main(["report", str(repo)]) == 0
    capsys.readouterr()
    assert PRIVATE not in (out / "report.html").read_text(encoding="utf-8")
    from lantern.mcp_server import Projects, tool_explain
    told = tool_explain(Projects(extra=[str(repo)]), {"project": str(repo), "target": "run"})
    assert PRIVATE not in json.dumps(told)
    provider = FixtureProvider(lambda system, user: "{}")
    pipeline.explain(out, repo, provider, ["py:app.run"])
    assert provider.calls and PRIVATE not in "\n".join(user for _system, user in provider.calls)


# ---------------------------------------------------------------------------- 2. result files, read back

SCAN = {"findings": [{"id": "f1", "rule": "X", "title": PRIVATE, "file": "a.py", "line": 1, "rank": "critical"}],
        "counts": {"critical": 1}, "tools": []}
READY = {"score": 97, "grade": "A", "shape": PRIVATE, "categories": []}


def _linked_results(tmp_path: Path, monkeypatch, name: str, holds: dict | str, state: str = "link") -> tuple[Path, Path]:
    """An analysed project whose result file `name` is a link to a file outside it that holds `holds`, or a pipe."""
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP})
    out = _analyze(repo)
    (out / name).unlink()
    if state == "pipe":
        os.mkfifo(out / name)
    else:
        text = holds if isinstance(holds, str) else json.dumps(holds)
        os.symlink(_write(tmp_path / "outside", {"kept": text}) / "kept", out / name)
    return repo, out


@only_posix
@pytest.mark.parametrize("state", ["link", "pipe"])
def test_a_command_about_a_result_refuses_one_that_is_not_a_plain_file(state, tmp_path, monkeypatch, capsys):
    repo, out = _linked_results(tmp_path, monkeypatch, "security.json", SCAN, state)
    before = (out / "report.html").read_bytes()
    for command in ("report", "evidence"):
        assert _in_time(lambda command=command: main([command, str(repo)]), out / "security.json") == 2
        said = capsys.readouterr()
        assert "security.json was not read" in said.err and PRIVATE not in said.err + said.out
    assert (out / "report.html").read_bytes() == before and PRIVATE not in _everything_but(out, "security.json")
    with pytest.raises(results.Refused):
        _in_time(lambda: pipeline.load(out, "security.json"), out / "security.json")
    from lantern.mcp_server import Projects, tool_findings
    with pytest.raises(results.Refused):
        _in_time(lambda: tool_findings(Projects(extra=[str(repo)]), {"project": str(repo)}), out / "security.json")


def _everything_but(out: Path, name: str) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(out.iterdir())
                     if p.is_file() and not p.is_symlink() and p.name != name)


@only_posix
@pytest.mark.parametrize("state", ["link", "pipe"])
def test_a_saved_map_that_is_not_a_plain_file_is_refused(state, tmp_path, monkeypatch, capsys):
    repo, out = _linked_results(tmp_path, monkeypatch, "graph.json", {"repo_root": "/", "nodes": [], "edges": []}, state)
    with pytest.raises(results.Refused):
        _in_time(lambda: Graph.load(out / "graph.json", repo), out / "graph.json")
    assert _in_time(lambda: main(["report", str(repo)]), out / "graph.json") == 2
    assert "graph.json was not read" in capsys.readouterr().err


def test_a_plain_result_file_is_read_as_before_and_a_missing_one_is_nothing(tmp_path, monkeypatch, capsys):
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP})
    out = _analyze(repo)
    assert pipeline.load(out, "security.json")["tools"] and pipeline.load(out, "nothing.json") is None
    assert results.table(out / "readiness.json")["grade"] and results.text(out / "nothing.json") is None
    with pytest.raises(FileNotFoundError):
        Graph.load(out / "nothing.json", repo)
    (out / "broken.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValueError):                                     # read strictly: never "nothing"
        pipeline.load(out, "broken.json")
    assert main(["report", str(repo)]) == 0 and main(["evidence", str(repo)]) == 0
    capsys.readouterr()


@only_posix
@pytest.mark.parametrize("state", ["link", "pipe"])
def test_the_app_shows_nothing_from_a_result_file_that_is_not_a_plain_file(state, tmp_path, monkeypatch):
    """The project cards, Ask Lantern and the Learn steps go on without a file they cannot use."""
    repo, out = _linked_results(tmp_path, monkeypatch, "readiness.json", READY, state)
    pipe = out / "readiness.json"
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    app = App(Store(tmp_path / "home"), "tok", 0)
    card = _in_time(lambda: app.summary(app.store.add_project(repo)), pipe)
    assert card.get("grade") is None and PRIVATE not in json.dumps(card)
    assert PRIVATE not in _in_time(lambda: ask.facts(repo), pipe)
    assert _in_time(lambda: learn._load(pipe), pipe) is None and _in_time(lambda: ask._load(pipe), pipe) is None
    for name in ("readiness.json", "badge.svg"):
        code, body, _ctype, _headers = _in_time(lambda name=name: result_page(out, name, None), pipe)
        assert PRIVATE not in body and '"A"' not in body and ">A<" not in body, (name, code)


def test_the_app_reads_a_plain_result_file_as_before(tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP})
    out = _analyze(repo)
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    app = App(Store(tmp_path / "home"), "tok", 0)
    grade = json.loads((out / "readiness.json").read_text(encoding="utf-8"))["grade"]
    assert app.summary(app.store.add_project(repo))["grade"] == grade
    assert "Readiness:" in ask.facts(repo) and learn._load(out / "readiness.json")["grade"] == grade
    assert result_page(out, "report.html", None)[0] == 200 and result_page(out, "readiness.json", None)[0] == 200


@only_posix
@pytest.mark.parametrize("state", ["link", "pipe"])
def test_a_report_page_is_not_built_from_a_file_that_is_not_a_plain_file(state, tmp_path, monkeypatch):
    _without_bandit(monkeypatch)
    donor = _analyze(_write(tmp_path / "donor" / "project", {"app.py": OTHER})) / "report.html"
    assert PRIVATE in donor.read_text(encoding="utf-8")
    repo, out = _linked_results(tmp_path, monkeypatch, "report.html", donor.read_text(encoding="utf-8"), state)
    code, body, _ctype, _headers = _in_time(lambda: result_page(out, "report.html", None), out / "report.html")
    assert code == 409 and PRIVATE not in body
    why = {"link": "it is a link", "pipe": "it is not a plain file"}[state]
    with pytest.raises(ValueError, match=f"report.html was not read: {why}"):
        _in_time(lambda: read_bundle(out / "report.html"), out / "report.html")
    with pytest.raises(ValueError, match="report.html was not read: it is not there; analyze again"):
        read_bundle(out / "no-such.html")                               # and one that is not there says that
    assert read_bundle(donor)["graph"]                                  # the twin: a plain report gives its data


@only_posix
@pytest.mark.parametrize("state", ["link", "pipe"])
def test_verify_does_not_take_a_digest_from_a_report_that_is_not_a_plain_file(state, tmp_path, monkeypatch, capsys):
    _without_bandit(monkeypatch)
    repo = _write(tmp_path / "project", {"app.py": APP})
    out = _analyze(repo)
    want, payload = evidence.read_digest(out / "evidence.html")         # the twin: the plain report names its digest
    assert want and want.startswith("sha256:") and isinstance(payload, dict)
    assert evidence.read_digest(out / "evidence.json")[0] == want
    kept = (out / "evidence.json").read_text(encoding="utf-8")
    for name in ("evidence.html", "evidence.json"):
        (out / name).unlink()
    if state == "pipe":
        os.mkfifo(out / "evidence.html")
        os.mkfifo(out / "evidence.json")
    else:
        os.symlink(_write(tmp_path / "outside", {"e.json": kept}) / "e.json", out / "evidence.html")
        os.symlink(tmp_path / "outside" / "e.json", out / "evidence.json")
    why = {"link": "it is a link", "pipe": "it is not a plain file"}[state]
    for name in ("evidence.html", "evidence.json"):
        with pytest.raises(results.Refused, match=f"{name} was not read: {why}"):
            _in_time(lambda name=name: evidence.read_digest(out / name), out / name)
    assert _in_time(lambda: main(["verify", str(repo), "--report", str(out / "evidence.html"), "--offline"]), out / "evidence.html") == 2
    assert f"evidence.html was not read: {why}" in capsys.readouterr().err
    with pytest.raises(results.Refused, match="no-such.html was not read: it is not there"):
        evidence.read_digest(out / "no-such.html")                      # and a report that is not there says that


@only_posix
def test_what_the_tests_left_as_their_record_is_read_only_as_a_plain_file(tmp_path):
    """The tests of a project run in the folder that holds the record of their calls, and could put anything under
    its name."""
    record = {"pairs": [{"caller": ["a.py", 1, "f", 2], "callee": ["a.py", 4, "g", 4], "count": 1}]}
    plain = _write(tmp_path, {"trace.json": json.dumps(record)}) / "trace.json"
    assert sandbox._recorded(plain) == record
    os.symlink(plain, tmp_path / "linked.json")
    os.mkfifo(tmp_path / "pipe.json")
    nothing = {"pairs": []}
    assert sandbox._recorded(tmp_path / "linked.json") == nothing
    assert _in_time(lambda: sandbox._recorded(tmp_path / "pipe.json"), tmp_path / "pipe.json", 10) == nothing
    assert sandbox._recorded(tmp_path / "nothing.json") == nothing
    for odd in ("[1, 2]", "{", '{"pairs": 7}', '{"pairs": null}'):
        assert sandbox._recorded(_write(tmp_path, {"odd.json": odd}) / "odd.json") == nothing, odd


def test_a_record_of_calls_keeps_only_rows_of_the_recorders_shape(tmp_path, monkeypatch):
    """The record is written inside the program that was traced. A row of another shape ended "Watch my tests
    run" with a Python error."""
    from lantern.trace import merge_trace, well_formed
    _without_bandit(monkeypatch)
    good = {"caller": [str(tmp_path / "app.py"), 1, "run", 2], "callee": [str(tmp_path / "app.py"), 5, "helper", 5], "count": 3}
    odd = [1, "x", None, [], {}, {"caller": 1, "callee": 2}, {"caller": ["a.py", 1, "f"], "callee": ["a.py", 1, "g", 1]},
           {"caller": [7, 1, "f", 1], "callee": ["a.py", 1, "g", 1]}, {"caller": ["a.py", 1, "f", "2"], "callee": ["a.py", 1, "g", 1]},
           {"caller": ["a.py", 1, "f", True], "callee": ["a.py", 1, "g", 1]}, {"callee": ["a.py", 1, "g", 1]}]
    assert well_formed({"pairs": [*odd, good]}) == {"pairs": [good]}
    for whole in (None, 7, [], "x", {"pairs": 7}, {"pairs": {"caller": 1}}, {}):
        assert well_formed(whole) == {"pairs": []}
    record = _write(tmp_path, {"trace.json": json.dumps({"pairs": [*odd, good]})}) / "trace.json"
    data = sandbox._recorded(record)
    sandbox._map_pairs(data, str(tmp_path), tmp_path)                  # neither of the two readers of a record
    repo = _write(tmp_path / "project", {"app.py": "def helper():\n    return 1\n\n\ndef run():\n    return helper()\n"})
    g = Graph.load(_analyze(repo) / "graph.json", repo)
    merge_trace(g, data)                                               # stops at what a traced program wrote


@only_posix
def test_the_note_of_what_a_clone_left_out_is_read_only_as_a_plain_file(tmp_path):
    note = json.dumps({"files": 3, "mb": 12, "examples": ["a.bin"]})
    own = _write(tmp_path / "own", {f".git/{remote.SKIPPED}": note})
    assert remote.skipped(own)["files"] == 3
    linked = tmp_path / "linked"
    (linked / ".git").mkdir(parents=True)
    os.symlink(own / ".git" / remote.SKIPPED, linked / ".git" / remote.SKIPPED)
    assert remote.skipped(linked) is None
    piped = tmp_path / "piped"
    (piped / ".git").mkdir(parents=True)
    os.mkfifo(piped / ".git" / remote.SKIPPED)
    assert _in_time(lambda: remote.skipped(piped), piped / ".git" / remote.SKIPPED, 10) is None
    assert remote.skipped(tmp_path) is None
