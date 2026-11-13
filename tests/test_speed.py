"""Directive point 10: faster, with no check dropped and no less code read.

Every speed-up stands beside the proof that it changes nothing:

    one walk of the folder per run      what each reader lists is what it listed when it walked by itself, in the
                                        same order; outside a run nothing is kept; a file is still asked about at
                                        the moment it is opened
    scanners started with the run       the same findings and records as when one ran after the other; a run that
                                        fails or stops leaves none of them going; where the project's own tests run
                                        in its folder, every scanner still comes after them
    the map's names looked up once      the same handlers as the search through every node gave
    the map saved field by field        exactly what `dataclasses.asdict` gave, and still a copy
    a pattern left out for a file       only for text it cannot match: every line a pattern matches is in a text
                                        that is still searched, and the checks find the same with and without

The measurement itself is `bench/speed.py`; its pure parts are tested at the end.
"""
import fnmatch
import json
import os
import re
import shutil
import sys
import threading
import time
import types
from dataclasses import asdict
from pathlib import Path

import pytest

from lantern import (aiapp, context, depaudit, listing, packs, php_frontend, pipeline, quick, readiness, remote,
                     scanresult, security, websec)
from lantern.graph import Edge, Graph, Node, edge_dict, node_dict
from lantern.python_frontend import inside_repo, skipped

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
import speed  # noqa: E402  (bench/speed.py)

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "old_results")
QUIET = lambda line: None  # noqa: E731


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


# A folder with everything the listing has to tell apart: code, a library folder, an environment named `env` beside
# a folder named `env` that is the project's own, built files, a pack folder, a file named like a folder left out.
TREE = {
    "app.py": "import os\n",
    "web/src/a.ts": "export const a = 1\n",
    "web/src/a.min.js": "var a=1\n",
    "web/src/types.d.ts": "export {}\n",
    "web/package.json": "{}\n",
    "web/package-lock.json": "{}\n",
    "web/node_modules/x/index.js": "module.exports = 1\n",
    "env/pyvenv.cfg": "home = /usr\n",
    "env/lib/site.py": "x = 1\n",
    "config/env/settings.py": "DEBUG = False\n",
    "config/settings_local.py": "DEBUG = True\n",
    ".env": "A=1\n",
    ".env.local": "B=2\n",
    "lantern-packs/mine.json": "{}\n",
    "deep/a/b/c/d.py": "y = 2\n",
    "vendor/lib.php": "<?php\n",
    "pages/index.html": "<p>hello</p>\n",
    "requirements.txt": "flask==3.0.0\n",
    "api/requirements.txt": "requests==2.32.0\n",
    "api/requirements-dev.txt": "pytest==8.0.0\n",
    "tests/requirements.txt": "responses==0.25.0\n",
    "examples/demo/package.json": "{}\n",
    "web/node_modules/x/package.json": "{}\n",
    "env/requirements.txt": "six==1.16.0\n",
    "config/env/requirements.txt": "attrs==24.1.0\n",
    "pyproject.toml": "[project]\nname = 'p'\n",
    "api/Gemfile": "gem 'rails'\n",
}


def _tree(tmp_path: Path) -> Path:
    repo = _write(tmp_path / "project", TREE)
    outside = _write(tmp_path / "outside", {"secret.py": "KEY = 1\n", "folder/more.py": "z = 3\n"})
    try:    # a link that leads out of the project, and a folder that is such a link: never the project's files
        os.symlink(outside / "secret.py", repo / "linked.py")
        os.symlink(outside / "folder", repo / "linked_folder", target_is_directory=True)
    except OSError:     # Windows without the right to make links: the rest of the tree is still told apart
        pass
    return repo


# ---------------------------------------------------------------------------------------------- the old way, kept
def _web_files_before(repo: Path, exts=None, names=None):
    """`websec._files` as it was until 2026-11-12: a walk of its own for every call."""
    for p in repo.rglob("*"):
        if not p.is_file() or not inside_repo(p, repo):
            continue
        parts = p.relative_to(repo).parts
        if skipped(parts[:-1], repo):
            continue
        if p.name.endswith((".min.js", ".map", ".d.ts")) or p.name in ("package-lock.json", "bun.lock"):
            continue
        if (exts and p.suffix in exts) or (names and (p.name in names or any(p.name.startswith(n) for n in names))):
            yield p


def _pack_files_before(repo: Path, globs: list[str]):
    """`packs._files` as it was until 2026-11-12."""
    pats = []
    for gl in globs:
        gl = gl.replace("\\", "/")
        pats.append(gl)
        if not gl.startswith("**/") and "/" not in gl:
            pats.append("**/" + gl)
    for p in repo.rglob("*"):
        if not p.is_file() or not inside_repo(p, repo):
            continue
        rel = p.relative_to(repo)
        if skipped(rel.parts[:-1], repo) or packs.PROJECT_DIR in rel.parts[:-1]:
            continue
        rp = rel.as_posix()
        if any(fnmatch.fnmatchcase(rp, pat) or fnmatch.fnmatchcase(rp, pat.removeprefix("**/")) for pat in pats):
            yield p


def _dependency_files_before(repo: Path, names=None, pattern=None):
    """`depaudit._project_files` as it was until 2026-11-12: a walk of its own for every call, twelve in a run."""
    from lantern.python_frontend import skipped_dir
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if not skipped_dir(dirpath, d) and d != "node_modules"]
        for fn in filenames:
            if (names and fn in names) or (pattern and pattern.search(fn)):
                p = Path(dirpath) / fn
                rel = p.relative_to(repo).as_posix()
                if not depaudit.TEST_DIR_RE.search(rel):
                    out.append(p)
    return sorted(out)


DEPENDENCY_ASKS = [(("uv.lock", "poetry.lock", "pdm.lock"), None), (("pyproject.toml",), None), (("package.json",), None),
                   (None, re.compile(r"^requirements[^/]*\.txt$")), (("Gemfile", "Gemfile.lock"), None),
                   (("linked.py", "secret.py", "more.py"), None), (("package.json",), re.compile(r"\.toml$"))]
WEB_ASKS = [({".py"}, None), ({".ts", ".js", ".json"}, None), ({".html"}, (".env",)), (None, (".env", "requirements")),
            ({".php", ".py", ".ts"}, ("package.json",))]
PACK_ASKS = [["*.py"], ["**/settings*.py", "settings*.py"], ["requirements.txt", "*/requirements.txt"], ["*.json"],
             ["web/**"], ["deep/a/*/c/d.py"], ["*.html", "*.php"]]


@pytest.mark.parametrize("in_a_run", [False, True])
def test_every_reader_lists_what_it_listed_before_in_the_same_order(tmp_path, in_a_run):
    repo = _tree(tmp_path)

    def compare():
        for exts, names in WEB_ASKS:
            assert list(websec._files(repo, exts, names)) == list(_web_files_before(repo, exts, names)), (exts, names)
        for globs in PACK_ASKS:
            assert list(packs._files(repo, globs)) == list(_pack_files_before(repo, globs)), globs
        for names, pattern in DEPENDENCY_ASKS:
            was = _dependency_files_before(repo, names, pattern)
            assert depaudit._project_files(repo, names=names, pattern=pattern) == was, (names, pattern)
            assert [type(x) for x in depaudit._project_files(repo, names=names, pattern=pattern)] == [type(x) for x in was]

    if in_a_run:
        with listing.one_run(repo):
            compare()
            compare()       # and again from what the run kept
    else:
        compare()
    names = {"/".join(parts) for _, parts in listing.files(repo)}
    assert {"app.py", "config/env/settings.py", ".env", "deep/a/b/c/d.py", "lantern-packs/mine.json"} <= names
    # left out as before: libraries, the environment (not the project's own folder of that name), a link that leads out
    assert not {n for n in names if n.startswith(("web/node_modules/", "env/", "vendor/", "linked"))}, names


def test_the_folder_is_walked_once_for_a_run_and_every_time_outside_one(tmp_path, monkeypatch):
    repo = _tree(tmp_path)
    walks = []
    real = listing._walk
    monkeypatch.setattr(listing, "_walk", lambda folder: (walks.append(folder), real(folder))[1])

    def ask():
        list(websec._files(repo, {".py"}))
        list(packs._files(repo, ["*.py"]))
        security._builtin_secrets(repo)

    ask()
    assert len(walks) == 3          # nobody said a run is under way: each reader looks for itself, as before
    del walks[:]
    with listing.one_run(repo):
        ask()
        ask()
        assert len(walks) == 1
        assert listing.going(repo)
    assert not listing.going(repo)
    ask()
    assert len(walks) == 4          # the run is over: nothing was kept


def test_outside_a_run_a_new_file_is_seen_at_once_and_inside_one_after_fresh(tmp_path):
    repo = _tree(tmp_path)
    seen = lambda: {p.name for p in websec._files(repo, {".py"})}  # noqa: E731
    assert "new.py" not in seen()
    (repo / "new.py").write_text("n = 1\n", encoding="utf-8")
    assert "new.py" in seen()
    with listing.one_run(repo):
        assert "later.py" not in seen()
        (repo / "later.py").write_text("m = 1\n", encoding="utf-8")
        assert "later.py" not in seen()         # one look for the run: the folder is not expected to change in it
        listing.fresh(repo)                     # ... and where it may have (the project's tests ran), it is asked anew
        assert "later.py" in seen()


def test_two_runs_of_one_folder_share_the_list_until_the_last_ends(tmp_path, monkeypatch):
    repo = _tree(tmp_path)
    walks = []
    real = listing._walk
    monkeypatch.setattr(listing, "_walk", lambda folder: (walks.append(folder), real(folder))[1])
    with listing.one_run(repo):
        listing.files(repo)
        with listing.one_run(repo):
            listing.files(repo)
        listing.files(repo)                     # the inner run ended; the outer one still has its list
        assert len(walks) == 1
    assert not listing.going(repo)


@pytest.mark.skipif(sys.platform == "win32", reason="needs the right to make a link")
def test_a_file_is_still_asked_about_when_it_is_opened(tmp_path):
    """What a run keeps is which files there are, never that they may be read: a file that became a link out of the
    project after it was listed is not read."""
    repo = _tree(tmp_path)
    outside = tmp_path / "outside" / "secret.py"
    with listing.one_run(repo):
        listed = [p for p in websec._files(repo, {".py"}) if p.name == "app.py"]
        assert listed and websec._read(listed[0], repo) == "import os\n"
        listed[0].unlink()
        os.symlink(outside, listed[0])
        assert [p for p in websec._files(repo, {".py"}) if p.name == "app.py"] == listed    # still on the run's list
        assert websec._read(listed[0], repo) == ""                                          # and not read


# ---------------------------------------------------------------------------------------------- a whole run
SMALL = {
    "app.py": "import subprocess\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
              "@app.route('/run')\ndef run():\n    return subprocess.check_output('ls ' + request.args['d'], shell=True)\n",
    "helpers.py": "import hashlib\n\n\ndef mark(text):\n    return hashlib.md5(text.encode()).hexdigest()\n",
    "requirements.txt": "flask==3.0.0\n",
}


def test_the_library_checks_name_the_files_they_named_before(tmp_path):
    """What the asks above must tell apart is in the tree: a name is listed whatever answers to it (a link that
    leads out), not under a library folder, an environment, the tests or the examples."""
    repo = _tree(tmp_path)
    found = {p.relative_to(repo).as_posix() for p in depaudit._project_files(repo, pattern=re.compile(r"^requirements"))}
    assert found == {"requirements.txt", "api/requirements.txt", "api/requirements-dev.txt", "config/env/requirements.txt"}
    assert [p.relative_to(repo).as_posix() for p in depaudit._project_files(repo, names=("package.json",))] \
        == ["web/package.json"]
    if (repo / "linked.py").is_symlink():
        assert depaudit._project_files(repo, names=("linked.py",)) == [repo / "linked.py"]      # named, never read
        assert depaudit._project_files(repo, names=("more.py",)) == []      # a linked folder is not walked into


def test_the_library_checks_walk_the_folder_once_for_a_run(tmp_path, monkeypatch):
    repo = _tree(tmp_path)
    walks = []
    real = depaudit._names
    monkeypatch.setattr(depaudit, "_names", lambda folder: (walks.append(os.fspath(folder)), real(folder))[1])
    depaudit.python_pins(repo)
    before = len(walks)
    assert before >= 4                          # outside a run: every ask walks, as before
    (repo / "late" ).mkdir()
    (repo / "late" / "requirements.txt").write_text("late==1.0\n", encoding="utf-8")
    assert "late/requirements.txt" in depaudit.python_pins(repo)[2]     # ... and sees what is there now
    del walks[:]
    with listing.one_run(repo):
        first = depaudit.python_pins(repo)
        for _, fn in depaudit.audits():
            fn(repo, True)
        assert depaudit.python_pins(repo) == first
        assert len(walks) == 1, walks
        (repo / "later").mkdir()
        (repo / "later" / "requirements.txt").write_text("later==1.0\n", encoding="utf-8")
        listing.fresh(repo)                     # the project's tests ran: the folder is asked anew
        assert "later/requirements.txt" in depaudit.python_pins(repo)[2]
        assert len(walks) == 2, walks


def test_a_whole_run_walks_once_for_the_library_checks(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL | {"requirements.txt": "flask==3.0.0\n", "web/package.json": "{}\n"})
    walks = []
    real = depaudit._names
    monkeypatch.setattr(depaudit, "_names", lambda folder: (walks.append(os.fspath(folder)), real(folder))[1])
    for jobs in ("0", "2"):
        del walks[:]
        monkeypatch.setenv("LANTERN_JOBS", jobs)
        pipeline.analyze(repo, tmp_path / f"out{jobs}", log=QUIET, offline=True)
        assert len(walks) == 1, (jobs, walks)
    assert speed.fingerprint(tmp_path / "out0") == speed.fingerprint(tmp_path / "out2")


def test_two_threads_that_ask_at_once_get_one_walk_and_nobody_waits_for_another_question(tmp_path):
    repo = _tree(tmp_path)
    made, gate, got = [], threading.Event(), []

    def slow():
        made.append(1)
        gate.wait(10)
        return ["answer"]

    with listing.one_run(repo):
        askers = [threading.Thread(target=lambda: got.append(listing.once(repo, "slow", slow))) for _ in range(3)]
        for t in askers:
            t.start()
        deadline = time.monotonic() + 10
        while not made and time.monotonic() < deadline:
            time.sleep(0.01)
        assert listing.once(repo, "quick", lambda: 7) == 7      # another question is not held up by the slow one
        assert listing.files(repo)                              # and neither is the list of files
        gate.set()
        for t in askers:
            t.join(10)
        assert made == [1] and got == [["answer"]] * 3
        assert listing.once(repo, "slow", lambda: ["another"]) == ["answer"]
    assert listing.once(repo, "slow", lambda: ["outside a run"]) == ["outside a run"]


def test_one_who_waited_for_a_walk_never_walks_again(tmp_path, monkeypatch):
    """The answer is kept before those who waited for it are let go. Until 2026-11-12 it was kept just after: one
    who waited could look first, find nothing, and walk the whole folder a second time."""
    repo = _tree(tmp_path)
    made, at_the_gate, waiter = [], threading.Event(), []

    class Gate:                                 # the lock those who wait stand at
        def __init__(self):
            self.real = threading.Lock()

        def acquire(self):
            return self.real.acquire()

        def release(self):
            self.real.release()
            if waiter and threading.current_thread() is not waiter[0]:
                waiter[0].join(10)              # the worst order: the one who waited goes on first, to its end

        def __enter__(self):
            at_the_gate.set()
            self.real.acquire()

        def __exit__(self, *exc):
            self.real.release()

    def walk():
        made.append(1)
        if len(made) == 1:
            assert at_the_gate.wait(10)         # the second asker stands at the gate before the walk ends
        return ["answer"]

    with listing.one_run(repo):
        run = listing._RUNS[listing._where(repo)]
        monkeypatch.setattr(listing, "threading", types.SimpleNamespace(Lock=Gate))    # only this module's gates
        got = []
        first = threading.Thread(target=lambda: got.append(listing.once(repo, "walk", walk)))
        first.start()
        deadline = time.monotonic() + 10
        while not made and time.monotonic() < deadline:
            time.sleep(0.01)
        waiter.append(threading.Thread(target=lambda: got.append(listing.once(repo, "walk", walk))))
        waiter[0].start()
        first.join(10)
        waiter[0].join(10)
        monkeypatch.setattr(listing, "threading", threading)
        assert got == [["answer"], ["answer"]] and made == [1]
        assert not run.making


def test_a_walk_that_fails_is_not_kept_and_holds_nobody_up(tmp_path):
    repo = _tree(tmp_path)

    def fails():
        raise OSError("the folder went away")

    with listing.one_run(repo):
        run = listing._RUNS[listing._where(repo)]
        with pytest.raises(OSError, match="went away"):
            listing.once(repo, "walk", fails)
        assert not run.making and not run.kept
        assert listing.once(repo, "walk", lambda: ["found"]) == ["found"]       # the next asker walks for itself
        assert listing.once(repo, "walk", fails) == ["found"]                   # and what it found is kept


def _results(out: Path) -> dict:
    return speed.fingerprint(out)


def test_a_run_walks_the_folder_once(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    walks = []
    real = listing._walk
    monkeypatch.setattr(listing, "_walk", lambda folder: (walks.append(os.fspath(folder)), real(folder))[1])
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    assert len(walks) == 1, walks
    assert not listing.going(repo)


def test_the_scanners_run_while_the_code_is_read(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "2")
    from lantern import engine
    began, map_done = threading.Event(), threading.Event()
    real_bandit, real_build = security.run_bandit, engine.build_graph

    def bandit(folder, applicable=True):
        began.set()
        assert map_done.wait(60), "the map was not finished while the scanner was going"
        return real_bandit(folder, applicable)

    def build(folder):
        assert began.wait(60), "the scanner was not started before the map was built"
        g = real_build(folder)
        map_done.set()
        return g

    monkeypatch.setattr(security, "run_bandit", bandit)
    monkeypatch.setattr(engine, "build_graph", build)
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    sec = json.loads((tmp_path / "out" / "security.json").read_text(encoding="utf-8"))
    assert [t["tool"] for t in sec["tools"]][:2] == ["bandit", "pip-audit"]         # the records in their old places
    assert any(f["tool"] == "bandit" for f in sec["findings"])


def test_with_no_room_beside_every_scanner_runs_in_its_turn(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "0")
    from lantern import engine
    order = []
    real_bandit, real_build = security.run_bandit, engine.build_graph
    monkeypatch.setattr(security, "run_bandit", lambda f, applicable=True: (order.append("bandit"), real_bandit(f, applicable))[1])
    monkeypatch.setattr(engine, "build_graph", lambda f: (order.append("map"), real_build(f))[1])
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    assert order == ["map", "bandit"]


def test_the_results_are_the_same_with_scanners_beside_the_reading_and_without(tmp_path, monkeypatch):
    for name in ("shop", "nextapp"):
        repo = tmp_path / name
        shutil.copytree(FIXTURES / name, repo, ignore=shutil.ignore_patterns(".lantern", "node_modules", "__pycache__"))
        marks = {}
        for room in ("0", "2"):
            monkeypatch.setenv("LANTERN_JOBS", room)
            out = tmp_path / f"{name}-{room}"
            pipeline.analyze(repo, out, log=QUIET, offline=True)
            marks[room] = _results(out)
        assert marks["0"] and speed.differing(marks["0"], marks["2"]) == [], name


def test_the_scan_does_not_wait_for_a_scanner_while_it_has_work_of_its_own(tmp_path, monkeypatch):
    """Bandit was started with the run and is still going when the map is done. The steps of the scan that need
    nothing from it (the web rules, the paid calls, the reading of where request data goes) are done meanwhile;
    until 2026-11-12 the run stood still until Bandit had ended (on Django: 43 seconds in, with the map done at
    26). What each step found is put together in the order it always was."""
    from lantern import flow
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "2")
    order, done = [], threading.Event()
    real = {"bandit": security.run_bandit, "web": websec.scan_web, "ai": aiapp.scan_ai, "flow": flow.analyze}

    def bandit(folder, applicable=True):
        done.wait(20)                           # still going until the scan's own work is done
        order.append("bandit")
        return real["bandit"](folder, applicable)

    def step(name, last=False):
        def run(*a, **k):
            order.append(name)
            try:
                return real[name](*a, **k)
            finally:
                if last:
                    done.set()
        return run

    monkeypatch.setattr(security, "run_bandit", bandit)
    monkeypatch.setattr(websec, "scan_web", step("web"))
    monkeypatch.setattr(aiapp, "scan_ai", step("ai"))
    monkeypatch.setattr(flow, "analyze", step("flow", last=True))
    pipeline.analyze(repo, tmp_path / "beside", log=QUIET, offline=True)
    assert order == ["web", "ai", "flow", "bandit"]
    # the same steps with nothing started early: each in its turn, and the same results in the same order
    monkeypatch.undo()
    monkeypatch.setenv("LANTERN_JOBS", "0")
    pipeline.analyze(repo, tmp_path / "in-turn", log=QUIET, offline=True)
    assert _results(tmp_path / "beside") == _results(tmp_path / "in-turn")
    sec = json.loads((tmp_path / "beside" / "security.json").read_text(encoding="utf-8"))
    tools = [t["tool"] for t in sec["tools"]]
    audits = [name for name, _ in depaudit.audits()]
    assert tools[0] == "bandit" and tools[1:1 + len(audits)] == audits and tools[-1] == "lantern-flow"
    assert tools.index("lantern-ai") > max(i for i, t in enumerate(tools) if t in ("gitleaks", "lantern-secrets"))
    found = [(f["tool"], f["rule"]) for f in sec["findings"]]
    assert {t for t, _ in found} >= {"bandit"} and len(found) >= 2


@pytest.mark.parametrize("said, cores, room", [("0", 8, 0), ("1", 8, 1), ("3", 1, 3), ("99", 8, 8), ("", 1, 0),
                                               ("", 2, 1), ("", 16, 2), ("many", 4, 2), ("-1", 4, 2), (" 2 ", 1, 2)])
def test_how_many_scanners_may_run_beside(monkeypatch, said, cores, room):
    monkeypatch.setenv("LANTERN_JOBS", said)
    monkeypatch.setattr(os, "cpu_count", lambda: cores)
    assert security.beside() == room


SLEEPER = "import os, sys, time\nopen(sys.argv[1], 'w').write(str(os.getpid()))\ntime.sleep(600)\n"


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def test_a_run_that_fails_leaves_no_scanner_going(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "2")
    from lantern import engine
    note = tmp_path / "pid"
    ended = []

    def bandit(folder, applicable=True):        # a scanner that would go on for ten minutes
        p = remote.run_bounded([sys.executable, "-c", SLEEPER, str(note)], timeout=600)
        ended.append(p.returncode)
        return [], scanresult.record("bandit", "failed", "ended")

    def build(folder):
        for _ in range(1200):                   # until the scanner's program is going
            if note.is_file() and note.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.05)
        raise RuntimeError("the map could not be built")

    monkeypatch.setattr(security, "run_bandit", bandit)
    monkeypatch.setattr(engine, "build_graph", build)
    began = time.monotonic()
    with pytest.raises(RuntimeError, match="could not be built"):
        pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    assert time.monotonic() - began < 120       # ended, not waited for
    assert ended and ended[0] != 0
    if sys.platform != "win32":
        assert _gone(int(note.read_text(encoding="utf-8")))
    assert not remote._WAITED and not remote._TOLD      # nothing is remembered of the run
    # the safe twin: the next run starts its scanners as if nothing had happened
    monkeypatch.undo()
    monkeypatch.setenv("LANTERN_JOBS", "2")
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    sec = json.loads((tmp_path / "out" / "security.json").read_text(encoding="utf-8"))
    assert next(t for t in sec["tools"] if t["tool"] == "bandit")["state"] == "ok"


def test_a_thread_told_to_stop_starts_no_helper_until_it_is_forgotten():
    me = threading.get_ident()
    cmd = [sys.executable, "-c", "print('ran')"]
    assert remote.run_bounded(cmd, timeout=60).stdout.strip() == "ran"
    remote.end_for([me])
    try:
        with pytest.raises(OSError, match="stopped"):
            remote.run_bounded(cmd, timeout=60)
    finally:
        remote.forget([me])
    assert remote.run_bounded(cmd, timeout=60).stdout.strip() == "ran"


def test_tests_run_in_the_projects_folder_come_before_every_scanner(tmp_path, monkeypatch):
    """`lantern analyze --trace` runs the project's tests in its own folder, and they may leave files there. Every
    scanner read those files when it ran after the tests, so none is started before them, and what was listed
    before the tests is looked up anew."""
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "2")
    from lantern import trace
    order = []
    key = "AKIA" + "Q7" * 8                     # made here: never a real-looking secret in a file of this repository
    real_bandit = security.run_bandit

    def tests_ran(folder, command, timeout=900):
        order.append("tests")
        _write(Path(folder), {"left_by_tests.py": "import os\n\n\ndef again(d):\n    os.system('ls ' + d)\n",
                              "settings.env.py": f"KEY = '{key}'\n"})
        return {"pairs": []}

    monkeypatch.setattr(trace, "run_trace", tests_ran)
    monkeypatch.setattr(security, "run_bandit",
                        lambda f, applicable=True: (order.append("bandit"), real_bandit(f, applicable))[1])
    pipeline.analyze(repo, tmp_path / "out", trace_cmd=["-m", "pytest"], log=QUIET, offline=True)
    assert order == ["tests", "bandit"]
    sec = json.loads((tmp_path / "out" / "security.json").read_text(encoding="utf-8"))
    files = {(f["tool"], f["file"]) for f in sec["findings"]}
    assert ("bandit", "left_by_tests.py") in files
    assert ("lantern-secrets", "settings.env.py") in files or ("gitleaks", "settings.env.py") in files


def test_scanners_started_for_another_folder_are_not_taken(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    other = _write(tmp_path / "other", {"clean.py": "x = 1\n"})
    from lantern.engine import build_graph
    early = security.Early(other, True, room=2).start()
    try:
        sec = security.scan(build_graph(repo), True, early)
    finally:
        early.close()
    assert any(f["tool"] == "bandit" and f["file"] == "app.py" for f in sec["findings"])


# ---------------------------------------------------------------------------------------------- the map's names
def _handler_nodes_before(g: Graph, handler: str, near_file: str) -> list[str]:
    """`packs._handler_nodes` as it was until 2026-11-12: through every node of the map for every name."""
    import re
    h = re.sub(r"\.as_view(\(\))?$|\(\)$", "", handler.strip())
    if not h:
        return []
    parts = h.split(".")
    cands = []
    for n in g.nodes.values():
        if n.kind not in ("callable", "class") or not n.file:
            continue
        q = n.qualname.split(".")
        if q[-len(parts):] == parts:
            cands.append(n)
    if len(cands) > 1:
        folder = near_file.rsplit("/", 1)[0] if "/" in near_file else ""
        same = [n for n in cands if (n.file.rsplit("/", 1)[0] if "/" in n.file else "") == folder]
        if same:
            cands = same
    out = []
    for n in cands:
        if n.kind == "class":
            methods = [m for m in g.nodes.values() if m.parent == n.id and m.kind == "callable" and
                       m.name in ("dispatch", "get", "post", "put", "patch", "delete", "handle", "__call__")]
            out += [m.id for m in methods]
        else:
            out.append(n.id)
    return out


def _views() -> Graph:
    g = Graph(repo_root="/nowhere")

    def add(qual, kind="callable", file="shop/views.py", parent=None):
        g.add_node(Node(id="py:" + qual, kind=kind, name=qual.rsplit(".", 1)[-1], qualname=qual, file=file, parent=parent))

    add("shop.views", "module")
    add("shop.views.index")
    add("shop.views.ItemView", "class")
    for m in ("get", "post", "helper", "dispatch"):
        add("shop.views.ItemView." + m, parent="py:shop.views.ItemView")
    add("blog.views", "module", "blog/views.py")
    add("blog.views.index", file="blog/views.py")
    add("blog.views.ItemView", "class", "blog/views.py")
    add("blog.views.ItemView.get", file="blog/views.py", parent="py:blog.views.ItemView")
    add("admin.index", file="admin.py")
    add("ext.thing", file=None)
    add("index", file="index.py")
    return g


HANDLERS = ["index", "views.index", "shop.views.index", "ItemView.as_view()", "ItemView.as_view", "views.ItemView",
            "blog.views.ItemView.as_view()", "index()", "missing", "", "  views.index  ", "ItemView.get", "get",
            "thing", "a.b.c.shop.views.index", "admin.index", "helper"]


@pytest.mark.parametrize("near", ["shop/urls.py", "blog/urls.py", "urls.py", "other/deep/urls.py"])
def test_a_registration_names_the_same_functions_as_before(near):
    g = _views()
    known = packs._handlers(g)
    for h in HANDLERS:
        assert packs._handler_nodes(g, h, near, known) == _handler_nodes_before(g, h, near), (h, near)
        assert packs._handler_nodes(g, h, near) == _handler_nodes_before(g, h, near), (h, near)
    assert packs._handler_nodes(g, "ItemView.as_view()", "shop/urls.py", known) == [
        "py:shop.views.ItemView.get", "py:shop.views.ItemView.post", "py:shop.views.ItemView.dispatch"]


def test_the_maps_names_are_put_in_order_once_for_all_registrations(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", {
        "manage.py": "import django\n", "requirements.txt": "django==5.0\n",
        "shop/__init__.py": "", "shop/views.py": "def index(request):\n    return 1\n\n\ndef about(request):\n    return 2\n",
        "shop/urls.py": "from django.urls import path\nfrom . import views\n\nurlpatterns = [\n"
                        "    path('', views.index),\n    path('about/', views.about),\n]\n"})
    made = []
    real = packs._handlers
    monkeypatch.setattr(packs, "_handlers", lambda g: (made.append(1), real(g))[1])
    from lantern.engine import build_graph
    g = build_graph(repo)
    entries = {n.qualname: n.entry["detail"] for n in g.entry_points() if (n.entry or {}).get("via") == "pack:django"}
    assert set(entries) == {"shop.views.index", "shop.views.about"}, entries
    assert len(made) == 1


# ---------------------------------------------------------------------------------------------- the saved map
def test_the_collectors_full_passes_wait_while_the_map_is_built(tmp_path, monkeypatch):
    """Nearly everything made while the map is built is kept, so a full pass of Python's cycle collector finds
    nothing to free and costs more the more there is (6 of the 26 seconds on Django). The full passes wait until the
    map is built; the small ones go on, so what a file's reading leaves behind is still freed, and when the build
    ends, however it ends, the collector is as it was."""
    import gc
    from lantern import engine, python_frontend
    repo = _write(tmp_path / "p", SMALL)
    seen = []
    real = python_frontend.build_graph

    def reading(folder, *more):                  # what the engine hands the reader: the folder, and its map
        seen.append((gc.get_threshold(), gc.isenabled()))
        return real(folder, *more)

    monkeypatch.setattr(python_frontend, "build_graph", reading)
    was = gc.get_threshold()
    try:
        gc.set_threshold(900, 7, 5)             # whatever the program around Lantern had set
        g = engine.build_graph(repo)
        assert seen == [((900, 7, engine.HOLD_FULL), True)] and engine.HOLD_FULL >= 100_000
        assert gc.get_threshold() == (900, 7, 5)
        assert g.meta["files"] >= 2

        def failing(folder, *more):
            seen.append((gc.get_threshold(), gc.isenabled()))
            raise RuntimeError("a reader gave up")

        monkeypatch.setattr(python_frontend, "build_graph", failing)
        with pytest.raises(RuntimeError, match="gave up"):
            engine.build_graph(repo)
        assert seen[-1][0][2] == engine.HOLD_FULL and gc.get_threshold() == (900, 7, 5)
        # two builds at once (the app's threads): the collector is put back when the last of them ends, not before,
        # and never left held
        with engine.building():
            with engine.building():
                assert gc.get_threshold() == (900, 7, engine.HOLD_FULL)
            assert gc.get_threshold() == (900, 7, engine.HOLD_FULL)
        assert gc.get_threshold() == (900, 7, 5)
        # a collector the program switched off stays off, and is not switched on at the end
        gc.disable()
        with engine.building():
            assert not gc.isenabled()
        assert not gc.isenabled() and gc.get_threshold() == (900, 7, 5)
    finally:
        gc.enable()
        gc.set_threshold(*was)


def test_two_threads_that_build_at_once_leave_the_collector_as_it_was():
    import gc
    from lantern import engine
    was = gc.get_threshold()
    inside, leave, seen = threading.Barrier(3), threading.Event(), []

    def build():
        with engine.building():
            inside.wait(10)
            leave.wait(10)
            seen.append(gc.get_threshold()[2])

    try:
        threads = [threading.Thread(target=build) for _ in range(2)]
        for t in threads:
            t.start()
        inside.wait(10)
        assert gc.get_threshold() == (was[0], was[1], engine.HOLD_FULL)
        leave.set()
        for t in threads:
            t.join(10)
        assert seen == [engine.HOLD_FULL] * 2 and gc.get_threshold() == was
    finally:
        gc.set_threshold(*was)


CLASSES = {
    "shapes/base.py": "class Shape:\n    def area(self):\n        return self.sides() * 2\n\n    def sides(self):\n"
                      "        return 0\n\n\nclass Named:\n    def name(self):\n        return 'n'\n",
    "shapes/flat.py": "from .base import Named, Shape\n\n\nclass Square(Shape):\n    def sides(self):\n        return 4\n\n\n"
                      "class Round(Shape, Named):\n    def sides(self):\n        return 1\n\n\n"
                      "class Tile(Square, Named):\n    def sides(self):\n        return 4\n",
    "shapes/deep.py": "from .flat import Round, Square, Tile\n\n\nclass Both(Square, Round):\n    pass\n\n\n"
                      "class Last(Both, Tile):\n    def sides(self):\n        return 9\n\n\n"
                      "class Loop(Again):\n    pass\n\n\nclass Again(Loop):\n    pass\n\n\nclass Alone:\n    pass\n",
    "shapes/__init__.py": "",
}


def _subclasses_before(r, cls_q: str) -> list[str]:
    """`Resolver.subclasses` as it was until 2026-11-12: worked out again at every call, each class looked for in
    the list so far (4.2 of the 30 seconds the Python reader took on Django)."""
    direct: dict[str, list[str]] = {}
    for q, (_, d) in r.defs.items():
        if d.kind == "class":
            for b in r.bases(q):
                direct.setdefault(b, []).append(q)
    out, stack = [], list(direct.get(cls_q, []))
    while stack:
        c = stack.pop()
        if c not in out:
            out.append(c)
            stack.extend(direct.get(c, []))
    return out


def _resolvers(repo: Path, monkeypatch) -> list:
    from lantern import python_frontend
    made = []
    real = python_frontend.Resolver.__init__
    monkeypatch.setattr(python_frontend.Resolver, "__init__", lambda self, *a, **k: (real(self, *a, **k), made.append(self))[0])
    python_frontend.build_graph(repo)
    monkeypatch.undo()
    return made


@pytest.mark.parametrize("files", [CLASSES, {"plain.py": "def f():\n    return 1\n\n\nclass A:\n    pass\n"}],
                         ids=["a tree of classes", "no class has a base"])
def test_the_classes_below_a_class_are_the_same_as_before_in_the_same_order(tmp_path, monkeypatch, files):
    repo = _write(tmp_path / "p", files)
    (r,) = _resolvers(repo, monkeypatch)
    classes = [q for q, (_, d) in r.defs.items() if d.kind == "class"]
    assert len(classes) >= 1
    for q in classes + ["shapes.base.Nobody"]:
        was = _subclasses_before(r, q)
        assert r.subclasses(q) == was, q
        assert r.subclasses(q) == was, q        # and when asked again
    if files is CLASSES:
        assert len(r.subclasses("shapes.base.Shape")) == 5 and r.subclasses("shapes.deep.Alone") == []
        assert set(r.subclasses("shapes.deep.Loop")) == {"shapes.deep.Loop", "shapes.deep.Again"}   # a loop ends
        # worked out once: the answer of the second ask is the first one's
        assert r.subclasses("shapes.base.Shape") is r.subclasses("shapes.base.Shape")


def test_the_map_of_classes_is_the_same_with_the_answers_kept(tmp_path, monkeypatch):
    """The edges an overridden method gets (`possible`, `override`), with every answer worked out anew as before
    and with the answers kept: the same edges in the same order."""
    from lantern import python_frontend
    repo = _write(tmp_path / "p", CLASSES)
    now = python_frontend.build_graph(repo)
    monkeypatch.setattr(python_frontend.Resolver, "subclasses", _subclasses_before)
    before = python_frontend.build_graph(repo)
    assert [edge_dict(e) for e in now.edges] == [edge_dict(e) for e in before.edges]
    assert now.sites == before.sites and now.unresolved == before.unresolved
    assert any(e.via == "override" for e in now.edges)


# ---------------------------------------------------------------------------------------------- the PHP reader

def _fun_in_before(m, cid: str, name: str, depth: int = 0):
    """`Model.fun_in` as it was: every method name of the class lower-cased and compared, for every call."""
    c = m.classes.get(cid)
    if c is None or depth > 8:
        return None
    low = name.lower()
    for f in c.funs:
        if f.lower() == low:
            return f"php:{cid}.{f}"
    for s in c.supers:
        if s in m.classes:
            r = _fun_in_before(m, s, name, depth + 1)
            if r:
                return r
    return None


class _Counted(set):
    """A class's method names that count how often they are gone through one by one."""
    def __init__(self, *a):
        super().__init__(*a)
        self.walks = 0

    def __iter__(self):
        self.walks += 1
        return super().__iter__()


def _php_class(cid: str, funs, supers=()):
    return php_frontend.PClass(id=cid, short=cid.split(".")[-1], ns=".".join(cid.split(".")[:-1]), file="a.php",
                               start=1, end=2, kind="class", supers=list(supers), funs=_Counted(funs))


def _php_model():
    m = php_frontend.Model()
    for k in [_php_class("App.Base", {"save", "Find", "__construct"}),
              _php_class("App.Note", {"title", "SAVE"}, ["App.Base", "Gone.Away"]),
              _php_class("App.Draft", {"publish"}, ["App.Note"]),
              _php_class("App.Empty", set(), ["App.Draft"]),
              _php_class("Ring.A", {"a"}, ["Ring.B"]), _php_class("Ring.B", {"b"}, ["Ring.A"]),
              _php_class("Twice", {"Run", "run", "RUN"}),            # no PHP file may say this; a garbled one can
              *[_php_class(f"Deep.C{i}", {f"m{i}"}, [f"Deep.C{i + 1}"]) for i in range(12)]]:
        m.classes[k.id] = k
    return m


PHP_NAMES = ["save", "SAVE", "Save", "find", "FIND", "title", "Title", "publish", "__construct", "__CONSTRUCT", "a", "B",
             "run", "Run", "rUn", "nothing", "", "m0", "M8", "m9", "m11", "ſave", "İ"]


def test_a_method_of_a_php_class_is_the_one_found_before():
    m = _php_model()
    for cid in [*m.classes, "Not.There"]:
        for name in PHP_NAMES:
            assert m.fun_in(cid, name) == _fun_in_before(m, cid, name), (cid, name)
    assert m.fun_in("App.Empty", "find") == "php:App.Base.Find"          # through three parents, whatever the case
    assert m.fun_in("Deep.C0", "m8") == "php:Deep.C8.m8" and m.fun_in("Deep.C0", "m9") is None   # as deep as before


def test_the_methods_of_a_php_class_are_gone_through_once_not_for_every_call():
    m = _php_model()
    for _ in range(200):
        for name in PHP_NAMES:
            m.fun_in("App.Empty", name)
    for cid in ("App.Empty", "App.Draft", "App.Note", "App.Base"):
        assert m.classes[cid].funs.walks <= 1, cid          # before: once for every call that got to the class


def test_a_php_method_read_after_the_first_question_is_found():
    m = _php_model()
    assert m.fun_in("App.Draft", "archive") is None
    m.classes["App.Base"].funs.add("Archive")                 # the reader was not done with the class yet
    assert m.fun_in("App.Draft", "archive") == "php:App.Base.Archive" == _fun_in_before(m, "App.Draft", "archive")
    m.classes["App.Base"] = _php_class("App.Base", {"other"})    # a second file gave the name to another class
    assert m.fun_in("App.Draft", "archive") is None and m.fun_in("App.Draft", "OTHER") == "php:App.Base.other"
    m.classes["App.Note"].supers.append("Twice")              # and a parent worked out later is asked too
    assert m.fun_in("App.Draft", "run") == _fun_in_before(m, "App.Draft", "run") is not None


class _Spy:
    """A syntax node that writes down whenever the parts beneath it are asked for."""
    def __init__(self, node, seen):
        self._node, self._seen = node, seen

    def __getattr__(self, name):
        return getattr(self._node, name)

    @property
    def children(self):
        self._seen.append(self._node.type)
        return [_Spy(c, self._seen) for c in self._node.children]


def _php_statements(text: str):
    return php_frontend._parser().parse(text.encode("utf-8")).root_node.children


PHP_QUIET = """<?php
function total($request, $rows, $response) {
    $sum = 0;
    foreach ($rows as $row) { $sum += $row->price * $request->get('n', 1); }
    $router2 = $response->json(['sum' => $sum]);
    return tidy($router2, $apps, $routes2, $v10, $r_, 'x');
}
"""
PHP_ROUTES = """<?php
Route::get('/notes', [NoteController::class, 'index']);
$r->post('/notes', 'NoteController@store');
add_action('wp_ajax_nopriv_save', 'save_note');
"""


def test_a_php_function_that_names_no_router_is_not_gone_through_for_routes():
    f = php_frontend.PFile(rel="a.php", lines=9)
    m = php_frontend.Model()
    seen: list[str] = []
    quiet = [_Spy(n, seen) for n in _php_statements(PHP_QUIET)]
    assert php_frontend._routes(m, f, quiet) == [] and php_frontend._wordpress(m, f, quiet) == []
    assert seen == []                                          # before: every part of the function, twice
    loud = [_Spy(n, seen) for n in _php_statements(PHP_ROUTES)]
    assert [(r.verb, r.path) for r in php_frontend._routes(m, f, loud)] == [("GET", "/notes"), ("POST", "/notes")]
    assert [d for d, _, _ in php_frontend._wordpress(m, f, loud)] == [
        "POST /wp-admin/admin-ajax.php?action=save (anyone can call it)"]
    assert seen                                                # and the spy does see a look


# Each line a statement: the ones a route or a WordPress hook is read from beside the ones that only look like it.
PHP_LOOKALIKES = [
    "Route::get('/a', 'h');", "\\Route::post('/a', 'h');", "Illuminate\\Support\\Facades\\Route::put('/a', 'h');",
    "Route :: get('/a', 'h');", "Route/* c */::get('/a', 'h');", "MyRoute::get('/a', 'h');", "Router::get('/a', 'h');",
    "route::get('/a', 'h');", "Route::prefix('v1')->middleware('auth')->group(function () { Route::get('/b', 'h'); });",
    "$app->get('/a', 'h');", "$router->post('/a', 'h');", "$route->put('/a', 'h');", "$group->delete('/a', 'h');",
    "$r->get('/a', 'h');", "$api->get('/a', 'h');", "$routes->get('/a', 'h');", "$v1->get('/a', 'h');",
    "$r ->get('/a', 'h');", "$r\n  ->get('/a', 'h');", "$r/* c */->get('/a', 'h');", "$r?->get('/a', 'h');",
    "$request->get('/a', 'h');", "$rr->get('/a', 'h');", "$r2->get('/a', 'h');", "$r_->get('/a', 'h');",
    "$ré->get('/a', 'h');", "$r€->get('/a', 'h');", "$this->r->get('/a', 'h');", "$R->get('/a', 'h');",
    "$apps->get('/a', 'h');", "$v12->get('/a', 'h');", "$x = \"$r->get('/a', 'h')\";", "$x = '$r'; $y->get('/a', 'h');",
    "$app->group('/api', function ($g) { $g->get('/c', 'h'); $app->get('/d', 'h'); });", "$$r->get('/a', 'h');",
    "function f($r) { return $r->get('/a', 'h'); }", "$f = fn($r) => $r->get('/a', 'h');",
    "add_action('wp_ajax_save', 'h');", "add_action('wp_ajax_nopriv_save', function () { echo 1; });",
    "add_action ('wp_ajax_save', 'h');", "\\add_action('wp_ajax_save', 'h');", "my_add_action('wp_ajax_save', 'h');",
    "add_actions('wp_ajax_save', 'h');", "ADD_ACTION('wp_ajax_save', 'h');", "$o->add_action('wp_ajax_save', 'h');",
    "register_rest_route('notes/v1', '/n/(?P<id>\\d+)', ['methods' => 'GET', 'callback' => 'h']);",
    "register_rest_routes('notes/v1', '/n', ['methods' => 'GET', 'callback' => 'h']);",
    "$r->get('/a', 'h'", "Route::get('/a', ", "add_action('wp_ajax_save',", "$r->", "Route::",
]


def _php_found(model, f, nodes):
    return ([(r.verb, r.path, r.line, r.auth, type(r.handler).__name__) for r in php_frontend._routes(model, f, nodes)],
            [(d, line, h is None) for d, h, line in php_frontend._wordpress(model, f, nodes)])


@pytest.mark.parametrize("rel", ["routes/web.php", "routes/api.php"])
def test_the_routes_of_a_php_file_are_the_same_with_the_quick_look_and_without(rel, monkeypatch):
    f = php_frontend.PFile(rel=rel, lines=9)
    m = php_frontend.Model()
    texts = ["<?php\n" + line + "\n" for line in PHP_LOOKALIKES] + ["<?php\n" + "\n".join(PHP_LOOKALIKES) + "\n",
                                                                    PHP_QUIET, PHP_ROUTES]
    quick_look = [_php_found(m, f, _php_statements(t)) for t in texts]
    monkeypatch.setattr(php_frontend, "ROUTER_NAMED", re.compile(rb""))
    monkeypatch.setattr(php_frontend, "HOOK_NAMED", re.compile(rb""))
    full = [_php_found(m, f, _php_statements(t)) for t in texts]
    assert quick_look == full
    assert sum(len(r) for r, _ in full) >= 20 and sum(len(w) for _, w in full) >= 6      # the lines do say something


def _php_map(repo: Path) -> dict:
    g = Graph(repo_root=str(repo))
    stats = php_frontend.add_php(g, repo)
    return {"stats": stats, "nodes": [node_dict(n) for n in g.nodes.values()], "edges": [edge_dict(e) for e in g.edges],
            "unresolved": dict(g.unresolved), "meta": json.loads(json.dumps(g.meta, default=str))}


def test_the_map_of_the_php_sample_is_the_same_with_the_quick_look_and_without(monkeypatch):
    quick_look = _php_map(FIXTURES / "phpapp")
    monkeypatch.setattr(php_frontend, "ROUTER_NAMED", re.compile(rb""))
    monkeypatch.setattr(php_frontend, "HOOK_NAMED", re.compile(rb""))
    assert quick_look == _php_map(FIXTURES / "phpapp")
    assert quick_look["stats"]["routes"] >= 5


def test_the_functions_of_a_php_project_are_put_by_file_once(tmp_path, monkeypatch):
    class Counted(dict):
        asked = 0

        def items(self):
            Counted.asked += 1
            return super().items()

    class Model(php_frontend.Model):
        def __init__(self):
            super().__init__()
            self.funs = Counted()

    monkeypatch.setattr(php_frontend, "Model", Model)

    def asked(n: int) -> tuple[int, dict]:
        repo = _write(tmp_path / f"p{n}", {f"src/f{i}.php": f"<?php\nfunction f{i}($r) {{ return f{(i + 1) % n}($r); }}\n"
                                           f"$r->get('/f{i}', 'f{i}');\n" for i in range(n)})
        Counted.asked = 0
        found = _php_map(repo)
        return Counted.asked, found

    few, small = asked(3)
    many, large = asked(30)
    assert few == many                           # before: all the functions of the project once more for every file
    assert small["stats"]["routes"] == 3 and large["stats"]["routes"] == 30
    assert [e["dst"] for e in large["edges"] if e["kind"] == "calls"][:2] == ["php:f1", "php:f2"]


# ---------------------------------------------------------------------------------------------- the readiness checks

READY_TREE = {
    "app/main.py": "import logging\nimport requests\n\ndef load(url):\n    try:\n        return requests.get(url)\n"
                   "    except:\n        print('no')\n\nDEBUG = True\n",
    "app/users.py": "def sign_in(name, password):\n    return check(name, password)\n",
    "app/names.py": "def compass(passWord, pW, bypass):\n    return 'password'  # the password is only named here\n",
    "app/keys.py": "def rotate(userPwd):\n    return userPwd\n",
    "app/phrase.py": "class Vault:\n    def open(self, PassPhrase):\n        return PassPhrase\n",
    "app/quiet.py": "def total(rows):\n    return sum(r.price for r in rows)\n",
    "app/empty.py": "",
    "web/src/api.ts": "export const load = () => fetch('/api/items', { signal: AbortSignal.timeout(500) })\n",
    "web/src/pw.js": "export function check(PW) { return PW.length > 8 }\n",
    "web/src/a.min.js": "var password=1\n",
    "web/src/types.d.ts": "export type Password = string\n",
    "tests/test_main.py": "import requests\n\ndef test_load(password):\n    print(requests.get('http://x'))\n",
    "web/src/api.test.ts": "it('loads', () => fetch('/api/items'))\n",
    "legacy/page.php": "<?php\n$passwd = $_POST['p'];\nprint($passwd);\n",
    "README.md": "password\n",
}
READY_PATTERNS = [readiness.BARE_EXCEPT, readiness.VALIDATION, readiness.DEBUG_ON, readiness.LOGGING, readiness.PY_HTTP,
                  readiness.RETRY, readiness.SHUTDOWN, re.compile(r"^\s*print\(", re.M),
                  re.compile(r"\b(fetch|axios\.(get|post|put|patch|delete))\("),
                  re.compile(r"AbortSignal\.timeout|AbortController|timeout\s*:"), re.compile(r"PASSWORD", re.I),
                  re.compile(r"def \w+\(.*\):\n\s+return"), re.compile(r"[a-z]{3}\d"), re.compile(r"\w+\(")]


def _code_before(repo, tests: bool = False):
    """`Repo.code` as it was: every file's ending and name asked again for every search."""
    for f in repo.files:
        if Path(f).suffix not in readiness.CODE_EXTS or f.endswith((".min.js", ".d.ts")):
            continue
        if repo.is_test(f) != tests:
            continue
        yield f, repo.text(f)


def _grep_before(repo, rx: re.Pattern, tests: bool = False, limit: int = 20):
    out = []
    for f, t in _code_before(repo, tests):
        for m in rx.finditer(t):
            line = t.count("\n", 0, m.start()) + 1
            out.append((f, line, t.splitlines()[line - 1].strip()[:160] if t else ""))
            if len(out) >= limit:
                return out
    return out


def _handles_passwords_before(code_texts):
    rx = re.compile(r"[A-Za-z_][\w]*")
    out = []
    for f, t in code_texts:
        if context._bundle(t):
            continue
        code = websec.code_only(t, not f.endswith(".py"))
        for m in rx.finditer(code):
            if context.PASSWORD_WORDS.search(websec.segments(m.group(0))):
                ln = code.count("\n", 0, m.start()) + 1
                out.append((f, ln, t.splitlines()[ln - 1].strip()[:160]))
                break
        if len(out) >= 40:
            break
    return out


@pytest.mark.parametrize("folder", ["made", *SAMPLES])
def test_the_readiness_searches_find_what_they_found_before(folder, tmp_path):
    repo = readiness.Repo(_write(tmp_path, READY_TREE) if folder == "made" else FIXTURES / folder)
    for tests in (False, True):
        assert list(repo.code(tests)) == list(_code_before(repo, tests))
        for rx in READY_PATTERNS:
            for limit in (1, 3, 20, 500):
                assert repo.grep(rx, tests, limit) == _grep_before(repo, rx, tests, limit), (rx.pattern, tests, limit)
        assert context.handles_passwords(repo.code(tests)) == _handles_passwords_before(_code_before(repo, tests))
    if folder == "made":
        assert [f for f, _ in repo.code()] == ["app/empty.py", "app/keys.py", "app/main.py", "app/names.py",
                                               "app/phrase.py", "app/quiet.py", "app/users.py", "legacy/page.php",
                                               "web/src/api.ts", "web/src/pw.js"]
        assert [f for f, _, _ in context.handles_passwords(repo.code())] == [
            "app/keys.py", "app/phrase.py", "app/users.py", "legacy/page.php", "web/src/pw.js"]


def test_a_files_name_is_asked_about_once_not_for_every_search(tmp_path, monkeypatch):
    asked = []
    real = readiness.Repo.is_test
    monkeypatch.setattr(readiness.Repo, "is_test", staticmethod(lambda f: asked.append(f) or real(f)))
    repo = readiness.Repo(_write(tmp_path, READY_TREE))
    asked.clear()
    for _ in range(10):
        for rx in READY_PATTERNS:
            repo.grep(rx)
            repo.grep(rx, tests=True)
    assert len(asked) <= len(repo.files)                        # before: every code file again for each of 280 searches


def test_a_file_that_cannot_hold_a_match_is_not_searched(tmp_path, monkeypatch):
    repo = readiness.Repo(_write(tmp_path, READY_TREE))
    asked: list[str] = []
    real = quick.Text.may_match
    monkeypatch.setattr(quick.Text, "may_match", lambda self, rx: asked.append(rx.pattern) or real(self, rx))
    assert [h[:2] for h in repo.grep(readiness.PY_HTTP)] == [("app/main.py", 6)]
    assert len(asked) == 10                                     # the quick look is what passes a file over
    blanked: list[str] = []
    real_only = websec.code_only
    monkeypatch.setattr(websec, "code_only", lambda t, js=False: blanked.append(t) or real_only(t, js))
    context.handles_passwords(repo.code())
    assert len(blanked) == 6 and READY_TREE["app/quiet.py"] not in blanked     # before: all ten files
    assert READY_TREE["app/names.py"] in blanked                # `compass`, `passWord`: looked at, and nothing found


def test_a_name_is_split_into_words_once():
    websec.segments.cache_clear()
    for _ in range(50):
        assert websec.segments("getServerSession") == "get server session"
        assert websec.segments("OAuth2PasswordBearer") == "o auth 2 password bearer"
        assert websec.segments("load_permissions") == "load permissions" and websec.segments("") == ""
    made = websec.segments.cache_info()
    assert made.misses == 4 and made.hits == 196 and made.maxsize       # bounded: a project's names are not kept for ever


def test_the_saved_map_is_what_asdict_gave_and_still_a_copy():
    n = Node(id="py:a.f", kind="callable", name="f", qualname="a.f", file="a.py", start_line=3, end_line=9,
             parent="py:a", fingerprint="abc", signature="(x)", docstring="does   things",
             decorators=["app.get('/x')", "login"],
             entry={"kind": "route", "detail": "GET /x", "middleware": ["auth"], "use": [{"id": "js:a::mw", "line": 2}],
                    "n": 1.5, "ok": True, "none": None, "pair": ("a", 1)})
    bare = Node(id="ext:os.system", kind="external", name="system", qualname="os.system")
    e = Edge(src="py:a.f", dst="ext:os.system", lines=[4, 7], via="import", detail=None)
    for thing, saved in ((n, node_dict(n)), (bare, node_dict(bare)), (e, edge_dict(e))):
        assert saved == asdict(thing)
        assert list(saved) == list(asdict(thing))               # the fields in the same order
        assert json.dumps(saved, indent=1) == json.dumps(asdict(thing), indent=1)
    saved = node_dict(n)
    saved["decorators"].append("changed")
    saved["entry"]["middleware"].append("changed")
    saved["entry"]["use"][0]["line"] = 99
    assert n.decorators == ["app.get('/x')", "login"]
    assert n.entry["middleware"] == ["auth"] and n.entry["use"] == [{"id": "js:a::mw", "line": 2}]
    g = Graph(repo_root="/nowhere")
    g.add_node(n)
    g.add_node(bare)
    g.add_edge("py:a.f", "ext:os.system", line=4, via="import")
    g.add_edge("py:a.f", "ext:os.system", line=7)
    d = g.to_dict()
    assert d["nodes"] == [asdict(n), asdict(bare)]
    assert d["edges"] == [asdict(x) for x in g.edges] == [asdict(e)]


# ---------------------------------------------------------------------------------------------- the quick look
def _pack_patterns() -> list[re.Pattern]:
    out = []
    for f in sorted((Path(packs.__file__).parent / "packs").glob("*.json")):
        pack = json.loads(f.read_text(encoding="utf-8"))
        out += [re.compile(r["pattern"]) for r in pack.get("rules", []) + pack.get("entries", [])]
    return out


PATTERNS = ([rx for _, _, rx in aiapp.CALL_PATTERNS] + [rx for _, rx in aiapp.KEY_PATTERNS]
            + [rx for _, rx in security.SECRET_PATTERNS] + _pack_patterns())

# Lines written for the patterns (keys are put together here, never written out whole), beside every line of the
# sample apps. Each is searched by every pattern the slow way, and wherever one matches the quick look must not
# have said that the text cannot match.
WRITTEN = [
    "resp = client.chat.completions.create(model=m, messages=msgs)", "r = openai.ChatCompletion.create()",
    "const { text } = await generateText({ model })", "msg = client.messages.create(model=m)",
    "anthropic.Anthropic()", "model.generate_content(prompt)", "mistralai.client()", "co.chat(message=q)",
    "client = Groq()", "replicate.run('a/b')", "InferenceClient(token=t)", "ollama.chat(model='x')",
    "llm = ChatOpenAI(temperature=0)", "index = VectorStoreIndex.from_documents(docs)", "boto.invoke_model(body=b)",
    "AzureOpenAI(api_version=v)", "client.embeddings.create(input=t)", "client.images.generate(prompt=p)",
    "client.audio.speech.create(voice=v)", "pc = Pinecone(api_key=k)", "import chromadb", "import weaviate",
    "QdrantClient(url=u)", "ORDER BY embedding <-> $1", "supabase.rpc('match_documents', q)", "embedding vector(1536)",
    "import faiss", "from pymilvus import MilvusClient", "stripe.checkout.sessions.create()", "const s = new Stripe(key)",
    "await resend.emails.send({ to })", "import sendgrid", "smtplib.SMTP(host)", "from twilio.rest import Client",
    "client.messages.create(to=n, body=b)", "STRIPE.CHECKOUT", "Sendgrid", "TWILIO",
    "key = '" + "AKIA" + "Q7" * 8 + "'", "token: " + "ghp_" + "a1B2" * 9, "-----BEGIN " + "RSA PRIVATE KEY-----",
    "-----BEGIN " + "PRIVATE KEY-----", "slack = '" + "xoxb-" + "1234567890-abcdef" + "'",
    "pay = '" + "sk_live_" + "a1B2c3D4" * 3 + "'", "ant = '" + "sk-ant-" + "a1B2c3D4_-" * 3 + "'",
    "oai = '" + "sk-proj-" + "a1B2c3D4" * 4 + "'", "g = '" + "AIza" + "a1B2c3D4e" * 4 + "'",
    "hf = '" + "hf_" + "a1B2c3D4" * 4 + "'", "API_KEY = '" + "a1B2c3D4" * 3 + "'",
    "Api-Key: '" + "a1B2c3D4" * 3 + "'", "os.environ['OPENAI_API_KEY'] = '" + "not-a-real-one" + "'",
    "path('items/', views.index),", "    url(r'^about/$', views.about),", "DEBUG = True", "ALLOWED_HOSTS = ['*']",
    "\u017ftripe.checkout", "\u212awilio", "re\u017fend.emails.send(",
]


def _sample_lines() -> list[str]:
    lines = []
    for f in sorted(FIXTURES.rglob("*")):
        if f.is_file() and f.suffix in (".py", ".js", ".ts", ".tsx", ".json", ".php", ".rb", ".go", ".kt", ".swift"):
            if "old_results" not in f.parts and f.stat().st_size < 100_000:
                lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines


def test_a_pattern_is_left_out_only_for_text_it_cannot_match():
    lines = WRITTEN + _sample_lines()
    whole = quick.Text("\n".join(lines))
    plain = quick.Text("\n".join(ln for ln in lines if ln.isascii()))
    checked = patterns_hit = 0
    for rx in PATTERNS:
        hits = [ln for ln in lines if rx.search(ln)]
        patterns_hit += bool(hits)
        for ln in hits:
            # the line as it is, and in other letter cases: a pattern that ignores case still matches those
            for form in (ln, ln.upper(), ln.lower(), ln.swapcase(), "  " + ln + "  # and more"):
                if rx.search(form):
                    checked += 1
                    assert quick.may_match(rx, form), (rx.pattern, form)
        if hits:
            assert whole.may_match(rx), rx.pattern
        if any(ln.isascii() for ln in hits):
            assert plain.may_match(rx), rx.pattern
    assert checked > 150 and patterns_hit >= 40, (checked, patterns_hit)    # the proof is not an empty one
    assert patterns_hit >= len(PATTERNS) * 2 // 3, (patterns_hit, len(PATTERNS))


def test_what_a_pattern_needs_is_read_from_the_pattern():
    need = lambda p, flags=0: quick.needs(re.compile(p, flags))  # noqa: E731
    # one piece for each arm of a choice (Python's own reader has already moved the "ch" both words begin with forward)
    assert need(r"\bstripe\.(?:checkout|charges)\b|\bStripe\(") == ("stripe.ch", "Stripe(")
    assert need(r"x(?:ab|cd)y") == ("ab", "cd")
    assert need(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----") == ("PRIVATE KEY-----",)
    assert need(r"colou?r") == ("colo",)                    # the optional letter is not needed, what stands before it is
    assert need(r"(?:foo)?bar\d+") == ("bar",)
    assert need(r"(?:ab)+c") == ("ab",)                     # at least once: needed
    assert need(r"(?:ab)*cd") == ("cd",)                    # perhaps never: not needed
    assert need(r"foo\bbar(?=x)baz") == ("foobarbaz",)      # what takes no text does not part what it stands between
    assert need(r"(?i)Api[_-]?Key") == ("api",)             # asked in lower case
    assert need(r"Send(?i:grid)mail") == ("Send",)          # a group that reads its text another way is not read
    assert need(r"(?i:send)grid") == ("grid",)
    assert need(r"\.rpc\(\s*['\"]match_\w+") == ("match_",)    # no quote in a piece
    assert need(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b") == ("KIA", "SIA")
    assert need(r"(?i)\u017ftripe\.pay") == ("tripe.pay",)     # only plain letters are looked for
    assert need(r"\w+\(") == ("(",)
    for shows_nothing in (r"[a-z]+", r".", r"a|\d", r"(?:x)?", r"(?:ab|)", r"\d{3}\s\d{4}"):
        assert need(shows_nothing) is None, shows_nothing
        assert quick.may_match(re.compile(shows_nothing), "anything")       # nothing known: never left out
    # a pattern over bytes is not asked: the text of a file is not held as bytes by any check
    assert quick.needs(re.compile(rb"stripe\.")) is None
    # a choice is asked arm by arm up to `MOST` arms; of one with more, nothing is said
    arms = [chr(ord("a") + i) + "zz" for i in range(quick.MOST + 1)]
    assert need("|".join(arms[:-1])) == tuple(arms[:-1]) and need("|".join(arms)) is None


def test_the_quick_look_says_no_only_when_it_is_sure():
    stripe = re.compile(r"\bstripe\.checkout", re.I)
    assert not quick.may_match(stripe, "nothing about payments\nin these two lines")
    assert quick.may_match(stripe, "x = STRIPE.Checkout")
    # text that is not plain ASCII: a letter may match one that lower() does not turn into it, so the answer is yes
    assert stripe.search("\u017ftripe.checkout") and quick.may_match(stripe, "\u017ftripe.checkout")
    assert quick.may_match(stripe, "caf\u00e9 and nothing else")
    exact = re.compile(r"\bStripe\(")
    assert not quick.may_match(exact, "caf\u00e9 and nothing else")         # case matters: the text is asked as it is
    assert not quick.may_match(exact, "stripe(")
    assert quick.may_match(exact, "new Stripe(key)")


@pytest.mark.parametrize("sample", SAMPLES)
def test_the_checks_find_the_same_with_the_quick_look_and_without(sample, monkeypatch):
    from lantern.engine import build_graph
    repo = FIXTURES / sample
    g = build_graph(repo)
    loaded, _ = packs.load_all(repo)

    def found():
        fresh = build_graph(repo)
        return {"calls": aiapp.find_calls(g), "secrets": security._builtin_secrets(repo),
                "packs": packs.scan_packs(repo, loaded), "entries": packs.apply_entries(fresh, repo, loaded),
                "marked": sorted((n.id, json.dumps(n.entry, sort_keys=True)) for n in fresh.entry_points())}

    quick_way = found()
    monkeypatch.setattr(quick.Text, "may_match", lambda self, rx: True)
    assert found() == quick_way


def test_secrets_are_found_the_same_with_the_quick_look_and_without(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", {
        "a.py": "KEY = '" + "AKIA" + "Q7" * 8 + "'\nTOKEN = '" + "ghp_" + "a1B2" * 9 + "'\n",
        "b.env": "PAY=" + "sk_live_" + "a1B2c3D4" * 3 + "\n", "c.yml": "nothing: here\n",
        "d.pem": "-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n", "e.js": "const s = '" + "xoxb-" + "1234567890-abcdef" + "'\n",
        "caf\u00e9.py": "# caf\u00e9\nK = '" + "sk-ant-" + "a1B2c3D4_-" * 3 + "'\n"})
    quick_way = security._builtin_secrets(repo)
    assert {(f["rule"], f["file"]) for f in quick_way[0]} >= {("aws-access-key", "a.py"), ("github-token", "a.py"),
                                                              ("slack-token", "e.js"), ("anthropic-key", "caf\u00e9.py")}
    monkeypatch.setattr(quick.Text, "may_match", lambda self, rx: True)
    assert security._builtin_secrets(repo) == quick_way


# ---------------------------------------------------------------------------------------------- bench/speed.py
def _run_files(out: Path, when: str, took: int, extra: str = "") -> Path:
    day = time.strftime("%b", (int(when[:4]), int(when[5:7]), 1, 0, 0, 0, 0, 1, 0)) + " " + str(int(when[8:10]))
    _write(out, {
        "graph.json": '{"nodes": []}',
        "calls.json": "{}",
        "readiness.json": json.dumps({"score": 71, "generated": "2020-01-02 03:04 UTC", "incomplete": [
            {"tool": "bandit", "state": "partial", "duration_ms": took, "reason": "1 file could not be read"}]}, indent=1),
        # as `evidence.baseline_from` writes it: the day of the first analysis is the file's first key
        "baseline.json": json.dumps({"date": when[:10], "commit": "c1", "id_version": 2, "counts": {"high": 1},
                                     "findings": {"a1": {"rule": "r1", "title": "seen 2020-01-02", "line": 3,
                                                         "date": "2020-01-02"}}}, indent=1),
        "security.json": json.dumps({"findings": [{"id": "a1", "line": 3}],
                                     "tools": [{"tool": "bandit", "duration_ms": took, "state": "ok"}]}, indent=1) + extra,
        "run.json": json.dumps({"timings": {"graph": took / 7, "scan": 2.5}, "finished_at": when[:16], "offline": True}),
        "evidence.json": json.dumps({"header": {"generated_at": when, "name": "p"}, "digest": "d1"}),
        "evidence.html": f"<span>p · {when[:10]}</span><div>Analyzed</div><div>{when}</div><p>made 2020-01-02</p>",
        "badge.svg": f"<svg><text>Lantern · 0 critical · {day}</text></svg>",
        "report.html": '<script>{"generated_at":"' + when[:16] + ' PST","timings":{"graph":' + str(took) + '},'
                       '"tools":[{"duration_ms":' + str(took) + '}],"findings":[1]}</script>',
    })
    return out


def test_two_runs_are_the_same_whatever_the_clock_said(tmp_path):
    a = _run_files(tmp_path / "a", "2026-11-12 19:52 UTC", 157)
    b = _run_files(tmp_path / "b", "2026-11-13 00:03 UTC", 9131)        # another minute, another day, other times
    assert speed.differing(speed.fingerprint(a), speed.fingerprint(b)) == []
    assert set(speed.fingerprint(a)) == {"graph.json", "calls.json", "readiness.json", "baseline.json", "security.json",
                                         "run.json", "evidence.json", "evidence.html", "badge.svg", "report.html"}


@pytest.mark.parametrize("name, old, new", [
    ("security.json", '"line": 3', '"line": 4'),
    ("security.json", '"state": "ok"', '"state": "partial"'),
    ("graph.json", "[]", "[1]"),
    ("readiness.json", "71", "72"),
    ("readiness.json", '"state": "partial"', '"state": "failed"'),
    ("readiness.json", "2020-01-02 03:04 UTC", "2020-01-02 03:05 UTC"),     # only a tool's time is taken out of this file
    ("baseline.json", '"line": 3', '"line": 4'),
    ("baseline.json", '"commit": "c1"', '"commit": "c2"'),
    ("baseline.json", "seen 2020-01-02", "seen 2020-01-03"),          # a day that is not the baseline's own
    ("baseline.json", '"date": "2020-01-02"', '"date": "2020-01-03"'),  # nor is a `date` further inside the file
    ("baseline.json", '"date": "2026-11-12"', '"date": "2026-11-1"'),   # the first key, not written as a day
    ("run.json", '"offline": true', '"offline": false'),
    ("evidence.json", '"d1"', '"d2"'),
    ("evidence.html", "made 2020-01-02", "made 2020-01-03"),          # a date that is not the run's own
    ("badge.svg", "0 critical", "1 critical"),
    ("report.html", '"findings":[1]', '"findings":[2]'),
])
def test_anything_but_the_clock_is_a_difference(tmp_path, name, old, new):
    a = _run_files(tmp_path / "a", "2026-11-12 19:52 UTC", 157)
    b = _run_files(tmp_path / "b", "2026-11-12 19:52 UTC", 157)
    text = (b / name).read_text(encoding="utf-8")
    assert old in text
    (b / name).write_text(text.replace(old, new), encoding="utf-8")
    assert speed.differing(speed.fingerprint(a), speed.fingerprint(b)) == [name]


def test_a_file_with_no_tool_time_in_it_has_the_mark_of_its_bytes(tmp_path):
    import hashlib
    out = _write(tmp_path / "o", {"readiness.json": '{"score": 71,\r\n "caf\u00e9": "\u017f"}\n'})
    assert speed.fingerprint(out) == {"readiness.json": hashlib.sha256((out / "readiness.json").read_bytes()).hexdigest()}


def test_only_the_day_a_baseline_was_made_is_taken_out_of_it(tmp_path):
    """Found 2026-11-12: one side of a comparison ran at 23:59 UTC and the other after midnight, and
    `baseline.json`, then compared byte for byte, was reported as different for the two projects in between."""
    import hashlib
    made = json.dumps({"date": "2026-11-12", "commit": None, "findings": {}}, indent=1)
    a = _write(tmp_path / "a", {"baseline.json": made})
    b = _write(tmp_path / "b", {"baseline.json": made.replace("2026-11-12", "2026-11-13")})
    assert speed.fingerprint(a) == speed.fingerprint(b)
    assert speed.fingerprint(a) != {"baseline.json": hashlib.sha256(made.encode("utf-8")).hexdigest()}
    for n, text in enumerate(("{}",                                         # no day in it
                              '{"commit": null, "date": "2026-11-12"}',     # a `date` that is not the first key
                              '{"date": "today", "caf\u00e9": "\u017f"}\r\n',  # not a day
                              '{"date": "2026-11-12 "}',                    # nor is this
                              '[{"date": "2026-11-12"}]')):                 # not the file `baseline_from` writes
        out = _write(tmp_path / f"o{n}", {"baseline.json": text})
        assert speed.fingerprint(out) == {"baseline.json": hashlib.sha256((out / "baseline.json").read_bytes()).hexdigest()}
    # the day at the start is taken out once: the same text further on stays
    twice = '{"date": "2026-11-12", "then": {"date": "2026-11-12"}}'
    c = _write(tmp_path / "c", {"baseline.json": twice})
    d = _write(tmp_path / "d", {"baseline.json": twice.replace("2026-11-12", "2026-11-13", 1)})
    e = _write(tmp_path / "e", {"baseline.json": twice.replace("2026-11-12", "2026-11-13")})
    assert speed.fingerprint(c) == speed.fingerprint(d) != speed.fingerprint(e)


def test_a_file_only_one_run_wrote_is_a_difference(tmp_path):
    a = _run_files(tmp_path / "a", "2026-11-12 19:52 UTC", 157)
    b = _run_files(tmp_path / "b", "2026-11-12 19:52 UTC", 157)
    (b / "calls.json").unlink()
    assert speed.differing(speed.fingerprint(a), speed.fingerprint(b)) == ["calls.json"]
    assert speed.differing(speed.fingerprint(a), speed.fingerprint(b), names=("graph.json", "badge.svg")) == []


# What a report holds, whatever way the page holds it: the one thing of a report another engine must write the same.
def _report_bundle(took: int = 157, when: str = "2026-11-12 19:52 UTC", **changes) -> dict:
    nodes = [{"id": f"py:app.f{i}", "kind": "callable", "name": f"f{i}", "file": "app.py", "start_line": i,
              "parent": "py:app" if i else None, "decorators": []} for i in range(12)]
    edges = [{"src": f"py:app.f{i}", "dst": f"py:app.f{i + 1}", "kind": "calls", "lines": [i]} for i in range(11)]
    bundle = {"version": "1.2.3", "generated_at": when, "graph": {"schema": 7, "nodes": nodes, "edges": edges},
              "stats": {"nodes": 12}, "security": {"findings": [{"id": "a1", "line": 3}],
                                                   "tools": [{"tool": "bandit", "duration_ms": took, "state": "ok"}]},
              "sources": {"py:app.f1": "def f1(): pass"}, "privacy": "full", "timings": {"graph": took / 7, "scan": 2.5},
              "readiness": {"score": 71}}
    bundle.update(changes)
    return bundle


def _as_rows(bundle: dict) -> str:
    """The page an engine that writes the map row by row makes of a bundle (as every Lantern did until point 10)."""
    from lantern.report import DATA_OPEN, safe_json
    return "<html><p>an older page</p>" + DATA_OPEN + safe_json(bundle) + "</script></html>"


def _report_marks(tmp_path: Path, name: str, page: str) -> dict:
    return speed.fingerprint(_write(tmp_path / name, {"report.html": page}))


def test_a_report_is_marked_by_what_it_holds_however_the_page_holds_it(tmp_path):
    from lantern.report import render
    packed = _report_marks(tmp_path, "packed", render(_report_bundle()))
    rows = _report_marks(tmp_path, "rows", _as_rows(_report_bundle()))
    assert '"packed":1' in render(_report_bundle()) and '"packed"' not in _as_rows(_report_bundle())
    assert len(packed[speed.REPORT_DATA]) == 64 and packed[speed.REPORT_DATA] == rows[speed.REPORT_DATA]
    assert speed.differing(rows, packed, speed.ACROSS_ENGINES) == []
    assert speed.differing(rows, packed) == ["report.html"]             # the pages are two pages, their data is one
    assert speed.REPORT_DATA in speed.ACROSS_ENGINES and "report.html" not in speed.ACROSS_ENGINES


def test_what_a_clock_put_into_a_report_is_no_difference_in_its_data(tmp_path):
    from lantern.report import render
    a = _report_marks(tmp_path, "a", render(_report_bundle(157, "2026-11-12 19:52 UTC")))
    b = _report_marks(tmp_path, "b", _as_rows(_report_bundle(9131, "2026-11-13 00:03 UTC")))
    assert a[speed.REPORT_DATA] == b[speed.REPORT_DATA]


def _one_field_first(bundle: dict) -> dict:
    """The same nodes with two fields of each the other way round: the same data in another order."""
    first = [dict([("kind", n["kind"]), ("id", n["id"]), *list(n.items())[2:]]) for n in bundle["graph"]["nodes"]]
    return {**bundle, "graph": {**bundle["graph"], "nodes": first}}


@pytest.mark.parametrize("what, change", [
    ("a node's line", lambda b: b["graph"]["nodes"][7].update(start_line=70)),
    ("a node fewer", lambda b: b["graph"]["nodes"].pop()),
    ("where a link goes", lambda b: b["graph"]["edges"][3].update(dst="py:app.f9")),
    ("a link to a function that is not there", lambda b: b["graph"]["edges"][3].update(dst="py:app.gone")),
    ("a number for a whole number", lambda b: b["graph"]["nodes"][2].update(start_line=2.0)),
    ("an empty list for nothing", lambda b: b["graph"]["nodes"][2].update(decorators=None)),
    ("a finding's line", lambda b: b["security"]["findings"][0].update(line=4)),
    ("how a scanner ended", lambda b: b["security"]["tools"][0].update(state="partial")),
    ("a function's lines", lambda b: b["sources"].update({"py:app.f1": "def f1(): return 1"})),
    ("the score", lambda b: b["readiness"].update(score=72)),
    ("a field more", lambda b: b.update(extra=1)),
])
@pytest.mark.parametrize("held", ["packed", "rows"])
def test_anything_else_in_a_report_is_a_difference_in_its_data(tmp_path, what, change, held):
    from lantern.report import render
    make = render if held == "packed" else _as_rows
    other = _report_bundle()
    change(other)
    a = _report_marks(tmp_path, "a", render(_report_bundle()))
    b = _report_marks(tmp_path, "b", make(other))
    assert speed.REPORT_DATA in speed.differing(a, b), what


def test_the_same_data_in_another_order_is_a_difference(tmp_path):
    from lantern.report import render
    a = _report_marks(tmp_path, "a", render(_report_bundle()))
    b = _report_marks(tmp_path, "b", render(_one_field_first(_report_bundle())))
    assert speed.REPORT_DATA in speed.differing(a, b)


def test_a_report_that_cannot_be_read_back_is_a_difference_and_says_why(tmp_path):
    from lantern.report import render
    good = render(_report_bundle())
    assert '"packed":1' in good
    marks = _report_marks(tmp_path, "bad", good.replace('"packed":1', '"packed":2'))       # not a way this Lantern writes
    assert marks[speed.REPORT_DATA].startswith("not read: ") and "analyze again" in marks[speed.REPORT_DATA]
    assert speed.REPORT_DATA in speed.differing(marks, _report_marks(tmp_path, "good", good))
    cut = _report_marks(tmp_path, "cut", good[:good.index('"packed":1')] + "</script>")     # the data is cut short
    assert cut[speed.REPORT_DATA].startswith("not read: ")
    assert speed.REPORT_DATA not in _report_marks(tmp_path, "none", "<html>no data here</html>")


def test_where_the_time_of_a_run_went():
    lines = [(0.9, "graph   12 files, 30 functions, 41 internal calls, 5 entry points (0.6s)"),
             (0.95, "calls   51 calls"),
             (3.0, "scan    1 critical, 0 high, 2 medium, 0 low (2.0s)"),
             (3.4, "ready   71/100 (grade C), web app"),
             (3.4, "release Blocked"),
             (4.0, "report  /tmp/out/report.html"),
             (4.5, "proof   /tmp/out/evidence.html")]
    spent = speed.phases(lines, 4.6)
    assert spent == {"start-up": 0.3, "map": 0.6, "scan": 2.0, "readiness": 0.4, "report": 0.6, "evidence": 0.6}
    assert speed.phases(lines[:3], 3.1) == {}           # a run that did not get to its last line has no such table


def _row(name, first, repeat, marks, commit="c1", **more):
    return {"name": name, "size": "small", "commit": commit, "first_seconds": first, "repeat_seconds": repeat,
            "first_range": [first, first], "repeat_range": [repeat, repeat], "first_cpu_seconds": first,
            "first_peak_mb": 100, "first_peak_all_mb": 120, "first_report_mb": 1.5, "first_results_mb": 2.5,
            "phases": dict.fromkeys(speed.PHASES, 0.1), "marks": {"first": marks, "repeat": marks},
            "repeat_differs": [], "first_differs": [], "runs_differ": [], **more}


def test_this_run_beside_an_earlier_one():
    same = {"graph.json": "g", "calls.json": "c", "security.json": "s", "readiness.json": "r", "baseline.json": "b",
            "badge.svg": "v", "evidence.json": "one engine", "report.html": "one engine"}
    other_engine = dict(same, **{"evidence.json": "another engine", "report.html": "another engine"})
    before = {"projects": [_row("shop", 10.0, 9.0, same), _row("django", 100.0, 99.0, same),
                           _row("hugo", 20.0, 19.0, same), _row("gone", 1.0, 1.0, same)]}
    now = [_row("shop", 5.0, 2.0, other_engine),                                    # faster, the same results
           _row("django", 50.0, 20.0, dict(other_engine, **{"security.json": "fewer findings"})),
           _row("hugo", 10.0, 9.0, same, commit="c2"),                              # not the same code: not compared
           _row("new", 1.0, 1.0, same)]
    side, changed = speed.compare(before, now)
    assert changed == ["django"]
    lines = {ln.split("|")[1].strip(): ln for ln in side.splitlines()[2:]}
    assert set(lines) == {"shop", "django", "hugo"}
    assert "| 10.0 | 5.0 | 9.0 | 2.0 |" in lines["shop"] and lines["shop"].rstrip(" |").endswith("the same as before")
    assert "DIFFERENT from before: security.json" in lines["django"]
    assert "not compared: another commit" in lines["hugo"]


def test_the_table_says_failed_and_different_in_words():
    ok = _row("shop", 1.0, 0.9, {})
    differs = _row("django", 100.0, 20.0, {}, repeat_differs=["security.json"])
    failed = {"name": "hugo", "size": "medium", "failed": "Traceback\nValueError: no"}
    text = speed.table([ok, differs, failed])
    rows = {ln.split("|")[1].strip(): ln for ln in text.split("\n\n")[0].splitlines()[2:]}     # the first table
    assert rows["shop"].rstrip(" |").endswith("the same")
    assert "DIFFERENT: security.json" in rows["django"]
    assert "FAILED" in rows["hugo"] and "ValueError: no" in rows["hugo"]
