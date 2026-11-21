"""The website's own run of a check whose tests were asked for (a firm pass or fail, stage 3, step 5, part (c)).

The website runs no test of a project itself. For a check that asks for its tests (`runs.tests`), a step of the
check's own user fetches the libraries the project names for the test machine and packs them with the project
(`lantern.runner prepare`); the website reads the archive out of that step's folder without following anything,
hands it to a test machine made for the check (`machines.Machines.run`, stood in for here: what a machine's program
answers, `tests/test_cloud_machines.py` and `tests/test_runner.py` have the real ones), and gives the analysis the
machine's result in a file it makes fresh (`LANTERN_TESTS_FROM`). The machine's minutes are not the check's own.

Each refusal stands beside the run that goes through. The clone step copies a local repository (the real one is
https only: `tests/test_remote.py`); everything after it is the real worker."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if not sys.platform.startswith("linux"):
    pytest.skip("the website runs its steps on Linux", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cloud"))
from test_cloud_runs import git  # noqa: E402
from test_runner_prepare import UNITTEST, _machine_result  # noqa: E402

from lantern import remote, runner  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_cloud.store import Store  # noqa: E402

LINK = "https://github.com/octo/adder"
ASKED = {"command": UNITTEST, "cwd": "", "minutes": 3, "memory": 512}
APP = "def add(a, b):\n    return a + b\n"
TEST_IT = ("import unittest\n\nfrom app import add\n\n\nclass T(unittest.TestCase):\n    def test_add(self):\n"
           "        self.assertEqual(add(1, 2), 3)\n")


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    src = tmp_path_factory.mktemp("origin") / "adder"
    src.mkdir()
    (src / "app.py").write_text(APP, encoding="utf-8")
    (src / "test_it.py").write_text(TEST_IT, encoding="utf-8")
    (src / "requirements.txt").write_text("", encoding="utf-8")
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    return src


@pytest.fixture
def clone_from(monkeypatch, origin):
    """The clone step copies the local repository; `files` are written into the copy (another project's needs)."""
    more: dict[str, str] = {}

    def fake_clone(link, dest, log):
        git("clone", "-q", "--depth", "1", origin.as_uri(), str(dest), cwd=dest.parent)
        for name, text in more.items():
            (dest / name).parent.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(text, encoding="utf-8")
        remote._mark(dest)
        return dest
    monkeypatch.setattr(worker_mod, "clone_repo", fake_clone)
    return more


def _done(settings: dict, **tests) -> dict:
    """What a machine's program answers for tests that ran, about the check it was handed."""
    r = _machine_result(**{"memory_limit": settings["memory"], **tests})
    r["check"].update(command=settings["command"], cwd=settings["cwd"], minutes=settings["minutes"],
                      memory=settings["memory"])
    return r


class StandIn:
    """The test machines, stood in for: what the worker hands them is written down, and each check gets `answer`
    (from the settings packed into its archive). `took`: seconds the machine's run takes on the worker's clock."""

    def __init__(self, answer=_done, archive_mb: int = 64, raises: Exception | None = None, took: float = 0.0,
                 clock=None):
        self.answer, self.archive_mb, self.raises, self.took, self.clock = answer, archive_mb, raises, took, clock
        self.got: list[dict] = []

    def run(self, archive, minutes, memory, log=None, cancel=None):
        archive = Path(archive)
        st, folder = os.lstat(archive), os.lstat(archive.parent)
        work = Path(tempfile.mkdtemp(prefix="lantern-stand-in-")) / "w"
        try:
            taken = runner.take(archive, work)
            files = sorted(p.relative_to(taken["project"]).as_posix() for p in taken["project"].rglob("*")
                           if p.is_file())
            settings = taken["settings"]
        finally:
            shutil.rmtree(work.parent, ignore_errors=True)
        self.got.append({"archive": archive, "plain": stat.S_ISREG(st.st_mode), "owner": st.st_uid,
                         "folder_owner": folder.st_uid, "folder_mode": stat.S_IMODE(folder.st_mode),
                         "minutes": minutes, "memory": memory, "settings": settings, "files": files})
        if log:
            log("machine the stand-in ran the tests")
        if self.clock is not None:
            self.clock.ahead += self.took
        if self.raises is not None:
            raise self.raises
        return self.answer(settings)

    def sweep_forever(self, over: threading.Event) -> None:
        over.wait()


class Clock:
    """The worker's clock, `ahead` seconds ahead of the real one once a stand-in machine has taken its time."""

    def __init__(self):
        self.ahead = 0.0

    def __getattr__(self, name):
        return getattr(time, name)

    def monotonic(self) -> float:
        return time.monotonic() + self.ahead


def _workdir() -> Path:
    """Under /tmp itself: where the tests run as root the steps run as a check's own user, who cannot pass through
    pytest's private temp folders."""
    w = Path(tempfile.mkdtemp(prefix="lantern-cloud-tests-"))
    os.chmod(w, 0o755)
    return w


@pytest.fixture
def website(tmp_path):
    """A worker of the website with the test machines it is handed, and what each of its steps was."""
    made: list = []

    def make(machines=None, **kw):
        w = _workdir()
        s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / f"cloud{len(made)}.db"),
                     results_dir=str(w / "results"), work_dir=str(w / "work"),
                     **{"audits": False, "clone_max_mb": 50, **kw})
        store = Store(s.db_path)
        worker = worker_mod.Worker(s, store, machines=machines)
        made.append((worker, w))
        return worker, store
    yield make
    for worker, w in made:
        worker.shutdown()
        shutil.rmtree(w, ignore_errors=True)


@pytest.fixture
def steps(monkeypatch):
    """Each restricted step of a run: its program's module, whether it had the network, and its user."""
    seen: list[dict] = []
    real = worker_mod.Worker._jailed

    def watched(self, rid, root, cmd, **kw):
        module = cmd[cmd.index("-m") + 1] if "-m" in cmd else cmd[0]
        seen.append({"module": module, "net": kw.get("net"), "user": self.users.of(root),
                     "env": dict(kw.get("extra") or {})})
        return real(self, rid, root, cmd, **kw)
    monkeypatch.setattr(worker_mod.Worker, "_jailed", watched)
    return seen


def _check(worker, store, tests=ASKED) -> tuple[dict, dict | None]:
    rid = store.create_run("github:1", LINK, "github.com", "structure", per_day=100, global_per_day=1000,
                           per_user_active=10, tests=tests)
    worker.run(rid)
    r = store.run(rid)
    out = Path(worker.results) / rid
    run = json.loads((out / "run.json").read_text(encoding="utf-8")) if (out / "run.json").is_file() else None
    return r, run


def _release_tests(out: Path) -> dict:
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    return next(c for c in rd["release"]["criteria"] if c["id"] == "tests")


# ---------------------------------------------------------------------------- the run that goes through
def test_a_check_that_asks_for_its_tests_has_them_run_on_a_test_machine(website, clone_from, steps):
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store)
    assert r["status"] == "done", (r["error"], r["log_tail"])
    assert r["tests"] == ASKED
    # the packing was a step of the check's own user, with the network, as the audits get it; the analysis had none
    modules = [s["module"] for s in steps]
    assert modules.index("lantern.runner") < modules.index("lantern.cli"), modules
    pack = next(s for s in steps if s["module"] == "lantern.runner")
    analysis = next(s for s in steps if s["module"] == "lantern.cli")
    assert pack["net"] is True and analysis["net"] is False
    assert pack["user"] == analysis["user"]
    if os.geteuid() == 0:
        assert pack["user"] is not None            # never the service's own user, where the service is root
    assert analysis["env"]["LANTERN_TESTS_FROM"].endswith(".json")
    # the machine was handed the check's own archive, as a plain file in a folder of the service's own
    (got,) = machines.got
    assert got["plain"] and got["owner"] == os.geteuid() and got["folder_owner"] == os.geteuid()
    assert got["folder_mode"] == 0o700
    assert (got["minutes"], got["memory"]) == (3, 512)
    assert (got["settings"]["command"], got["settings"]["cwd"]) == (UNITTEST, "")
    assert {"app.py", "test_it.py"} <= set(got["files"]) and not any(f.startswith(".git/") for f in got["files"])
    assert not got["archive"].exists()               # removed once the machine was done with it
    # and the report has the machine's run
    tr = run["trace"]
    assert tr["ran"] is True and tr["place"] == "test machine" and tr["returncode"] == 0, tr
    assert tr["command"] == UNITTEST and tr["observed_edges"] >= 1
    assert _release_tests(Path(worker.results) / r["id"])["state"] == "passed"
    assert "Running your tests on a test machine made for this check" in r["log_tail"]


def test_tests_that_failed_on_the_machine_failed(website, clone_from):
    worker, store = website(StandIn(answer=lambda s: _done(s, returncode=1)))
    r, run = _check(worker, store)
    assert r["status"] == "done" and run["trace"]["returncode"] == 1
    assert _release_tests(Path(worker.results) / r["id"])["state"] == "failed"


def test_a_check_that_asks_for_no_tests_hands_nothing_to_a_machine(website, clone_from, steps):
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store, tests=None)
    assert r["status"] == "done" and r["tests"] is None
    assert machines.got == [] and "lantern.runner" not in [s["module"] for s in steps]
    assert "trace" not in run or not run["trace"], run.get("trace")
    assert all("LANTERN_TESTS_FROM" not in s["env"] for s in steps)


def test_the_machines_minutes_are_not_the_checks_own(website, clone_from, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(worker_mod, "time", clock)
    machines = StandIn(took=4 * 3600, clock=clock)            # four hours on a test machine
    worker, store = website(machines, job_timeout=600)       # the website's own ten minutes
    r, run = _check(worker, store)
    assert r["status"] == "done", r["error"]
    assert clock.ahead == 4 * 3600 and run["trace"]["place"] == "test machine"


@pytest.mark.parametrize("folder", ["-x", "--", "--minutes"])
def test_a_test_folder_whose_name_begins_with_a_dash_is_a_folder_and_no_setting(website, clone_from, folder):
    # a folder of the project's own may be called that; the packing step and the analysis are told it as a folder
    clone_from[f"{folder}/app.py"], clone_from[f"{folder}/test_it.py"] = APP, TEST_IT
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store, tests={**ASKED, "cwd": folder})
    assert r["status"] == "done", (r["error"], r["log_tail"])
    (got,) = machines.got
    assert got["settings"]["cwd"] == folder and got["settings"]["command"] == UNITTEST
    tr = run["trace"]                                # the analysis read the machine's result as this check's
    assert tr["ran"] is True and tr["place"] == "test machine", tr


# ---------------------------------------------------------------------------- where the tests do not run there
def test_with_the_machines_off_nothing_is_packed_and_the_report_says_why(website, clone_from, steps):
    worker, store = website(None)
    r, run = _check(worker, store)
    assert r["status"] == "done", r["error"]
    assert "lantern.runner" not in [s["module"] for s in steps]
    tr = run["trace"]
    assert tr["ran"] is False and tr["not_run_for"] == "machine" and tr["unavailable"] == worker_mod.MACHINES_OFF
    assert _release_tests(Path(worker.results) / r["id"])["state"] == "missing"


def test_libraries_from_another_store_are_not_fetched_and_no_machine_is_made(website, clone_from):
    clone_from["requirements.txt"] = "--index-url https://packages.example.invalid/simple\nstage2sample==1.0.0\n"
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store)
    assert r["status"] == "done", r["error"]
    assert machines.got == []
    tr = run["trace"]
    assert tr["ran"] is False and tr["not_run_for"] == "libraries", tr
    assert _release_tests(Path(worker.results) / r["id"])["state"] == "missing"


@pytest.mark.parametrize("said", [
    {"version": 1, "state": "unable", "why_not": "The tests' own network could not be made on this machine."},
    {"version": 1, "state": "refused", "why_not": "The check's archive is not a .zip the test machine can read."},
    {"version": 1, "state": "stopped", "why_not": "The tests ran past their minutes and were stopped."}])
def test_what_the_machine_said_of_tests_it_did_not_run_is_in_the_report(website, clone_from, said):
    worker, store = website(StandIn(answer=lambda s: said))
    r, run = _check(worker, store)
    assert r["status"] == "done", r["error"]
    tr = run["trace"]
    assert tr["ran"] is False and tr["not_run_for"] == "machine" and tr["unavailable"] == said["why_not"]


def test_a_machine_that_fails_leaves_the_check_without_its_tests(website, clone_from):
    worker, store = website(StandIn(raises=KeyError("a bug of Lantern's own")))
    r, run = _check(worker, store)
    assert r["status"] == "done", r["error"]
    assert run["trace"]["unavailable"] == worker_mod.MACHINE_FAILED and run["trace"]["not_run_for"] == "machine"


def test_an_archive_larger_than_a_machine_is_handed_is_not_handed(website, clone_from):
    machines = StandIn(archive_mb=0)
    worker, store = website(machines)
    r, run = _check(worker, store)
    assert r["status"] == "done" and machines.got == []
    assert run["trace"]["unavailable"] == worker_mod.TOO_LARGE.format(mb=0)


def test_a_file_that_grows_after_it_was_measured_is_copied_no_further_than_its_limit(tmp_path, monkeypatch):
    """The size is first read from what is open; a step still writing may make it longer while it is copied. The copy
    stops at the limit, and a file of exactly the limit is copied whole (the twin)."""
    src = tmp_path / "step"
    src.mkdir()
    (src / "check.zip").write_bytes(b"x" * 10)
    real_fstat = os.fstat

    def measured_short(f):                   # what it said when it was measured, before it grew
        st = real_fstat(f)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 4,
                               st.st_atime, st.st_mtime, st.st_ctime))
    fd = os.open(src, os.O_RDONLY)
    try:
        assert worker_mod._take_one(fd, "check.zip", tmp_path / "whole", most=10)
        assert (tmp_path / "whole").read_bytes() == b"x" * 10
        monkeypatch.setattr(os, "fstat", measured_short)
        with pytest.raises(worker_mod.TooLarge):
            worker_mod._take_one(fd, "check.zip", tmp_path / "cut", most=9)
        assert len((tmp_path / "cut").read_bytes()) <= 9
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------- what a packing step leaves
def _after_the_packing(monkeypatch, then) -> None:
    """`then(root)` once the packing step has ended (the step itself runs as it always does)."""
    real = worker_mod.Worker._jailed

    def and_then(self, rid, root, cmd, **kw):
        got = real(self, rid, root, cmd, **kw)
        if "lantern.runner" in cmd:
            then(root)
        return got
    monkeypatch.setattr(worker_mod.Worker, "_jailed", and_then)


def _kept_by_the_service(tmp_path: Path) -> Path:
    secret = tmp_path / "service-only.txt"
    secret.write_text("kept-by-the-service-alone", encoding="utf-8")
    return secret


@pytest.mark.parametrize("where", [runner.ARCHIVE, runner.PREPARED])
def test_a_link_left_in_the_packing_steps_folder_is_never_followed(website, clone_from, monkeypatch, tmp_path, where):
    secret = _kept_by_the_service(tmp_path)

    def plant(root):
        at = root / "tmp" / "pack" / where
        at.unlink()
        os.symlink(secret, at)
    _after_the_packing(monkeypatch, plant)
    machines = StandIn()
    worker, store = website(machines)
    r, _run = _check(worker, store)
    assert r["status"] == "error" and r["error"] == worker_mod.NOT_PLAIN
    assert machines.got == [] and secret.read_text(encoding="utf-8") == "kept-by-the-service-alone"


def test_a_link_where_the_machines_result_goes_is_never_written_through(website, clone_from, monkeypatch, tmp_path):
    secret = _kept_by_the_service(tmp_path)
    _after_the_packing(monkeypatch, lambda root: os.symlink(secret.parent, root / "tmp" / "tests"))
    worker, store = website(StandIn())
    r, _run = _check(worker, store)
    assert r["status"] == "error" and r["error"] == worker_mod.NOT_PLAIN
    assert sorted(p.name for p in secret.parent.iterdir() if p.suffix == ".json") == []
    assert secret.read_text(encoding="utf-8") == "kept-by-the-service-alone"


def test_a_packing_step_that_says_another_check_hands_nothing_to_a_machine(website, clone_from, monkeypatch):
    def rewrite(root):
        f = root / "tmp" / "pack" / runner.PREPARED
        said = json.loads(f.read_text(encoding="utf-8"))
        f.write_text(json.dumps({**said, "minutes": 240}), encoding="utf-8")
    _after_the_packing(monkeypatch, rewrite)
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store)
    assert r["status"] == "done" and machines.got == []
    assert run["trace"]["unavailable"] == worker_mod.PREPARE_FAILED


# ---------------------------------------------------------------------------- what a check asks of its tests
def test_what_a_check_asks_of_its_tests_is_taken_by_shape():
    assert worker_mod.tests_asked({"tests": None}) is None
    assert worker_mod.tests_asked({"tests": dict(ASKED)}) == ASKED
    assert worker_mod.tests_asked({"tests": {**ASKED, "cwd": "web/tests"}})["cwd"] == "web/tests"
    for bad in ([UNITTEST], "python -m unittest", {**ASKED, "more": 1}, {k: v for k, v in ASKED.items() if k != "cwd"},
                {**ASKED, "command": ["python", "app.py"]}, {**ASKED, "command": ["pnpm", "test"]},
                {**ASKED, "command": "python -m unittest"}, {**ASKED, "minutes": 0}, {**ASKED, "minutes": True},
                {**ASKED, "memory": 64}, {**ASKED, "cwd": "../up"}, {**ASKED, "cwd": "/etc"}):
        with pytest.raises(worker_mod.RunFailed):
            worker_mod.tests_asked({"tests": bad})


def test_a_check_whose_tests_are_asked_in_another_shape_runs_nothing(website, clone_from, steps):
    machines = StandIn()
    worker, store = website(machines)
    r, run = _check(worker, store, tests={**ASKED, "command": ["python", "app.py"]})
    assert r["status"] == "error" and "not one the test machine runs" in r["error"]
    assert steps == [] and machines.got == [] and run is None


def test_the_analysis_is_told_the_tests_but_runs_none(website):
    assert worker_mod.tests_words(None) == []
    words = worker_mod.tests_words({**ASKED, "cwd": "web"})
    assert words[:3] == ["--trace", "--sandbox", "--test-cwd=web"]
    assert words[words.index("--") + 1:] == UNITTEST


def test_the_tests_asked_are_kept_with_the_check(tmp_path):
    store = Store(str(tmp_path / "c.db"))
    rid = store.create_run("github:1", LINK, "github.com", "structure", per_day=9, global_per_day=9, per_user_active=9,
                           tests=ASKED)
    assert store.run(rid)["tests"] == ASKED
    other = store.create_run("github:1", LINK, "github.com", "structure", per_day=9, global_per_day=9,
                             per_user_active=9)
    assert store.run(other)["tests"] is None


def test_an_earlier_database_gets_the_column(tmp_path):
    db = tmp_path / "old.db"
    Store(str(db))                                          # today's, then made as it was before the column
    con = sqlite3.connect(db)
    con.execute("alter table runs drop column tests")
    con.execute("insert into runs (id, account, link, host, privacy, status, created) values "
                "('r1', 'github:1', 'https://github.com/o/a', 'github.com', 'structure', 'done', '2026-11-20T10:00:00')")
    con.commit()
    con.close()
    store = Store(str(db))
    assert "tests" in {row[1] for row in store.db.execute("pragma table_info(runs)")}
    assert store.run("r1")["tests"] is None


def test_the_website_hands_its_test_machines_to_its_worker(tmp_path):
    machines = StandIn()
    w = _workdir()
    try:
        s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "c.db"),
                     results_dir=str(w / "results"), work_dir=str(w / "work"), audits=False)
        app = create_app(s, transport=httpx.MockTransport(lambda request: httpx.Response(503)), test_machines=machines)
        assert app.state.worker.machines is machines and app.state.test_machines is machines
        app.state.worker.shutdown()
        off = create_app(s, transport=httpx.MockTransport(lambda request: httpx.Response(503)))
        assert off.state.worker.machines is None            # no key and no image: the machines are off
        off.state.worker.shutdown()
    finally:
        shutil.rmtree(w, ignore_errors=True)

