"""Cloud service: what it deletes is its own, and a delete that fails is written down, said and tried again.

Stage 7 of the 2026-11-09 directive, part 2 ("Fix silent report-retention cleanup failures. Record and safely retry
failed cleanup without deleting user-owned source folders. Test path, link and ownership boundaries.").
Until 2026-11-10:
  * at start-up the service deleted everything in its work folder and its uploads folder, whatever it was;
  * a person's delete was answered "deleted" while the result files stayed on the disk, with no record and no second
    try; a retention pass that failed every hour told nobody;
  * a repository whose folders are nested 1,100 deep left its run "running" for good, kept its owner from starting
    another, and after a restart kept the service from starting at all (Python 3.11 and 3.12).
Each dangerous case has a safe twin here: what Lantern made is removed.
"""
import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if os.name != "posix":   # said here, before anything only Linux has is imported. The shared way to delete
    # (`lantern.removal`) is tested on Windows too, in tests/test_removal.py.
    pytest.skip("the cloud worker runs on Linux (its restricted process is POSIX)", allow_module_level=True)
import resource  # noqa: E402

from test_cloud_runs import (LINK, bearer, clone_from, git, holds, left_by_a_step, make, origin,  # noqa: E402,F401
                             wait, workdir)
from fastapi.testclient import TestClient  # noqa: E402

from lantern import remote  # noqa: E402
from lantern_cloud import app as app_mod  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_cloud.store import Store  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

ADMIN = "s" * 24
MARK = ".lantern-work"          # what the worker writes into each folder it makes for a run


def settings(tmp_path, **kw) -> Settings:
    return Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                    results_dir=str(tmp_path / "results"), work_dir=workdir(tmp_path), admin_secret=ADMIN,
                    **{"audits": False, **kw})


def service(s, gw_app):
    return TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app)))


def start(tmp_path, **kw):
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = settings(tmp_path, **kw)
    return service(s, gw_app), gw_app, s


def passed(cloud, seconds=30.0):
    """The clean-up pass the service makes when it starts has ended."""
    c = cloud.app.state.cleanup
    assert c.first.wait(seconds), "the clean-up pass at start-up did not end"
    return c


def owner_sees(cloud) -> dict:
    r = cloud.get("/v1/admin/stats", headers=bearer(ADMIN))
    assert r.status_code == 200, r.text
    return r.json()["cleanup"]


def a_worker(s, store=None):
    w = worker_mod.Worker(s, store or Store(s.db_path))
    w.pool.shutdown(wait=False, cancel_futures=True)      # only what happens at start-up is tried
    return w


def a_run(store, status="done") -> str:
    rid = store.create_run("github:1", LINK, "github.com", "structure", per_day=99, global_per_day=99, per_user_active=99)
    store.update_run(rid, status=status)
    return rid


@pytest.fixture
def refuse(monkeypatch):
    """While `on`, the system says no to every delete inside a folder that is being emptied (as a disk that has gone
    read-only does). `only`: just the names that start with it."""
    state = {"on": False, "only": ""}
    real = {n: getattr(os, n) for n in ("unlink", "rmdir")}

    def make_one(name):
        def call(path, *a, **kw):
            if state["on"] and kw.get("dir_fd") is not None and os.fspath(path).startswith(state["only"]):
                raise PermissionError(13, "Read-only file system", os.fspath(path))
            return real[name](path, *a, **kw)
        return call
    for n in real:
        monkeypatch.setattr(os, n, make_one(n))
    return state


@pytest.fixture
def done_run(tmp_path, clone_from):  # noqa: F811
    cloud, gw_app, s = start(tmp_path)
    tok = gw_app.state.store.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    assert wait(cloud, tok, rid)["status"] == "done"
    return cloud, gw_app, s, tok, rid


def _outside(tmp_path, mode=0o555) -> Path:
    out = tmp_path / "outside" / "someone-elses"
    out.mkdir(parents=True)
    (out / "keep.txt").write_text("keep", encoding="utf-8")
    os.chmod(out, mode)
    return out


def _mode(p) -> int:
    return os.lstat(p).st_mode & 0o7777


# ---------------------------------------------------------------------------- at start-up: only Lantern's own
def test_at_start_the_work_folder_keeps_everything_that_is_not_lanterns(tmp_path):
    s = settings(tmp_path)
    work = Path(s.work_dir)
    (work / "my-project" / "src").mkdir(parents=True)
    (work / "my-project" / "src" / "app.py").write_text("print('mine')\n", encoding="utf-8")
    (work / "notes.txt").write_text("mine\n", encoding="utf-8")
    (work / "run-20261109" / "src").mkdir(parents=True)          # a person's folder, named the way Lantern names a run's
    (work / "run-20261109" / "src" / "main.py").write_text("print('mine too')\n", encoding="utf-8")
    outside = _outside(tmp_path)
    os.symlink(outside, work / "run-linked00")                    # a link with the name of a run's folder
    for left in ("run-abcd1234", "explain-wxyz6789"):             # what a run that was cut off leaves: Lantern's mark inside
        (work / left / "tmp").mkdir(parents=True)
        (work / left / "tmp" / "x").write_text("left by a run that was cut off\n", encoding="utf-8")
        (work / left / MARK).write_text("made by lantern-cloud for one run\n", encoding="utf-8")
    before = _mode(work)
    try:
        w = a_worker(s)
        assert sorted(p.name for p in work.iterdir()) == ["my-project", "notes.txt", "run-20261109", "run-linked00"]
        assert (work / "my-project" / "src" / "app.py").is_file() and (work / "run-20261109" / "src" / "main.py").is_file()
        assert _mode(outside) == 0o555 and (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
        assert _mode(work) in (before, 0o711)       # the work folder's own mode is the one the worker gives it
        seen = w.cleanup.state()
        assert seen["left_alone"]["work"] == 4 and seen["waiting"] == 0, seen
    finally:
        os.chmod(outside, 0o755)


def test_at_start_the_uploads_folder_keeps_everything_that_is_not_lanterns(tmp_path):
    s = settings(tmp_path)
    store = Store(s.db_path)
    over, waiting = a_run(store, "done"), a_run(store, "queued")
    up = Path(s.uploads())
    up.mkdir(parents=True, exist_ok=True)
    (up / "photos").mkdir()
    (up / "photos" / "a.jpg").write_bytes(b"jpg")
    (up / "taxes.zip").write_bytes(b"PK")                         # a .zip that is no run's
    (up / "AbCdEfGh12345678.zip").write_bytes(b"PK")              # named like a run's upload, but no run has that id
    outside = _outside(tmp_path, 0o755)
    os.symlink(outside / "keep.txt", up / ".part-00000000000000aa")   # a link with the name of a half-received upload
    (up / ".part-0123456789abcdef").write_bytes(b"PK")            # cut off while it was being received
    (up / f"{over}.zip").write_bytes(b"PK")                       # its run is over
    (up / f"{waiting}.zip").write_bytes(b"PK")                    # its run has not started yet: kept for it
    from lantern_cloud.cleanup import Cleanup
    c = Cleanup(store, s.results_dir, s.work_dir, s.uploads())
    c.sweep_uploads({waiting})
    assert sorted(p.name for p in up.iterdir()) == sorted(
        [".part-00000000000000aa", "AbCdEfGh12345678.zip", "photos", "taxes.zip", f"{waiting}.zip"])
    assert (up / "photos" / "a.jpg").is_file() and (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert c.state()["left_alone"]["uploads"] == 4, c.state()


def test_a_restart_removes_the_folder_of_a_run_that_was_cut_off(tmp_path, clone_from):  # noqa: F811
    """The safe twin, with the folder as the worker itself makes it."""
    s = settings(tmp_path)
    store = Store(s.db_path)
    w = a_worker(s, store)
    root = w.cleanup.fresh("run-")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert root.parent == Path(s.work_dir) and (root / MARK).is_file()
    a_worker(s, store)                                            # the service starts again
    assert list(Path(s.work_dir).iterdir()) == []


# ---------------------------------------------------------------------------- a delete that fails
def test_a_delete_that_cannot_remove_the_files_says_so_and_is_tried_again(done_run, refuse):
    cloud, gw_app, s, tok, rid = done_run
    passed(cloud)
    folder = Path(s.results_dir) / rid
    had = len(list(folder.iterdir()))
    assert had >= 8 and owner_sees(cloud)["waiting"] == 0 and cloud.get("/v1/health").json()["cleanup"] == "ok"
    refuse["on"] = True
    try:
        r = cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok))
    finally:
        refuse["on"] = False
    assert r.status_code == 200 and r.json() == {"deleted": rid, "files": "waiting"}
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).status_code == 404      # nobody can open it any more
    assert len(list(folder.iterdir())) == had
    seen = owner_sees(cloud)
    assert seen["waiting"] == 1 and seen["by_kind"] == {"results": 1} and seen["oldest"], seen
    assert "could not be removed" in seen["reasons"][0] and rid not in str(seen), seen   # counts and reasons, no run ids
    assert cloud.get("/v1/health").json()["cleanup"] == "ok"                           # owed for minutes, not for a day
    store = cloud.app.state.store
    with store.lock:
        store.db.execute("update leftovers set noted = ?",
                         ((dt.datetime.now(dt.UTC) - dt.timedelta(hours=25)).isoformat(),))
        store.db.commit()
    assert cloud.get("/v1/health").json()["cleanup"] == "behind"                       # owed for more than a day
    cloud.app.state.cleanup.upkeep()                                                   # the next pass, the disk well again
    assert not folder.exists()
    seen = owner_sees(cloud)
    assert seen["waiting"] == 0 and seen["last_pass"]["ok"] is True and seen["last_pass"]["removed"] == 1, seen
    assert cloud.get("/v1/health").json()["cleanup"] == "ok"


def test_a_delete_answers_removed_when_the_files_are_gone(done_run):
    """The safe twin."""
    cloud, gw_app, s, tok, rid = done_run
    r = cloud.delete(f"/v1/runs/{rid}", headers=bearer(tok))
    assert r.json() == {"deleted": rid, "files": "removed"} and not (Path(s.results_dir) / rid).exists()
    assert owner_sees(cloud)["waiting"] == 0


def test_deleting_an_account_says_when_files_wait(done_run, refuse):
    cloud, gw_app, s, tok, rid = done_run
    refuse["on"] = True
    try:
        r = cloud.delete("/v1/me", headers=bearer(tok))
    finally:
        refuse["on"] = False
    assert r.json() == {"deleted": True, "runs": 1, "files": "waiting"}
    assert (Path(s.results_dir) / rid).is_dir() and owner_sees(cloud)["by_kind"] == {"results": 1}
    cloud.app.state.cleanup.upkeep()
    assert not (Path(s.results_dir) / rid).exists() and owner_sees(cloud)["waiting"] == 0


def test_a_delete_that_was_cut_off_is_finished_when_the_service_starts_again(done_run):
    cloud, gw_app, s, tok, rid = done_run
    folder = Path(s.results_dir) / rid
    cloud.app.state.store.delete_run(rid)       # the first half of a delete; the service is cut off before the second
    assert folder.is_dir()
    again = service(s, gw_app)
    passed(again)
    assert not folder.exists() and owner_sees(again)["waiting"] == 0


def test_the_files_of_a_run_that_is_still_listed_are_never_removed_as_a_leftover(done_run):
    cloud, gw_app, s, tok, rid = done_run
    c = passed(cloud)
    store = cloud.app.state.store
    with store.lock:                            # a record that should not be there: the run is finished and listed
        store.db.execute("insert into leftovers (kind, name, noted) values ('results', ?, ?)", (rid, "2026-01-01T00:00:00+00:00"))
        store.db.commit()
    c.upkeep()
    assert (Path(s.results_dir) / rid / "report.html").is_file()
    assert store.leftovers() == [] and owner_sees(cloud)["refused"] >= 1


def test_planted_records_remove_nothing(tmp_path):
    s = settings(tmp_path)
    store = Store(s.db_path)
    Path(s.results_dir).mkdir(parents=True)
    (tmp_path / "mine.txt").write_text("mine", encoding="utf-8")            # beside the results folder
    (Path(s.results_dir) / "my-project").mkdir()
    (Path(s.results_dir) / "my-project" / "a.py").write_text("x = 1\n", encoding="utf-8")
    rows = [("results", ".."), ("results", "."), ("results", str(tmp_path)), ("results", "../mine.txt"),
            ("results", "my-project/a.py"), ("results", "short"), ("work", "my-project"), ("work", "../results"),
            ("upload", "a/b.zip"), ("upload", "taxes.zip"), ("nonsense", "AbCdEfGh12345678")]
    with store.lock:
        store.db.executemany("insert into leftovers (kind, name, noted) values (?, ?, '2026-01-01T00:00:00+00:00')", rows)
        store.db.commit()
    from lantern_cloud.cleanup import Cleanup
    c = Cleanup(store, s.results_dir, s.work_dir, s.uploads())
    c.upkeep()
    assert (tmp_path / "mine.txt").is_file() and (Path(s.results_dir) / "my-project" / "a.py").is_file()
    assert store.leftovers() == [] and c.state()["refused"] == len(rows)
    for kind, name in rows:                                                    # and Lantern never writes one down itself
        assert c.discard(kind, name) is False
    assert store.leftovers() == []


def test_a_link_with_a_runs_name_in_the_results_folder_is_not_followed(tmp_path):
    s = settings(tmp_path)
    store = Store(s.db_path)
    Path(s.results_dir).mkdir(parents=True)
    outside = _outside(tmp_path)
    rid = "AbCdEfGh12345678"
    os.symlink(outside, Path(s.results_dir) / rid)
    from lantern_cloud.cleanup import Cleanup
    c = Cleanup(store, s.results_dir, s.work_dir, s.uploads())
    try:
        assert c.discard("results", rid) is False
        assert _mode(outside) == 0o555 and (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
        left = store.leftovers()
        assert [(x["kind"], x["name"], x["tried"]) for x in left] == [("results", rid, 1)] and "link" in left[0]["why"]
    finally:
        os.chmod(outside, 0o755)


def test_a_results_folder_of_another_user_is_left(tmp_path, monkeypatch):
    s = settings(tmp_path)
    store = Store(s.db_path)
    rid = "AbCdEfGh12345678"
    (Path(s.results_dir) / rid).mkdir(parents=True)
    (Path(s.results_dir) / rid / "report.html").write_text("x", encoding="utf-8")
    me = os.geteuid()
    if me == 0:
        os.chown(Path(s.results_dir) / rid, 65534, 65534)
    else:
        monkeypatch.setattr(os, "geteuid", lambda: me + 1)
    from lantern_cloud.cleanup import Cleanup
    c = Cleanup(store, s.results_dir, s.work_dir, s.uploads())
    assert c.discard("results", rid) is False
    assert (Path(s.results_dir) / rid / "report.html").is_file() and "another user" in store.leftovers()[0]["why"]


# ---------------------------------------------------------------------------- the pass: retention, and telling the owner
def test_a_retention_pass_that_fails_is_told_to_the_owner(tmp_path, monkeypatch):
    def broken(*a, **kw):
        raise RuntimeError("the database is locked")
    real = app_mod.sweep
    monkeypatch.setattr(app_mod, "sweep", broken)
    cloud, gw_app, s = start(tmp_path, retention_days=30)
    passed(cloud)
    seen = owner_sees(cloud)
    assert seen["last_pass"]["ok"] is False and seen["last_pass"]["error"] == "RuntimeError", seen
    assert cloud.get("/v1/health").json()["cleanup"] == "ok"                 # nothing is overdue yet
    store = cloud.app.state.store
    rid = a_run(store)
    with store.lock:                                                          # a run a day past its 30 days, still here
        store.db.execute("update runs set finished = ? where id = ?",
                         ((dt.datetime.now(dt.UTC) - dt.timedelta(days=31, hours=1)).isoformat(), rid))
        store.db.commit()
    assert cloud.get("/v1/health").json()["cleanup"] == "behind"
    monkeypatch.setattr(app_mod, "sweep", real)
    cloud.app.state.cleanup.upkeep()                                         # the pass works again
    assert store.run(rid) is None and cloud.get("/v1/health").json()["cleanup"] == "ok"
    assert owner_sees(cloud)["last_pass"]["ok"] is True


def test_the_retention_pass_removes_old_runs_and_their_files(done_run, refuse):
    """The safe twin of the above, and the same record when the files cannot be removed."""
    cloud, gw_app, s, tok, rid = done_run
    store, c = cloud.app.state.store, passed(cloud)
    c.days = 30
    with store.lock:
        store.db.execute("update runs set finished = '2020-01-01T00:00:00+00:00' where id = ?", (rid,))
        store.db.commit()
    refuse["on"] = True
    try:
        c.upkeep()
    finally:
        refuse["on"] = False
    assert store.run(rid) is None and (Path(s.results_dir) / rid).is_dir() and owner_sees(cloud)["by_kind"] == {"results": 1}
    c.upkeep()
    assert not (Path(s.results_dir) / rid).exists() and owner_sees(cloud)["waiting"] == 0


def test_result_folders_no_run_points_at_are_counted_for_the_owner_and_left(done_run):
    """Folders a failed delete left before 2026-11-10 have no record: the owner is told how many, and decides."""
    cloud, gw_app, s, tok, rid = done_run
    c = passed(cloud)
    orphan = Path(s.results_dir) / "ZyXwVuTs87654321"
    orphan.mkdir()
    (orphan / "report.html").write_text("x", encoding="utf-8")
    (Path(s.results_dir) / "notes.txt").write_text("mine", encoding="utf-8")
    c.upkeep()
    assert orphan.is_dir() and (Path(s.results_dir) / rid / "report.html").is_file()
    assert owner_sees(cloud)["left_alone"]["results"] == 2


def test_the_health_page_says_one_word_about_clean_up(tmp_path):
    cloud, gw_app, s = start(tmp_path)
    passed(cloud)
    assert cloud.get("/v1/health").json()["cleanup"] == "ok"
    seen = owner_sees(cloud)
    assert seen["waiting"] == 0 and seen["by_kind"] == {} and seen["oldest"] is None and seen["behind"] is False, seen
    assert seen["left_alone"] == {"work": 0, "uploads": 0, "results": 0} and seen["last_pass"]["ok"] is True
    assert cloud.get("/v1/admin/stats").status_code == 403                    # the counts are the owner's only


# ---------------------------------------------------------------------------- the end of a run
def test_a_work_folder_that_could_not_be_removed_is_said_in_the_runs_log_and_removed_later(tmp_path, clone_from, refuse):  # noqa: F811
    cloud, gw_app, s = start(tmp_path)
    tok = gw_app.state.store.sign_in("github:1", "github:octo")
    refuse["only"], refuse["on"] = "run-", True
    try:
        rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
        done = wait(cloud, tok, rid)
    finally:
        refuse["on"] = False
    assert done["status"] == "done", done
    assert "could not remove its copy of the code" in done["log_tail"], done["log_tail"]
    left = list(Path(s.work_dir).iterdir())
    assert len(left) == 1 and left[0].name.startswith("run-") and str(left[0]) not in done["log_tail"]
    assert owner_sees(cloud)["by_kind"] == {"work": 1}
    cloud.app.state.cleanup.upkeep()
    assert list(Path(s.work_dir).iterdir()) == [] and owner_sees(cloud)["waiting"] == 0


def test_a_run_is_recorded_as_ended_even_when_tidying_up_breaks(tmp_path, clone_from, monkeypatch):  # noqa: F811
    cloud, gw_app, s = start(tmp_path)
    tok = gw_app.state.store.sign_in("github:1", "github:octo")
    passed(cloud)

    def broken(self, kind, name):
        raise RecursionError("maximum recursion depth exceeded")
    from lantern_cloud.cleanup import Cleanup
    real = Cleanup.discard
    monkeypatch.setattr(Cleanup, "discard", broken)
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    done = wait(cloud, tok, rid)
    monkeypatch.setattr(Cleanup, "discard", real)
    assert done["status"] == "done" and done["finished"], done
    nxt = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))    # and the person can start another
    assert nxt.status_code == 202, nxt.text
    wait(cloud, tok, nxt.json()["id"])
    left = list(Path(s.work_dir).iterdir())                                    # what the broken tidy-up left is written
    assert len(left) == 1 and owner_sees(cloud)["by_kind"] == {"work": 1, "upload": 1}   # down, and the next pass removes it
    cloud.app.state.cleanup.upkeep()
    assert list(Path(s.work_dir).iterdir()) == [] and owner_sees(cloud)["waiting"] == 0


@pytest.fixture
def few_open_files():
    """Room for a hundred more open files than this process holds now: plenty for a run, far too few for code that
    keeps one open per folder level."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        top = max(int(n) for n in os.listdir("/proc/self/fd"))
    except (OSError, ValueError):
        top = 400
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(soft, top + 100), hard))
    yield
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


@pytest.fixture
def deep_origin(tmp_path):
    """A repository whose folders are nested 1,100 deep (more than Python 3.11 and 3.12 recurse)."""
    src = tmp_path / "origin-deep" / "shop"
    shutil.copytree(Path(__file__).resolve().parent / "fixtures" / "shop", src)
    fd = os.open(src, os.O_RDONLY)
    for _ in range(1100):
        os.mkdir("d", dir_fd=fd)
        nxt = os.open("d", os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = nxt
    with open(os.open("leaf.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w", encoding="utf-8") as f:
        f.write("x = 1\n")
    os.close(fd)
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    yield src
    subprocess.run(["rm", "-rf", "--", str(src.parent)], capture_output=True)


def test_a_repository_nested_1100_deep_ends_its_run_and_leaves_nothing(tmp_path, monkeypatch, deep_origin, few_open_files):
    def fake_clone(link, dest, log):
        log(f"cloning {link}")
        git("clone", "-q", "--depth", "1", deep_origin.as_uri(), str(dest), cwd=dest.parent)
        remote._mark(dest)
        return dest
    monkeypatch.setattr(worker_mod, "clone_repo", fake_clone)
    cloud, gw_app, s = start(tmp_path)
    tok = gw_app.state.store.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    try:
        done = wait(cloud, tok, rid, timeout=240)
        assert done["status"] in ("done", "error") and done["finished"], done
        assert list(Path(s.work_dir).iterdir()) == [], "the copy of the repository is still in the work folder"
        assert owner_sees(cloud)["waiting"] == 0
        nxt = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
        assert nxt.status_code == 202, nxt.text                                # the person is not kept from the next check
        wait(cloud, tok, nxt.json()["id"], timeout=240)
        a_worker(s, cloud.app.state.store)                                     # and the service starts again
    finally:
        for p in Path(s.work_dir).iterdir():
            subprocess.run(["rm", "-rf", "--", str(p)], capture_output=True)


def test_a_cut_off_run_nested_1100_deep_does_not_keep_the_service_from_starting(tmp_path, few_open_files):
    s = settings(tmp_path)
    store = Store(s.db_path)
    w = a_worker(s, store)
    root = w.cleanup.fresh("run-")
    fd = os.open(root, os.O_RDONLY)
    for _ in range(1100):
        os.mkdir("d", dir_fd=fd)
        nxt = os.open("d", os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = nxt
    os.close(fd)
    try:
        a_worker(s, store)
        assert list(Path(s.work_dir).iterdir()) == []
    finally:
        subprocess.run(["rm", "-rf", "--", str(root)], capture_output=True)


def test_the_store_keeps_the_record_in_the_same_step_as_the_delete(tmp_path):
    store = Store(str(tmp_path / "c.db"))
    a, b = a_run(store), a_run(store)
    from lantern_cloud.cleanup import RUN_ID
    assert RUN_ID.fullmatch(a) and RUN_ID.fullmatch(b)      # the names the store gives are the names clean-up removes
    store.delete_run(a)
    assert [(x["kind"], x["name"], x["tried"]) for x in store.leftovers()] == [("results", a, 0)]
    assert store.delete_user("github:1") == [b]
    assert sorted(x["name"] for x in store.leftovers()) == sorted([a, b])
    store.leftover_failed("results", a, "1 thing in it could not be removed")
    assert [(x["tried"], x["why"]) for x in store.leftovers() if x["name"] == a] == [(1, "1 thing in it could not be removed")]
    store.forget_leftover("results", a)
    store.forget_leftover("results", b)
    assert store.leftovers() == []
    db = sqlite3.connect(str(tmp_path / "c.db"))      # an earlier database gets the table when the service starts
    db.execute("drop table leftovers")
    db.commit()
    db.close()
    assert Store(str(tmp_path / "c.db")).leftovers() == []


# ---------------------------------------------------------------------------- what the service takes from a step
SECRET = "KEPT-FROM-EVERY-RUN-7351"


def elsewhere(tmp_path) -> Path:
    """A folder that is no run's, holding files named like results, each with a secret in it."""
    d = tmp_path / "elsewhere"
    (d / "cache").mkdir(parents=True)
    for name in (*worker_mod.RESULT_FILES, "explanations.json", "planted.json", "cache/0123456789abcdef01234567.json"):
        (d / name).write_text(json.dumps({"meta": {"files": 1}, "stats": {}, "secret": SECRET}), encoding="utf-8")
        os.chmod(d / name, 0o600)
    return d


@pytest.mark.parametrize("where,what,how", [("out/graph.json", "graph.json", "link"),
                                            ("out/graph.json", "graph.json", "second name"),
                                            ("out", "", "link")],
                         ids=["a link", "a second name of a file", "the whole folder is a link"])
def test_a_result_file_that_is_a_link_is_not_followed(tmp_path, clone_from, monkeypatch, where, what, how):  # noqa: F811
    """The service takes the result files from a step that runs with fewer rights than itself. Only plain files of
    the step's own folder are taken. A link where a result belongs is never followed, a file that has a second name
    somewhere else is not read, and the folder itself is opened only when it is a real folder: until 2026-11-10 the
    file a link pointed at was copied into the run's results, where the run's owner can download it."""
    other = elsewhere(tmp_path)
    left_by_a_step(monkeypatch, "analyze", where, other / what if what else other, how)
    cloud, gw_app, s = start(tmp_path)
    tok = gw_app.state.store.sign_in("github:1", "github:octo")
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok)).json()["id"]
    done = wait(cloud, tok, rid)
    assert holds(Path(s.results_dir), SECRET) == [], "a file outside the run was copied into its results"
    assert done["status"] == "error" and "not a plain file" in done["error"], done
    assert not (Path(s.results_dir) / rid).exists() and list(Path(s.work_dir).iterdir()) == []
    assert all(q.read_text(encoding="utf-8").count(SECRET) == 1 for q in other.rglob("*") if q.is_file())   # untouched
    assert sorted(q.name for q in other.iterdir()) == sorted(["cache", "explanations.json", "planted.json",
                                                              *worker_mod.RESULT_FILES])


def _fresh(tmp_path):
    out, dest = tmp_path / "out", tmp_path / "kept"
    (out / "cache").mkdir(parents=True)
    dest.mkdir()
    (out / "report.html").write_text("<p>the report</p>", encoding="utf-8")
    (out / "graph.json").write_text("{}", encoding="utf-8")
    (out / "cache" / "0123456789abcdef01234567.json").write_text('{"lens1": {}}', encoding="utf-8")
    return out, dest


def test_plain_files_are_taken_as_they_are(tmp_path):
    """The safe twin of every case below: what the step wrote as plain files arrives, byte for byte."""
    out, dest = _fresh(tmp_path)
    assert worker_mod._take(out, worker_mod.RESULT_FILES, dest) == ["report.html", "graph.json"]
    assert (dest / "report.html").read_text(encoding="utf-8") == "<p>the report</p>"
    assert worker_mod._take(out, ("report.html",), dest, as_name=".{}.new") == ["report.html"]
    assert (dest / ".report.html.new").is_file()
    assert worker_mod._there(out, "report.html") and not worker_mod._there(out, "evidence.html")
    (out / "cache" / "inner").mkdir()
    (out / "cache" / "inner" / "x.json").write_text("1", encoding="utf-8")
    (dest / "cache").mkdir()
    (dest / "cache" / "from-before.json").write_text('"kept"', encoding="utf-8")
    held = len(os.listdir("/dev/fd"))
    assert worker_mod._take_tree(out, "cache", dest / "cache") == 2
    assert len(os.listdir("/dev/fd")) == held, "a file or folder was left open"
    assert sorted(q.relative_to(dest).as_posix() for q in (dest / "cache").rglob("*")) == [
        "cache/0123456789abcdef01234567.json", "cache/from-before.json", "cache/inner", "cache/inner/x.json"]
    assert worker_mod._take(tmp_path / "not-there", ("report.html",), dest) == []      # no folder: nothing, no error
    assert worker_mod._take_tree(out, "not-there", dest / "none") == 0
    assert not (dest / "none").exists() and not worker_mod._there(tmp_path / "not-there", "report.html")


@pytest.mark.parametrize("shape", ["a link to a file", "a link to nothing", "a second name", "a folder", "a pipe",
                                   "the folder is a link"])
def test_what_is_not_a_plain_file_is_not_taken(tmp_path, shape):
    other = elsewhere(tmp_path)
    out, dest = _fresh(tmp_path)
    at = out / "graph.json"
    at.unlink()
    if shape == "a link to a file":
        os.symlink(other / "graph.json", at)
    elif shape == "a link to nothing":
        os.symlink(tmp_path / "nothing-here", at)
    elif shape == "a second name":
        os.link(other / "graph.json", at)
    elif shape == "a folder":
        at.mkdir()
    elif shape == "a pipe":
        os.mkfifo(at)
    else:
        shutil.rmtree(out)
        os.symlink(other, out)
    held = len(os.listdir("/dev/fd"))
    with pytest.raises(worker_mod.NotPlain):
        worker_mod._take(out, worker_mod.RESULT_FILES, dest)
    assert holds(dest, SECRET) == []
    assert len(os.listdir("/dev/fd")) == held, "a file or folder was left open"
    if shape == "the folder is a link":
        with pytest.raises(worker_mod.NotPlain):
            worker_mod._there(out, "report.html")
        with pytest.raises(worker_mod.NotPlain):
            worker_mod._take_tree(out, "cache", dest / "cache")
        assert not (dest / "cache").exists()
    else:
        assert worker_mod._there(out, "graph.json")        # it is there, and it is looked at without being opened


@pytest.mark.parametrize("shape", ["a link to a file", "a second name", "a link to a folder", "the cache is a link",
                                   "a pipe", "nested too deep"])
def test_a_cache_with_anything_but_plain_files_is_not_taken_at_all(tmp_path, shape):
    """Looked at whole before the first file is copied: one thing that is not a plain file or a real folder, and
    nothing of the cache is kept."""
    other = elsewhere(tmp_path)
    out, dest = _fresh(tmp_path)
    cache = out / "cache"
    if shape == "a link to a file":
        os.symlink(other / "planted.json", cache / "zz-planted.json")
    elif shape == "a second name":
        os.link(other / "planted.json", cache / "zz-planted.json")
    elif shape == "a link to a folder":
        os.symlink(other, cache / "zz-more")
    elif shape == "the cache is a link":
        shutil.rmtree(cache)
        os.symlink(other / "cache", cache)
    elif shape == "a pipe":
        os.mkfifo(cache / "zz-pipe")
    else:
        deep = cache
        for _ in range(worker_mod.MAX_CACHE_DEPTH + 1):
            deep = deep / "d"
        deep.mkdir(parents=True)
        (deep / "x.json").write_text("1", encoding="utf-8")
    held = len(os.listdir("/dev/fd"))
    with pytest.raises(worker_mod.NotPlain):
        worker_mod._take_tree(out, "cache", dest / "cache")
    assert not (dest / "cache").exists() and holds(dest, SECRET) == []
    assert len(os.listdir("/dev/fd")) == held, "a file or folder was left open"


def test_a_cache_file_that_cannot_be_copied_whole_leaves_the_one_from_before(tmp_path, monkeypatch):
    """An explanation that is already kept is replaced only by a whole file: a copy that stops half-way (a full
    disk) leaves the old one as it was and nothing half-written beside it."""
    out, dest = _fresh(tmp_path)
    name = "0123456789abcdef01234567.json"
    (dest / "cache").mkdir()
    (dest / "cache" / name).write_text('{"paid": "for"}', encoding="utf-8")

    def half(src, to, *a, **kw):
        to.write(b'{"le')
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(shutil, "copyfileobj", half)
    with pytest.raises(OSError):
        worker_mod._take_tree(out, "cache", dest / "cache")
    assert [q.name for q in (dest / "cache").iterdir()] == [name]
    assert (dest / "cache" / name).read_text(encoding="utf-8") == '{"paid": "for"}'


def test_a_run_whose_result_files_are_plain_is_kept_whole(done_run):
    cloud, _gw, s, tok, rid = done_run                                           # the safe twin
    kept = {p.name for p in (Path(s.results_dir) / rid).iterdir()}
    assert {"report.html", "evidence.html", "graph.json", "security.json", "readiness.json"} <= kept
    assert cloud.get(f"/v1/runs/{rid}", headers=bearer(tok)).json()["summary"]["score"] is not None


def test_the_website_says_when_a_deleted_runs_files_wait(tmp_path):
    """The page reads the answer of a delete; tools/cloud_site_smoke.js presses it in a browser."""
    cloud, gw_app, s = start(tmp_path)
    page = cloud.get("/").text
    assert page.count("done.files === 'waiting'") == 2 and page.count("filesWaitSheet(") == 3
    assert "could not remove its files" in page and "tries again by itself" in page
