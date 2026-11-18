"""The cloud service's restricted steps, each check under a user of its own (website stage, step 2, 2026-11-18).

A check of a project is done in steps that read the project and never run it: unpacking an upload, the dependency
audit, the analysis, the explanations. Each runs in the restricted process (`lantern/_jail.py`), whose walls keep it
from writing outside its own folder and from the network. Until this change every step ran as one user: as root's
`nobody`, or, where the service is not root, as the service's own user. A step that was taken over (a hole in a
reader that some project's files find) could read what that user may read: what other checks hold while they run,
and, as the service's own user, the service's database, every check's results and the service's running program
(threat model, open risk 0).

Now, where the service is root, each check is given a user of its own from a range nobody else uses
(`_jail.STEP_USERS`, `apart.StepUsers`), its folders are handed to that user and closed to every other, the
service's own files are closed to others when it starts (`apart.close_up`), a step that reads no network has a
network of its own, what is still running as the check's user when the check ends is ended, and before each check
a step of that check's user tries to read the service's files and the check goes on only where it could not
(`apart.PROOF`). Where `LANTERN_CLOUD_STEPS_APART=required` (the website's image) a service that cannot keep checks
apart starts none.

Each test that needs root says so (only root can run a step as another user); CI runs this file a second time as
root, where a skipped test fails the run.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if not sys.platform.startswith("linux"):
    pytest.skip("the cloud service runs its steps on Linux", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402
from test_cloud_runs import LINK, bearer, git, wait  # noqa: E402

from lantern import _jail, remote  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.cleanup import MARK, MARK_TEXT, Cleanup  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_cloud.store import Store  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

AS_ROOT = pytest.mark.skipif(os.geteuid() != 0, reason="needs root: only root can run a step as another user")
SECRET = "kept-by-the-service-alone"
SOMEONE = "AbCdEfGh12345678"                     # another person's finished check
FORMER = 1000                                    # the user the website's image ran the service as until this change


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    src = tmp_path_factory.mktemp("origin") / "shop"
    shutil.copytree(ROOT / "tests" / "fixtures" / "shop", src)
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    return src


@pytest.fixture
def clone_from(monkeypatch, origin):
    """The clone step copies a local repository (the real one is https only: tests/test_remote.py)."""
    seen = {}

    def fake_clone(link, dest, log):
        seen["link"] = link
        git("clone", "-q", "--depth", "1", origin.as_uri(), str(dest), cwd=dest.parent)
        remote._mark(dest)
        return dest
    monkeypatch.setattr(worker_mod, "clone_repo", fake_clone)
    return seen


@pytest.fixture
def data(monkeypatch):
    """The service's files laid out as in its image: one folder (the disk the service keeps), which others may
    pass through and list, holding the database, the results, the uploads, Lantern's own folder and the work folder.
    Under /tmp itself: a step's user must be able to pass through to its own folders, and pytest's own temp folders
    are closed to other users. Another person's finished check, with its upload and Lantern's own files, is there
    before the service starts."""
    d = Path(tempfile.mkdtemp(prefix="lantern-cloud-data-"))
    os.chmod(d, 0o755)
    monkeypatch.setenv("LANTERN_HOME", str(d / "lantern"))
    for folder, name in (("results/" + SOMEONE, "report.html"), ("work-uploads", SOMEONE + ".zip"),
                         ("lantern", "settings.json")):
        (d / folder).mkdir(parents=True, exist_ok=True)
        (d / folder / name).write_text(SECRET, encoding="utf-8")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def start(tmp_path, data: Path, **kw):
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(data / "lantern_cloud.db"),
                 results_dir=str(data / "results"), work_dir=str(data / "work"), **{"audits": False, **kw})
    cloud = TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app)))
    return cloud, gw_app.state.store, s


def lines(cloud, rid) -> list[str]:
    return cloud.app.state.worker.logs.since(rid, 0)[0]


def step(monkeypatch, script: str, *extra):
    """Each check's analysis step runs `script` instead of Lantern's analysis, with the check's code and its output
    folder after `extra`."""
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd", staticmethod(
        lambda repo, out, privacy, offline=True: [sys.executable, "-c", script, *map(str, extra), str(repo), str(out)]))


def check(cloud, gw, who: str = "github:1") -> dict:
    tok = gw.sign_in(who, who.replace(":", ":u"))
    r = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(tok))
    assert r.status_code == 202, r.text
    return wait(cloud, tok, r.json()["id"])


# ---------------------------------------------------------------------------- what a step may read
LOOK = r"""
import os, sys
def look(kind, path, how):
    try:
        if how == "file":
            with open(path, "rb") as f:
                f.read(1)
        elif how == "list":
            os.listdir(path)
        else:                                   # "enter": pass through the folder to a name inside it
            os.stat(path)
            try:
                os.stat(os.path.join(path, "nothing-of-that-name"))
            except FileNotFoundError:
                pass
        said = "read"
    except PermissionError:
        said = "refused"
    except OSError as e:
        said = "error-%d" % e.errno
    print("LOOKED", kind, how, said, flush=True)
a = sys.argv[1:-2]
for i in range(0, len(a), 3):
    look(*a[i:i + 3])
repo, out = sys.argv[-2:]
look("own-code", repo, "list")
look("own-folder", os.getcwd(), "list")
with open(os.path.join(os.getcwd(), "written-here"), "w") as f:
    f.write("x")
look("own-file", os.path.join(os.getcwd(), "written-here"), "file")
"""


@AS_ROOT
def test_a_check_cannot_read_the_services_files_or_another_persons_check(tmp_path, data, clone_from, monkeypatch):
    """The database, another person's results and upload, Lantern's own folder of the service, the service's
    environment (its secrets) and its open files: each refused to the check's step. Its own code and its own temp
    folder it reads and writes, as before (the twin: the step is not simply broken)."""
    db = data / "lantern_cloud.db"
    places = [("database", db, "file"),
              ("results", data / "results", "list"), ("results", data / "results", "enter"),
              ("report", data / "results" / SOMEONE / "report.html", "file"),
              ("uploads", data / "work-uploads", "list"), ("upload", data / "work-uploads" / f"{SOMEONE}.zip", "file"),
              ("lantern", data / "lantern", "list"), ("lantern-file", data / "lantern" / "settings.json", "file"),
              ("work", data / "work", "list"),
              ("environment", f"/proc/{os.getpid()}/environ", "file"), ("open-files", f"/proc/{os.getpid()}/fd", "list")]
    step(monkeypatch, LOOK, *[x for p in places for x in p])
    cloud, gw, s = start(tmp_path, data)
    done = check(cloud, gw)
    said = {(x.split()[1], x.split()[2]): x.split()[3] for x in lines(cloud, done["id"]) if x.startswith("LOOKED ")}
    assert len(said) == len(places) + 3, lines(cloud, done["id"])
    let_through = sorted(f"{k} ({how})" for (k, how), v in said.items() if not k.startswith("own-") and v != "refused")
    assert let_through == [], let_through
    assert [said[("own-code", "list")], said[("own-folder", "list")], said[("own-file", "file")]] == ["read"] * 3, said


WAIT = r"""
import os, sys, time
out = sys.argv[-1]
open(os.path.join(out, "waiting"), "w").close()
for _ in range(1200):
    if os.path.exists(os.path.join(out, "go-on")):
        break
    time.sleep(0.05)
"""

HUNT = r"""
import os, sys
mine = os.path.dirname(os.path.dirname(sys.argv[-1]))       # this check's own folder
seen = set()
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            parts = f.read().split(b"\0")
    except OSError:
        continue
    for p in parts:
        p = p.decode("utf-8", "replace")
        if p.startswith("/") and "/run-" in p and not p.startswith(mine):
            seen.add(p)
for p in sorted(seen):
    try:
        os.listdir(p)
        print("OTHER read", flush=True)
    except PermissionError:
        print("OTHER refused", flush=True)
    except OSError as e:
        print("OTHER error-%d" % e.errno, flush=True)
print("HUNTED", len(seen), flush=True)
"""


@AS_ROOT
def test_a_check_cannot_read_another_persons_check_while_it_runs(tmp_path, data, clone_from, monkeypatch):
    """The paths of a check that is running can be read by anyone from the list of the computer's programs (their
    command lines). The second person's step looks for them there and tries to read the first person's code and
    output folder while the first check waits: refused. Before, both ran as one user, and it read them."""
    outs = []

    def cmd(repo, out, privacy, offline=True):
        outs.append(Path(out))
        return [sys.executable, "-c", WAIT if len(outs) == 1 else HUNT, str(repo), str(out)]
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd", staticmethod(cmd))
    cloud, gw, s = start(tmp_path, data)
    a, b = gw.sign_in("github:1", "github:a"), gw.sign_in("github:2", "github:b")
    first = cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(a)).json()["id"]
    end = time.monotonic() + 60
    while not (outs and (outs[0] / "waiting").exists()) and time.monotonic() < end:
        time.sleep(0.05)
    assert outs and (outs[0] / "waiting").exists(), lines(cloud, first)
    try:
        second = wait(cloud, b, cloud.post("/v1/repos", json={"link": LINK}, headers=bearer(b)).json()["id"])
    finally:
        (outs[0] / "go-on").write_text("", encoding="utf-8")
    wait(cloud, a, first)
    said = lines(cloud, second["id"])
    hunted = [x for x in said if x.startswith("HUNTED ")]
    assert hunted and int(hunted[0].split()[1]) >= 2, said         # it found the first check's code and folder
    assert [x for x in said if x.startswith("OTHER ")] == ["OTHER refused"] * int(hunted[0].split()[1]), said


USER = r"""
import os, sys
st = os.stat(os.getcwd())
print("STEP-USER", os.getuid(), os.geteuid(), os.getgid(), os.getegid(), len(os.getgroups()), st.st_uid,
      oct(st.st_mode & 0o777), flush=True)
"""


@AS_ROOT
def test_each_check_runs_as_a_user_of_its_own(tmp_path, data, clone_from, monkeypatch):
    """Not root, not `nobody` (whom every check shared), not the service's own user, and not the user of another
    check: two checks, two users of the range kept for them, no other group, each the owner of its own temp folder,
    which no other user may enter."""
    step(monkeypatch, USER)
    cloud, gw, s = start(tmp_path, data)
    seen = []
    for who in ("github:1", "github:2"):
        done = check(cloud, gw, who)
        got = [x.split()[1:] for x in lines(cloud, done["id"]) if x.startswith("STEP-USER ")]
        assert len(got) == 1, lines(cloud, done["id"])
        uid, euid, gid, egid, groups, owner, mode = got[0]
        assert uid == euid == gid == egid == owner and groups == "0" and mode == "0o700", got
        seen.append(int(uid))
    users = getattr(_jail, "STEP_USERS", range(0))
    assert all(u in users and u not in (0, 65534, os.geteuid()) for u in seen) and seen[0] != seen[1], seen


SEND = ("import socket, sys\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.sendto(sys.argv[1].encode(), ('127.0.0.1', int(sys.argv[2])))\nprint('SENT', sys.argv[1], flush=True)\n")


@AS_ROOT
def test_a_step_that_reads_no_network_reaches_nothing_below_python(tmp_path, data, clone_from, monkeypatch):
    """A program of the analysis that is not held by Python's guard (here Python started without its site
    folder, so the guard is not loaded; a library written in C would do as well) sends a datagram to an address of
    this computer: nothing arrives, because the step has a network of its own. Where the kernel has no Landlock,
    or for a datagram, which Landlock does not cover, the guard was the only wall. The twin: the dependency audit,
    a step that needs the network, still reaches the same listener."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(0.2)
    port = rx.getsockname()[1]
    real = worker_mod.programs.python

    def python(module, *args):
        if module == "lantern.depaudit":
            return [sys.executable, "-S", "-c", SEND, "AUDIT", str(port)]
        return real(module, *args)
    monkeypatch.setattr(worker_mod.programs, "python", python)
    monkeypatch.setattr(worker_mod.Worker, "analyze_cmd", staticmethod(
        lambda repo, out, privacy, offline=True: [sys.executable, "-S", "-c", SEND, "ANALYSIS", str(port)]))
    cloud, gw, s = start(tmp_path, data, audits=True)
    try:
        done = check(cloud, gw)
        said = lines(cloud, done["id"])
        assert "SENT AUDIT" in said and "SENT ANALYSIS" in said, said     # both programs ran and sent
        got = []
        while True:
            try:
                got.append(rx.recv(100).decode())
            except TimeoutError:
                break
        assert got == ["AUDIT"], (got, said)
    finally:
        rx.close()


# ---------------------------------------------------------------------------- what the service does for a step
@AS_ROOT
def test_what_a_step_left_is_never_followed_when_the_next_step_is_given_its_folder(tmp_path, data, monkeypatch):
    """Before a step starts, the service hands the step's folders to the check's user. A step that was taken over
    can leave links there for the next one: to a file and a folder of root's, in place of its home folder. Nothing a
    link names is handed over; before, the service changed the owner of the file a link named."""
    cloud, gw, s = start(tmp_path, data)
    w = cloud.app.state.worker
    victim = tmp_path / "root-only.txt"
    victim.write_text(SECRET, encoding="utf-8")
    folder = tmp_path / "root-only"
    folder.mkdir()
    root = w.cleanup.fresh("run-")
    tmp = root / "tmp"
    tmp.mkdir()
    users = getattr(w, "users", None)
    if users is not None:
        users.take(root)
    leave = ("import os, shutil\nos.symlink(%r, 'x')\nshutil.rmtree('home')\nos.symlink(%r, 'home')\n"
             "os.symlink(%r, 'out')\n" % (str(victim), str(folder), str(folder)))
    try:
        for cmd in ([sys.executable, "-S", "-c", leave], [sys.executable, "-S", "-c", "pass"]):
            rc, output, timed_out = w._jailed("t", root, cmd, cwd=tmp, net=False, log=lambda m: None, timeout=60)
            assert rc == 0 and not timed_out, output
        assert os.path.islink(tmp / "x") and os.path.islink(tmp / "home") and os.path.islink(tmp / "out")
        assert [os.stat(victim).st_uid, os.stat(folder).st_uid] == [0, 0]
        assert victim.read_text(encoding="utf-8") == SECRET
    finally:
        if users is not None:
            users.give_back(root)
        shutil.rmtree(root, ignore_errors=True)


def _mode(p: Path) -> int:
    return os.lstat(p).st_mode & 0o777


@AS_ROOT
def test_the_services_own_files_are_closed_to_others_when_it_starts(tmp_path, data):
    """The database and its journal files, the results, the uploads and Lantern's own folder: owner only. The work
    folder: others may pass through it to a folder of their own, and may not list it."""
    con = __import__("sqlite3").connect(data / "lantern_cloud.db")
    con.execute("pragma journal_mode=wal")
    con.execute("create table t (x)")
    con.commit()
    start(tmp_path, data)
    db = data / "lantern_cloud.db"
    assert [_mode(db)] + [_mode(Path(f"{db}{x}")) for x in ("-wal", "-shm") if os.path.exists(f"{db}{x}")] == \
        [0o600] * (1 + sum(os.path.exists(f"{db}{x}") for x in ("-wal", "-shm")))
    assert [_mode(data / x) for x in ("results", "work-uploads", "lantern")] == [0o700] * 3
    assert _mode(data / "work") == 0o711
    con.close()


@AS_ROOT
def test_what_the_former_user_of_the_service_made_becomes_the_services_own(tmp_path, data):
    """Until this change the website's image ran the service as an ordinary user, who owns what the service made on
    its disk. Now the service is root, and its clean-up removes only what is its own: without a change of owner, a
    check its person deletes would stay on the disk. At its start the service takes over the entries of its own
    folders that the user who owns its database made; another user's entry, and what a link names, stay as they
    are."""
    db = data / "lantern_cloud.db"
    Store(str(db))
    work = data / "work"
    left = work / "run-abcd1234"
    left.mkdir(parents=True)
    (left / MARK).write_text(MARK_TEXT, encoding="utf-8")
    others = data / "results" / "ZzZzZzZzZzZzZzZz"
    others.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.chown(outside, 4343, 4343)
    (data / "results" / "LiNkLiNkLiNkLiNk").symlink_to(outside, target_is_directory=True)
    for p in [db, data / "results", data / "results" / SOMEONE, data / "results" / SOMEONE / "report.html",
              data / "work-uploads", data / "work-uploads" / f"{SOMEONE}.zip", data / "lantern", work, left, left / MARK]:
        os.chown(p, FORMER, FORMER)
    os.chown(others, 4242, 4242)
    os.chown(data / "results" / "LiNkLiNkLiNkLiNk", FORMER, FORMER, follow_symlinks=False)
    start(tmp_path, data)
    owners = {p.name: os.lstat(p).st_uid for p in [db, data / "results", data / "results" / SOMEONE, data / "work-uploads",
                                                     data / "work-uploads" / f"{SOMEONE}.zip", data / "lantern", work]}
    assert set(owners.values()) == {0}, owners
    assert os.lstat(others).st_uid == 4242 and os.lstat(outside).st_uid == 4343
    # and a check its person deletes is removed from the disk again
    store = Store(str(db))
    c = Cleanup(store, str(data / "results"), str(work), str(data / "work-uploads"))
    assert c.discard("results", SOMEONE) is True and not (data / "results" / SOMEONE).exists()


# ---------------------------------------------------------------------------- a service that cannot keep checks apart
def test_where_checks_must_be_kept_apart_a_service_that_cannot_starts_none(tmp_path, data, clone_from, monkeypatch):
    """Not root (the service cannot change a step's user): with LANTERN_CLOUD_STEPS_APART=required, as in the
    website's image, a check is refused before anything of it is copied, with a sentence for the person, and the
    health page says "shared". The twin: without that setting the check runs, as on a person's own computer."""
    from lantern_cloud import apart
    monkeypatch.setattr(apart, "as_root", lambda: False)
    step(monkeypatch, "print('ANALYSED')")
    cloud, gw, s = start(tmp_path, data, steps_apart="required")
    assert cloud.get("/v1/health").json()["steps"] == "shared"
    done = check(cloud, gw)
    assert done["status"] == "error" and done["error"] == apart.NOT_APART, done
    assert "link" not in clone_from and "ANALYSED" not in lines(cloud, done["id"])
    (tmp_path / "twin").mkdir()
    cloud, gw, s = start(tmp_path / "twin", data, steps_apart="")
    done = check(cloud, gw, "github:2")
    assert clone_from["link"] == LINK and "ANALYSED" in lines(cloud, done["id"]), done


@AS_ROOT
def test_each_check_first_proves_that_its_steps_cannot_read_the_services_files(tmp_path, data, clone_from, monkeypatch,
                                                                             caplog):
    """Before its first step, each check's user tries to read the service's files; the check goes on only when it
    could read none of them, and says so in its log. Here the database was opened to others after the service
    started: the next check is refused where checks must be kept apart, the health page says "open", and the
    service's own log tells the owner what was read, by kind only. The twin: the check before it went on, the
    health page said "apart", and the service's log said nothing of it."""
    from lantern_cloud import apart
    step(monkeypatch, "print('ANALYSED')")
    cloud, gw, s = start(tmp_path, data, steps_apart="required")
    end = time.monotonic() + 30          # where checks must be kept apart, the service also proves it when it starts
    while cloud.get("/v1/health").json()["steps"] == "unchecked" and time.monotonic() < end:
        time.sleep(0.1)
    assert cloud.get("/v1/health").json()["steps"] == "apart"
    done = check(cloud, gw)
    said = lines(cloud, done["id"])
    assert "ANALYSED" in said and apart.APART in said, said
    assert cloud.get("/v1/health").json()["steps"] == "apart"
    assert not [r for r in caplog.records if "could read" in r.getMessage()]
    os.chmod(data / "lantern_cloud.db", 0o644)
    done = check(cloud, gw, "github:2")
    assert done["status"] == "error" and done["error"] == apart.NOT_APART, done
    said = lines(cloud, done["id"])
    assert "ANALYSED" not in said and any("database" in x for x in said), said
    assert cloud.get("/v1/health").json()["steps"] == "open"
    warned = [r.getMessage() for r in caplog.records if r.name == "lantern_cloud" and "could read" in r.getMessage()]
    assert warned and all("(database)" in m and str(data) not in m for m in warned), warned


def _proof_saying(how: str):
    """A stand-in for the steps of a check that runs every step as it is but the service's own proof, which says
    what `how` names and nothing else."""
    from lantern_cloud import apart
    real = worker_mod.Worker._jailed

    def jailed(self, key, root, cmd, **kw):
        if apart.PROOF not in cmd:
            return real(self, key, root, cmd, **kw)
        uid, probes = self.users.of(root), cmd[cmd.index(apart.PROOF) + 1:]
        if how == "nothing":            # stopped at its time limit before it said anything
            return None, "", True
        if how == "cut short":          # it said whom it ran as, and was stopped before its first answer
            return None, f"LANTERN-STEP-USER {uid} {uid}\n", True
        answers = "".join(f"LANTERN-STEP-CHECK {probes[i]} {probes[i + 2]} refused\n" for i in range(0, len(probes), 3))
        return 0, "LANTERN-STEP-USER 0 0\n" + answers, False     # "as root": it ran as another user, and said so
    return jailed


@AS_ROOT
@pytest.mark.parametrize("how", ["nothing", "cut short", "as root"])
def test_a_proof_that_did_not_answer_stops_its_check_and_says_nothing_of_the_service(tmp_path, data, clone_from,
                                                                                   monkeypatch, caplog, how):
    """A proof step that does not answer (it was stopped at its time limit before it said anything, or before its
    first answer; it may also not start, or end before it is done) proves nothing either way: its check is not
    started, with a sentence that says so, and neither the health page (whose "open" the uptime check mails the
    owner about) nor the service's log says that a check's user could read the service's files. The look-alike: a
    proof that answered every question and said it ran as another user than the check's is one whose user is not
    kept apart, and is said to be. The twin: the next check, whose proof answers, goes on."""
    from lantern_cloud import apart
    step(monkeypatch, "print('ANALYSED')")
    cloud, gw, s = start(tmp_path, data, steps_apart="required")
    end = time.monotonic() + 30
    while cloud.get("/v1/health").json()["steps"] == "unchecked" and time.monotonic() < end:
        time.sleep(0.1)
    assert cloud.get("/v1/health").json()["steps"] == "apart"
    real = worker_mod.Worker._jailed
    monkeypatch.setattr(worker_mod.Worker, "_jailed", _proof_saying(how))
    done = check(cloud, gw)
    said = lines(cloud, done["id"])
    assert done["status"] == "error" and "link" not in clone_from and "ANALYSED" not in said, done
    warned = [r.getMessage() for r in caplog.records if r.name == "lantern_cloud" and "could read" in r.getMessage()]
    if how == "as root":
        assert done["error"] == apart.NOT_APART and cloud.get("/v1/health").json()["steps"] == "open", done
        assert warned and all("(user)" in m for m in warned), warned
        return
    assert cloud.get("/v1/health").json()["steps"] == "apart"
    assert not warned and done["error"] != apart.NOT_APART, (warned, done)
    assert done["error"] == apart.UNPROVEN and apart.UNANSWERED in said, (done, said)
    assert [r for r in caplog.records if r.name == "lantern_cloud" and "did not answer" in r.getMessage()]
    monkeypatch.setattr(worker_mod.Worker, "_jailed", real)
    done = check(cloud, gw, "github:2")
    assert "ANALYSED" in lines(cloud, done["id"]) and cloud.get("/v1/health").json()["steps"] == "apart", done


# ---------------------------------------------------------------------------- the twins: a whole check still works
def _step_users_running() -> list[int]:
    """The processes of this computer that run as one of the users kept for steps."""
    users = getattr(_jail, "STEP_USERS", range(0))
    found = []
    for pid in os.listdir("/proc"):
        try:
            with open(f"/proc/{pid}/status", "rb") as f:
                uid = next(int(x.split()[1]) for x in f.read().splitlines() if x.startswith(b"Uid:"))
        except (OSError, ValueError, StopIteration, IndexError):
            continue
        if uid in users:
            found.append(int(pid))
    return found


@AS_ROOT
def test_a_whole_check_of_the_sample_runs_under_a_user_of_its_own(tmp_path, data, clone_from):
    """The twin of the tests above: Lantern's own analysis of the sample app, run as the check's user, finds what it
    always found and the results are kept; nothing of the check is left in the work folder, and nothing of it still
    runs."""
    cloud, gw, s = start(tmp_path, data)
    done = check(cloud, gw)
    said = lines(cloud, done["id"])
    assert done["status"] == "done", (done, said)
    assert done["summary"]["counts"]["critical"] >= 1 and len(done["commit"]) == 40, done
    assert (data / "results" / done["id"] / "report.html").is_file()
    assert [p.name for p in (data / "work").iterdir()] == []
    assert _step_users_running() == []


@AS_ROOT
def test_an_uploaded_app_is_unpacked_and_checked_under_a_user_of_its_own(tmp_path, data, monkeypatch):
    """The twin for an upload: it is unpacked by the check's user, checked, and gone from the uploads."""
    from test_cloud_runs import SHOP, _zip_of

    def no_clone(link, dest, log):
        raise AssertionError("an upload must not be cloned")
    monkeypatch.setattr(worker_mod, "clone_repo", no_clone)
    cloud, gw, s = start(tmp_path, data)
    tok = gw.sign_in("github:1", "github:octo")
    r = cloud.post("/v1/uploads?name=shop", content=_zip_of(SHOP), headers=bearer(tok))
    assert r.status_code == 202, r.text
    done = wait(cloud, tok, r.json()["id"])
    assert done["status"] == "done", (done, lines(cloud, done["id"]))
    assert done["summary"]["counts"]["critical"] >= 1 and "Unpacking your upload" in done["log_tail"], done
    assert not (data / "work-uploads" / f"{done['id']}.zip").exists()
    assert [p.name for p in (data / "work").iterdir()] == [] and _step_users_running() == []


# ---------------------------------------------------------------------------- the launcher
LAUNCH = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from lantern._jail import main; main(sys.argv[1:])"


def launch(tmp_path, user, *, nobody=False) -> subprocess.CompletedProcess:
    policy = {"writable": [str(tmp_path)], "python": False, "parent": os.getpid(), "user": user}
    if nobody:
        policy["nobody"] = True
    cmd = [sys.executable, "-S", "-c", "import os; print('RAN-AS', os.getuid(), flush=True)"]
    return subprocess.run([sys.executable, "-I", "-c", LAUNCH, json.dumps(policy), "--", *cmd], cwd="/",
                          capture_output=True, text=True, encoding="utf-8", timeout=60)


@AS_ROOT
@pytest.mark.parametrize("user", [0, 65534, FORMER, -1, "300000", True, 1 << 40])
def test_the_launcher_runs_a_step_only_as_one_of_the_users_kept_for_steps(tmp_path, user):
    """Root, `nobody`, an ordinary user of the computer, and what is no user number: nothing is started, and the
    launcher says why. Never as root what was to run as a user of its own."""
    r = launch(tmp_path, user, nobody=True)
    assert r.returncode == _jail.UNAVAILABLE and "RAN-AS" not in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert f"{_jail.MARK} user" in r.stdout + r.stderr


@AS_ROOT
def test_the_launcher_runs_a_step_as_the_user_it_was_given(tmp_path):
    """The twin: a user of the range kept for steps is the user the command runs as."""
    users = getattr(_jail, "STEP_USERS", range(300_000, 300_001))
    r = launch(tmp_path, users[0])
    assert r.returncode == 0 and f"RAN-AS {users[0]}" in r.stdout, (r.returncode, r.stdout, r.stderr)


@AS_ROOT
def test_ending_the_programs_of_a_checks_user_ends_those_and_no_others(tmp_path):
    """What still runs as a check's user when the check is over is ended (a step's launcher ends what its command
    started; this is the second wall). Programs of another user are not touched, and the service's own users are
    never asked for."""
    users = getattr(_jail, "STEP_USERS", range(300_000, 300_002))
    a, b = users[7], users[8]
    pa = subprocess.Popen(["sleep", "60"], user=a, group=a, extra_groups=[])
    pb = subprocess.Popen(["sleep", "60"], user=b, group=b, extra_groups=[])
    try:
        assert _jail.end_user(a) == 0
        assert pa.wait(5) is not None and pb.poll() is None
        for wrong in (0, os.geteuid(), 65534, FORMER):
            with pytest.raises(ValueError):
                _jail.end_user(wrong)
    finally:
        for p in (pa, pb):
            p.kill()
            p.wait(5)
