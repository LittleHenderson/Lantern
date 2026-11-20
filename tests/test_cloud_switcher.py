"""The website's switcher: the one part of the website's image that stays root (website stage, step 3, 2026-11-20).

The owner's answer of 2026-11-20 let the website's image start as root, so that each check's steps run as a user of
that check's own (tests/test_cloud_step_user.py), "then narrow root to a small part". From 2026-11-18 until this
change the whole service ran as root: its pages, its database, the clones it makes and the results it reads back.
Now the image starts `lantern_cloud.switcher` as root. It starts the service as an ordinary user of its own and,
only when the service asks over the socket that the service alone holds, gives a check a user of its own, hands the
check's folders to that user before each step and back after it, starts and stops each step as that user, and ends
what that user left (cloud/lantern_cloud/switcher.py).

Here, as any user: what the switcher takes from the service (by its shape alone), the users and folders it refuses,
what it looks at before it runs anything as root, the service's side (each step a `Remote` that
`lantern.sandbox._stream` runs like a process of its own), the health page. As root: the real switcher with a
service of a test's own, each step as the check's user with no other group and no network, what that step may read,
what a step leaves handed back, a step stopped with everything it started, the hand-over that never follows a link,
the refusals when it starts, and a whole check of the sample by the real service under the switcher. Each danger
beside a safe twin. CI runs this file a second time as root, where a skipped test fails the run.
"""

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
if not sys.platform.startswith("linux"):
    pytest.skip("the switcher runs on Linux, in the website's image", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
import lantern_files  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from lantern import _jail, sandbox  # noqa: E402
from lantern_cloud import apart, switcher  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402

AS_ROOT = pytest.mark.skipif(os.geteuid() != 0, reason="needs root: only root can start a program as another user")
SERVICE = 61000          # the service's user here: a number with no account, which the switcher takes as a name
OTHER = 4242             # somebody else on the same computer
CHECK = "run-abcd1234"   # a check's folder, named as `Cleanup.fresh` names one
SECRET = "kept-by-the-service-alone"


# ---------------------------------------------------------------------------- what the switcher takes from the service
GOOD_STEP = {"op": "step", "check": CHECK, "argv": ["python", "-c", "pass"], "env": {"PATH": "/usr/bin"}, "net": False}


def _req(**kw) -> bytes:
    return json.dumps({**GOOD_STEP, **kw}).encode()


@pytest.mark.parametrize("data, why", [
    (b"not json", "not JSON"),
    ('{"op": "take", "check": "run-abcd1234"}'.encode("utf-16"), "not JSON"),
    (b"[1, 2]", "does not know"),
    (json.dumps({"op": "run_as_root"}).encode(), "does not know"),
    (json.dumps({"op": "take", "check": "../../etc"}).encode(), "check's folder"),
    (json.dumps({"op": "take", "check": "run-abcd1234/../../x"}).encode(), "check's folder"),
    (json.dumps({"op": "take", "check": "results"}).encode(), "check's folder"),
    (json.dumps({"op": "take", "check": "run-ABCD1234"}).encode(), "check's folder"),
    (json.dumps({"op": "give_back", "check": 7}).encode(), "check's folder"),
    (_req(argv="python -c pass"), "list of words"),
    (_req(argv=[]), "list of words"),
    (_req(argv=["python", "a\0b"]), "list of words"),
    (_req(env={"A=B": "c"}), "names and words"),
    (_req(env={"PATH": 1}), "names and words"),
    (_req(env={"X": "a\0b"}), "names and words"),
    (_req(net="no"), "network"),
    (_req(net=0), "network"),
    (_req(argv=["x" * (switcher.MOST_TEXT + 1)]), "too long"),
])
def test_the_switcher_takes_a_request_by_its_shape_alone(data, why):
    """A service that was taken over can send the switcher anything. Each request is read by its shape: an operation
    it knows, a check's folder named as the service names one (no path, no other folder of the service), a command
    of words, an environment of names and words, and whether the step reads the network; anything else is refused
    before anything is done."""
    with pytest.raises(switcher.Refused, match=why):
        switcher.read_request(data)


def test_a_request_of_the_right_shape_gives_only_what_it_names():
    """The twin: what the switcher takes, and nothing more (a user number or a folder the service adds is dropped:
    the switcher chooses both)."""
    assert switcher.read_request(json.dumps({"op": "hello", "uid": 0}).encode()) == {"op": "hello"}
    assert switcher.read_request(json.dumps({"op": "take", "check": "explain-a_b0c9z8"}).encode()) == \
        {"op": "take", "check": "explain-a_b0c9z8"}
    assert switcher.read_request(_req(uid=0, cwd="/", user="root")) == GOOD_STEP
    assert switcher.read_request(_req(net=True))["net"] is True


@pytest.mark.parametrize("word", ["0", "root", "65534", "nobody", str(_jail.STEP_USERS[0]), str(_jail.STEP_USERS[-1])])
def test_the_service_never_runs_as_root_nobody_or_a_checks_user(word):
    with pytest.raises(switcher.Refused, match="ordinary user"):
        switcher.service_user(word)


def test_the_service_never_runs_in_roots_group_or_as_a_user_with_no_account(monkeypatch):
    import pwd
    with pytest.raises(switcher.Refused, match="no user"):
        switcher.service_user("no-such-user-of-lantern")
    monkeypatch.setattr(pwd, "getpwnam", lambda name: pwd.struct_passwd(("svc", "x", 4321, 0, "", "/h", "/bin/sh")))
    with pytest.raises(switcher.Refused, match="ordinary user"):
        switcher.service_user("svc")


def test_an_ordinary_user_by_number_or_by_name():
    """The twin: a number (its group the same number) and a name of this system."""
    import pwd
    assert switcher.service_user(str(SERVICE)) == (SERVICE, SERVICE, str(SERVICE), None)
    ordinary = next((p for p in pwd.getpwall() if p.pw_uid not in (0, 65534) and p.pw_gid != 0
                     and p.pw_uid not in _jail.STEP_USERS), None)
    if ordinary is not None:
        assert switcher.service_user(ordinary.pw_name)[:2] == (ordinary.pw_uid, ordinary.pw_gid)


# ---------------------------------------------------------------------------- what root runs: nothing the service may change
def _st(mode: int, uid: int = 0, gid: int = 0) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


@pytest.mark.parametrize("st, above, may", [
    (_st(stat.S_IFREG | 0o644, uid=SERVICE), False, True),        # its own
    (_st(stat.S_IFREG | 0o664, gid=SERVICE), False, True),        # its group may write it
    (_st(stat.S_IFREG | 0o646), False, True),                     # anyone may write it
    (_st(stat.S_IFDIR | 0o1777), False, True),                    # a code folder anyone may add to, sticky or not
    (_st(stat.S_IFDIR | 0o775, gid=SERVICE), True, True),         # a folder above, its group may write
    (_st(stat.S_IFDIR | 0o777), True, True),                      # a folder above that anyone may write
    # the twins
    (_st(stat.S_IFDIR | 0o1777), True, False),                    # a folder above like /tmp: nobody moves root's entry
    (_st(stat.S_IFREG | 0o664, gid=OTHER), False, False),         # another group may write it
    (_st(stat.S_IFREG | 0o644), False, False),
    (_st(stat.S_IFDIR | 0o755), True, False),
])
def test_what_the_services_user_may_change(st, above, may):
    assert switcher._may_change(st, SERVICE, SERVICE, above=above) is may


def _code_tree(base: Path) -> Path:
    """Code of root's, as in the image: folders 0755, files 0644, nothing the service's user may change."""
    top = base / "code"
    (top / "pkg" / "sub").mkdir(parents=True)
    for f in (top / "pkg" / "__init__.py", top / "pkg" / "sub" / "m.py", top / "site.pth"):
        f.write_text("x = 1\n", encoding="utf-8")
    for p in [base, top, top / "pkg", top / "pkg" / "sub"]:
        os.chmod(p, 0o755)
    return top


def test_root_runs_nothing_the_services_user_could_change(tmp_path):
    """Before the switcher runs anything as root it looks at every folder Python loads code from, each file and
    folder in them and every folder above them: the first thing the service's user could change stops it. A file
    anyone may write, a folder anyone may add a module to, a link to a file the service could change, a link to a
    place that is not there but that the service could make (in a folder anyone may write, sticky or not: the
    sticky bit keeps others from removing an entry, not from making one), and a folder a link leads to that holds
    such a file. The twin: the same tree with none of these."""
    top = _code_tree(tmp_path)
    assert switcher.unchangeable(SERVICE, SERVICE, places=[top]) is None
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    shut = tmp_path / "shut"
    shut.mkdir()
    os.chmod(shut, 0o755)
    (open_dir / "f.py").write_text("x = 2\n", encoding="utf-8")
    os.chmod(open_dir / "f.py", 0o644)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.chmod(elsewhere, 0o755)
    (elsewhere / "w.py").write_text("x = 3\n", encoding="utf-8")
    cases = {
        "a file anyone may write": lambda: os.chmod(top / "pkg" / "sub" / "m.py", 0o666),
        "a folder anyone may add to": lambda: os.chmod(top / "pkg" / "sub", 0o777),
        "a sticky folder of code anyone may add to": lambda: os.chmod(top / "pkg" / "sub", 0o1777),
        "a link to a file in a folder anyone may write": lambda: (top / "pkg" / "l.py").symlink_to(open_dir / "f.py"),
        "a link to nothing, in a folder anyone may write": lambda: (top / "pkg" / "l.py").symlink_to(open_dir / "no.py"),
        "a link to nothing, in a sticky folder": lambda: (top / "pkg" / "l.py").symlink_to(sticky / "no.py"),
        "a link to a folder with a file anyone may write": lambda: (
            os.chmod(elsewhere / "w.py", 0o666), (top / "pkg" / "lib").symlink_to(elsewhere, target_is_directory=True)),
    }
    for name, plant in cases.items():
        shutil.rmtree(top)
        top = _code_tree(tmp_path)
        os.chmod(elsewhere / "w.py", 0o644)
        plant()
        assert switcher.unchangeable(SERVICE, SERVICE, places=[top]) is not None, name
    # the twins: a link to nothing in a folder nobody else may write, a link to a folder of root's, a loop of links
    shutil.rmtree(top)
    top = _code_tree(tmp_path)
    os.chmod(elsewhere / "w.py", 0o644)
    (top / "pkg" / "gone.py").symlink_to(shut / "no.py")
    (top / "pkg" / "lib").symlink_to(elsewhere, target_is_directory=True)
    (top / "pkg" / "lib2").symlink_to(top / "pkg", target_is_directory=True)
    assert switcher.unchangeable(SERVICE, SERVICE, places=[top]) is None


def test_a_folder_above_the_code_that_the_service_could_change_stops_it(tmp_path):
    """A folder above the code that the service's user may write could hold another folder in its place."""
    top = _code_tree(tmp_path / "a")
    os.chmod(tmp_path / "a", 0o777)
    assert switcher.unchangeable(SERVICE, SERVICE, places=[top]) == str(tmp_path / "a")
    os.chmod(tmp_path / "a", 0o1777)       # the twin: like /tmp, nobody may move root's folder in it
    assert switcher.unchangeable(SERVICE, SERVICE, places=[top]) is None


def test_the_folders_python_loads_code_from_are_all_looked_at(monkeypatch, tmp_path):
    """Not only Lantern's two packages and Python's own library: the libraries installed beside it too, whose
    `.pth` files Python runs when it starts, even in isolated mode. A path entry that is not there is passed over,
    and none is looked at twice."""
    top = _code_tree(tmp_path)
    monkeypatch.setattr(sys, "path", [str(top / "pkg"), str(top), "/no/such/place", ""])
    places = switcher._code_places()
    assert top in places and top / "pkg" not in places and Path("/no/such/place") not in places
    assert Path(os.path.dirname(os.path.dirname(_jail.__file__))).resolve() in places or any(
        p in Path(_jail.__file__).resolve().parents for p in places)


# ---------------------------------------------------------------------------- the service's folder and places
def test_the_services_folder_must_be_its_own_named_by_its_full_path(tmp_path):
    """The switcher gives what is in the service's folder to the service's user: a relative path, the top of the
    system, a file, a link to a folder, and a folder of somebody else's are refused. The twin: the service's own."""
    me = os.geteuid()
    own = tmp_path / "data"
    own.mkdir()
    (tmp_path / "file").write_text("", encoding="utf-8")
    (tmp_path / "link").symlink_to(own, target_is_directory=True)
    for bad in ("data", "/", str(tmp_path / "file"), str(tmp_path / "link"), str(tmp_path / "nothing")):
        with pytest.raises(switcher.Refused):
            switcher.open_data(bad, me)
    with pytest.raises(switcher.Refused, match="neither"):
        switcher.open_data(str(own), me + 1)
    fd, mounted = switcher.open_data(str(own) + "/", me)
    os.close(fd)
    assert mounted is False


def test_every_place_of_the_service_must_be_in_its_folder(monkeypatch, tmp_path):
    data = tmp_path / "data"
    names = {"LANTERN_CLOUD_DB": data / "db", "LANTERN_CLOUD_RESULTS": data / "results",
             "LANTERN_CLOUD_WORK": data / "work", "LANTERN_CLOUD_UPLOADS": data / "uploads",
             "LANTERN_HOME": data / "lantern"}
    for k, v in names.items():
        monkeypatch.setenv(k, str(v))
    assert switcher.places(str(data)) == str(data / "work")
    for k in names:
        for wrong in (str(tmp_path / "elsewhere"), str(data), str(data) + "/../x"):
            monkeypatch.setenv(k, wrong)
            with pytest.raises(switcher.Refused, match=k):
                switcher.places(str(data))
        monkeypatch.setenv(k, str(names[k]))


def test_the_switcher_starts_nothing_but_as_root_on_linux_and_with_a_command(capsys):
    assert switcher.main([]) == 2
    if os.geteuid() != 0:
        assert switcher.main(["--", "true"]) == 2
        assert "only root can do" in capsys.readouterr().err


# ---------------------------------------------------------------------------- the service's side
class _FakeSwitcherEnd:
    """The switcher's end of one step's socket, answering as told."""

    def __init__(self, answers):
        self.mine, self.theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.asked = []
        self.answers = answers
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        try:
            while True:
                data = self.mine.recv(1 << 16)
                if not data:
                    return
                self.asked.append(json.loads(data))
                for a in self.answers:
                    if a is None:
                        self.mine.close()
                        return
                    self.mine.send(json.dumps(a).encode())
        except OSError:
            return

    def gone(self):
        """The switcher's end goes. A close alone would not end the socket while the reader above is still in
        `recv` on it (the system keeps it open for that call), so it is shut down first."""
        self.mine.shutdown(socket.SHUT_RDWR)
        self.mine.close()


def _remote(answers, lines=b"one\ntwo\n"):
    end = _FakeSwitcherEnd(answers)
    r, w = os.pipe()
    os.write(w, lines)
    os.close(w)
    return switcher.Remote(end.theirs, r, 4321), end


def test_a_step_stopped_through_the_switcher_says_what_it_could_not_end():
    """The service asks the switcher to stop a step with everything it started: what the switcher says comes back as
    what could not be ended, and what it could not hand back to the service is said too."""
    remote, end = _remote([{"over": True, "rc": 3, "said": ["one thing"], "left": ["one thing"], "kept": 2}])
    said, left = remote.stop(1.5)
    assert end.asked == [{"do": "stop", "ask": 1.5}]
    assert remote.returncode == 3 and left == ["one thing"]
    assert said[0] == "one thing" and "2 thing(s)" in said[1], said
    remote.stdout.close()


def test_a_switcher_that_does_not_answer_is_said_and_counted_as_not_ended():
    """A switcher that went (or never answers) cannot say that what the step started was ended: the service's own
    words say so, and the run reads as one with something left (`sandbox._Run.left`), never as one that ended
    cleanly."""
    remote, _end = _remote([None])
    said, left = remote.stop(0.5)
    assert remote.returncode is None and said == left and "did not answer" in said[0]
    remote.stdout.close()


def test_whether_a_step_ended_is_what_the_switcher_says():
    remote, end = _remote([])
    assert remote.ended() is False
    end.mine.send(json.dumps({"ended": True}).encode())
    deadline = time.monotonic() + 5
    while not remote.ended() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert remote.ended() is True
    remote.stdout.close()
    remote2, end2 = _remote([])
    end2.gone()                            # the switcher went: ended, and `stop` says what that means
    deadline = time.monotonic() + 5
    while not remote2.ended() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert remote2.ended() is True
    remote2.stdout.close()


def test_the_sandbox_runs_a_step_of_the_switcher_like_a_process_of_its_own(tmp_path):
    """`sandbox._stream(start=)`: the lines of the step are streamed as they come, the step is stopped through the
    switcher once (the switcher says how it ended), and what it could not end is handed on. The twin: where the
    switcher refuses to start the step, its words come out and nothing was started here."""
    remote, end = _remote([{"over": True, "rc": 0, "said": [], "left": []}], lines=b"LINE-1\nLINE-2\n")
    end.mine.send(json.dumps({"ended": True}).encode())
    got, left = [], []
    rc, output, timed_out = sandbox._stream(["ignored"], tmp_path, {}, 30, got.append, start=lambda: remote, left=left)
    assert (rc, timed_out, left) == (0, False, []) and "LINE-1" in output and "LINE-2" in output
    assert [a for a in end.asked if a.get("do") == "stop"] and got[:2] == ["LINE-1", "LINE-2"], (end.asked, got)

    def refused():
        raise switcher.Refused("that check was given no user")
    with pytest.raises(switcher.Refused, match="given no user"):
        sandbox._stream(["ignored"], tmp_path, {}, 30, got.append, start=refused)


class _Client:
    """The switcher as the service sees it, for the parts that need no root."""

    def __init__(self):
        self.pid, self.taken, self.given = 999, [], []

    def take(self, check):
        self.taken.append(check)
        return _jail.STEP_USERS[5]

    def give_back(self, check):
        self.given.append(check)
        return 1


def test_the_users_of_checks_come_from_the_switcher(tmp_path):
    users = apart.SwitchedUsers(_Client())
    root = tmp_path / CHECK
    assert users.switched and users.on and users.switcher == 999
    assert users.of(root) is None
    assert users.take(root) == _jail.STEP_USERS[5] and users.client.taken == [CHECK]
    assert users.of(root) == _jail.STEP_USERS[5]
    assert users.give_back(root) == 1 and users.of(root) is None and users.client.given == [CHECK]
    assert users.give_back(root) == 0 and users.client.given == [CHECK]      # given back once


def test_a_client_is_only_made_from_the_switchers_own_socket(monkeypatch, tmp_path):
    """The service finds its end of the switcher's socket by a number in its environment, which it takes out of it
    for good: a number that is no socket, a socket of another kind, and a word that is no number are not the
    switcher, and no client is made. The twin: the switcher's own socket answers, and the service learns which
    program the switcher is."""
    monkeypatch.setattr(switcher, "_client", None)
    monkeypatch.setattr(switcher, "_ended_with_the_switcher", lambda: None)
    monkeypatch.delenv(switcher.FD_VARIABLE, raising=False)
    assert switcher.connect() is None and not switcher.connected()
    monkeypatch.setenv(switcher.FD_VARIABLE, "seven")
    with pytest.raises(switcher.SwitcherGone):
        switcher.connect()
    assert switcher.FD_VARIABLE not in os.environ
    f = open(tmp_path / "file", "w", encoding="utf-8")   # noqa: SIM115 - closed below
    stream_a, stream_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        for fd in (f.fileno(), stream_a.fileno()):
            monkeypatch.setenv(switcher.FD_VARIABLE, str(fd))
            with pytest.raises(switcher.SwitcherGone):
                switcher.connect()
        os.fstat(f.fileno())                   # not closed by the refusal
    finally:
        f.close()
        stream_a.close()
        stream_b.close()
    mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    def answer():
        data, fds, _flags, _ = socket.recv_fds(mine, 1 << 16, 4)
        with socket.socket(fileno=fds[0]) as reply:
            assert json.loads(data) == {"op": "hello"}
            reply.send(json.dumps({"switcher": 4242, "user": SERVICE}).encode())
    t = threading.Thread(target=answer, daemon=True)
    t.start()
    monkeypatch.setenv(switcher.FD_VARIABLE, str(theirs.fileno()))
    client = switcher.connect()
    t.join(10)
    try:
        assert client is not None and client.pid == 4242 and switcher.connect() is client
        assert switcher.FD_VARIABLE not in os.environ and switcher.connected()
    finally:
        client.sock.close()
        mine.close()


def _service(tmp_path, **kw):
    from lantern_gateway.app import Settings as GwSettings
    from lantern_gateway.app import create_app as create_gateway
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "c.db"),
                 results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"), **{"audits": False, **kw})
    return TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app), start_worker=False))


def test_the_health_page_says_whether_the_service_runs_as_root(tmp_path, monkeypatch):
    """`service_user`: "own" where the service is an ordinary user (the switcher started it so), "root" where the
    whole service runs as root (the uptime check emails the owner). A service the switcher started can keep each
    check apart before its first proof ("unchecked"); one it did not start, and that is not root, cannot ("shared")."""
    monkeypatch.setattr(switcher, "_client", None)
    monkeypatch.setattr(apart, "as_root", lambda: False)
    monkeypatch.delenv(switcher.FD_VARIABLE, raising=False)
    h = _service(tmp_path).get("/v1/health").json()
    assert (h["steps"], h["service_user"]) == ("shared", "own"), h
    monkeypatch.setenv(switcher.FD_VARIABLE, "9")
    h = _service(tmp_path).get("/v1/health").json()
    assert (h["steps"], h["service_user"]) == ("unchecked", "own"), h
    monkeypatch.setattr(apart, "as_root", lambda: True)
    h = _service(tmp_path).get("/v1/health").json()
    assert h["service_user"] == "root", h


class _StepClient(_Client):
    """A switcher that runs each step here, as this user, the way the real one hands it back: lines, an end, a stop."""

    def __init__(self, refuse=False):
        super().__init__()
        self.refuse, self.steps = refuse, []

    def step(self, check, argv, env, net):
        if self.refuse:
            raise switcher.Refused("a step of that check is under way")
        self.steps.append((check, argv, net))
        p = subprocess.run(argv, capture_output=True, env={**env, "PATH": os.environ.get("PATH", "")}, timeout=60)
        remote, end = _remote([{"over": True, "rc": p.returncode, "said": [], "left": []}], lines=p.stdout)
        end.mine.send(json.dumps({"ended": True}).encode())
        return remote


def test_the_website_starts_each_step_through_the_switcher(tmp_path, monkeypatch):
    """Where the switcher started the service, a check's step is handed to it (the check's folder by name, the
    command, the environment, whether it reads the network) and runs only in the check's temp folder; a step it
    cannot start ends the check with a sentence for the person, never with the step run some other way."""
    cloud = _service(tmp_path)
    w = worker_mod.Worker(cloud.app.state.settings, cloud.app.state.store)
    try:
        client = _StepClient()
        w.users = apart.SwitchedUsers(client)
        root = w.cleanup.fresh("run-")
        (root / "tmp").mkdir()
        w.users.take(root)
        rc, output, timed_out = w._jailed("r", root, [sys.executable, "-c", "print('STEPPED')"], cwd=root / "tmp",
                                          net=False, log=lambda m: None, timeout=60)
        assert (rc, timed_out) == (0, False) and "STEPPED" in output, output
        assert client.steps[0][0] == root.name and client.steps[0][2] is False
        with pytest.raises(RuntimeError, match="temp folder"):
            w._jailed("r", root, [sys.executable, "-c", "pass"], cwd=root, net=False, log=lambda m: None, timeout=60)
        w.users = apart.SwitchedUsers(_StepClient(refuse=True))
        w.users.take(root)
        with pytest.raises(worker_mod.RunFailed) as e:
            w._jailed("r", root, [sys.executable, "-c", "pass"], cwd=root / "tmp", net=False, log=lambda m: None,
                      timeout=60)
        assert str(e.value.args[0]) == worker_mod.STEP_NOT_STARTED
    finally:
        w.shutdown()


# ---------------------------------------------------------------------------- as root: the hand-over and the hand-back
def _owner(p: Path) -> int:
    return os.lstat(p).st_uid


def _check_folder(base: Path) -> Path:
    """A check's folder as the service makes one: its own, with a temp folder and a copy of the code."""
    root = base / "work" / CHECK
    (root / "tmp" / "out").mkdir(parents=True)
    (root / "src" / "app").mkdir(parents=True)
    (root / "tmp" / "out" / "result.json").write_text("{}", encoding="utf-8")
    (root / "src" / "app" / "main.py").write_text("print(1)\n", encoding="utf-8")
    for p in [base / "work", root, *root.rglob("*")]:
        os.chown(p, SERVICE, SERVICE, follow_symlinks=False)
    return root


@AS_ROOT
def test_the_hand_over_changes_only_what_it_holds_and_never_what_a_link_names(tmp_path):
    """Before a step, the check's temp folder and its copy of the code, with what is in them, become the check's
    user's. A service that was taken over can plant things there: a link to a file and to a folder of root's, a
    second name of a file of its own (which may be the name of somebody else's file), a pipe, a folder of somebody
    else's, a program that keeps its owner's rights when it is run. The link's own owner changes and what it names
    does not; the second name, the pipe and the other's folder stay as they are, and nothing in that folder is
    looked at; the program loses the bit. The twin: the service's own files and folders become the user's."""
    os.chmod(tmp_path, 0o755)
    root = _check_folder(tmp_path)
    tmp, uid = root / "tmp", _jail.STEP_USERS[11]
    victim = tmp_path / "root-only.txt"
    victim.write_text(SECRET, encoding="utf-8")
    victim_dir = tmp_path / "root-only"
    victim_dir.mkdir()
    (tmp / "to-file").symlink_to(victim)
    (tmp / "to-folder").symlink_to(victim_dir, target_is_directory=True)
    outside = tmp_path / "service-elsewhere.txt"
    outside.write_text("x", encoding="utf-8")
    os.chown(outside, SERVICE, SERVICE)
    os.link(outside, tmp / "second-name")
    os.mkfifo(tmp / "pipe")
    others = tmp / "others"
    others.mkdir()
    (others / "inside.txt").write_text("x", encoding="utf-8")
    os.chown(others / "inside.txt", SERVICE, SERVICE)
    os.chown(others, OTHER, OTHER)
    (tmp / "prog").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(tmp / "prog", 0o4755)
    for p in (tmp / "to-file", tmp / "to-folder", tmp / "pipe", tmp / "prog"):
        os.chown(p, SERVICE, SERVICE, follow_symlinks=False)
    os.chmod(tmp / "prog", 0o4755)          # a change of owner takes the bit away by itself: set it again
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        kept = switcher.hand_over(fd, uid, SERVICE)
    finally:
        os.close(fd)
    assert [_owner(victim), _owner(victim_dir)] == [0, 0] and victim.read_text(encoding="utf-8") == SECRET
    assert [_owner(tmp / "to-file"), _owner(tmp / "to-folder")] == [uid, uid]
    assert [_owner(tmp / "second-name"), _owner(outside), _owner(tmp / "pipe")] == [SERVICE] * 3
    assert [_owner(others), _owner(others / "inside.txt")] == [OTHER, SERVICE]
    assert _owner(tmp / "prog") == uid and not os.lstat(tmp / "prog").st_mode & (stat.S_ISUID | stat.S_ISGID)
    # the twin: the service's own, all of it
    for p in (tmp, tmp / "out", tmp / "out" / "result.json", root / "src", root / "src" / "app" / "main.py"):
        assert _owner(p) == uid, p
    assert [stat.S_IMODE(os.lstat(p).st_mode) for p in (root, tmp, root / "src")] == [0o711, 0o700, 0o700]
    assert _owner(root) == SERVICE and kept == 1      # the file with a second name could not be handed over


@AS_ROOT
def test_the_hand_back_never_follows_what_a_step_left(tmp_path):
    """After a step, what is the check's user's in its folder becomes the service's again, which may then read,
    write and remove it. A step that was taken over can leave a link to a file of root's, a second name of a file
    of root's, a pipe, a folder of somebody else's: none of them is followed, opened or handed to the service; a
    second name of a file stays the step's. The twin: the step's own files and folders are the service's, readable
    and writable by it."""
    os.chmod(tmp_path, 0o755)
    root = _check_folder(tmp_path)
    tmp, uid = root / "tmp", _jail.STEP_USERS[12]
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        switcher.hand_over(fd, uid, SERVICE)
        victim = tmp_path / "root-only.txt"
        victim.write_text(SECRET, encoding="utf-8")
        (tmp / "to-file").symlink_to(victim)
        os.link(victim, tmp / "second-of-roots")
        own = tmp / "written"
        own.write_text("x", encoding="utf-8")
        os.link(own, tmp / "second-of-its-own")
        os.mkfifo(tmp / "pipe")
        (tmp / "deep" / "er").mkdir(parents=True)
        (tmp / "deep" / "er" / "f").write_text("x", encoding="utf-8")
        others = tmp / "others"
        others.mkdir()
        (others / "f").write_text("x", encoding="utf-8")
        for p in (tmp / "to-file", own, tmp / "pipe", tmp / "deep", tmp / "deep" / "er", tmp / "deep" / "er" / "f",
                  others / "f"):
            os.chown(p, uid, uid, follow_symlinks=False)
        os.chmod(tmp / "deep" / "er" / "f", 0o400)
        os.chown(others, OTHER, OTHER)
        kept = switcher.hand_back(fd, uid, SERVICE, SERVICE)
    finally:
        os.close(fd)
    assert _owner(victim) == 0 and _owner(tmp / "second-of-roots") == 0 and victim.read_text(encoding="utf-8") == SECRET
    assert _owner(tmp / "to-file") == SERVICE and _owner(tmp / "pipe") == uid
    assert _owner(own) == uid and kept == 2         # a file with a second name stays the step's: both its names
    assert [_owner(others), _owner(others / "f")] == [OTHER, uid]
    for p in (tmp, tmp / "out" / "result.json", tmp / "deep", tmp / "deep" / "er", root / "src" / "app" / "main.py"):
        assert _owner(p) == SERVICE, p
    assert stat.S_IMODE(os.lstat(tmp / "deep" / "er" / "f").st_mode) == 0o600 and _owner(tmp / "deep" / "er" / "f") == SERVICE


@AS_ROOT
def test_a_tree_deeper_than_it_follows_is_counted_not_followed(tmp_path, monkeypatch):
    os.chmod(tmp_path, 0o755)
    root = _check_folder(tmp_path)
    deep = root / "tmp"
    for i in range(6):
        deep = deep / f"d{i}"
        deep.mkdir()
        os.chown(deep, SERVICE, SERVICE)
    monkeypatch.setattr(switcher, "MOST_DEPTH", 3)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        kept = switcher.hand_over(fd, _jail.STEP_USERS[13], SERVICE)
    finally:
        os.close(fd)
    assert kept >= 1 and _owner(root / "tmp" / "d0") == _jail.STEP_USERS[13] and _owner(deep) == SERVICE


@AS_ROOT
def test_what_is_on_the_services_disk_becomes_its_own_when_the_switcher_starts(tmp_path):
    """What the service made while it ran as root, what a step left when the machine stopped (`nobody`'s, a check's
    user's) become the service's user's when the switcher starts. Somebody else's file, a file of root's with a
    second name, what a link names and the disk's own lost+found are left as they are."""
    data = tmp_path / "data"
    (data / "results" / "x").mkdir(parents=True)
    (data / "lost+found").mkdir()
    made = {"by-root": 0, "by-nobody": _jail.NOBODY, "by-a-step": _jail.STEP_USERS[3], "already": SERVICE}
    for name, uid in made.items():
        (data / "results" / "x" / name).write_text("x", encoding="utf-8")
        os.chown(data / "results" / "x" / name, uid, uid)
    (data / "results" / "x" / "somebody").write_text("x", encoding="utf-8")
    os.chown(data / "results" / "x" / "somebody", OTHER, OTHER)
    victim = tmp_path / "root-only.txt"
    victim.write_text(SECRET, encoding="utf-8")
    (data / "results" / "link").symlink_to(victim)
    os.link(victim, data / "results" / "second")
    fd = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
    try:
        kept = switcher.take_over(fd, SERVICE, SERVICE, mounted=True)
    finally:
        os.close(fd)
    assert {n: _owner(data / "results" / "x" / n) for n in made} == dict.fromkeys(made, SERVICE)
    assert _owner(data / "results" / "x" / "somebody") == OTHER and _owner(data / "lost+found") == 0
    assert _owner(victim) == 0 and _owner(data / "results" / "link") == SERVICE and kept == 1
    assert _owner(data) == SERVICE and stat.S_IMODE(os.lstat(data).st_mode) == 0o711


# ---------------------------------------------------------------------------- as root: the real switcher
START = "import sys; sys.path[:0] = [{pkgs!r}, {cloud!r}]; from lantern_cloud.switcher import main; sys.exit(main(sys.argv[1:]))"

# The service of these tests: hands the test its end of the switcher's socket, says who it runs as, and waits.
RELAY = r"""
import json, os, socket, sys
fd = int(os.environ["LANTERN_CLOUD_SWITCHER_FD"])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
me = {"ids": [os.getuid(), os.geteuid(), os.getgid(), os.getegid()], "groups": os.getgroups(), "pid": os.getpid(),
      "home": os.environ.get("HOME"), "user": os.environ.get("USER")}
socket.send_fds(s, [json.dumps(me).encode()], [fd])
s.recv(1)
"""


@pytest.fixture(scope="module")
def pkgs():
    """Lantern's two packages, copied where the switcher runs them from as root: root's, and every folder above
    them root's or a folder like /tmp, as in the image (the checkout itself may be the ordinary user's)."""
    if os.geteuid() != 0:
        pytest.skip("needs root: only root can start a program as another user")
    top = Path(tempfile.mkdtemp(prefix="lantern-switcher-pkgs-", dir="/tmp"))
    os.chmod(top, 0o755)
    skip = shutil.ignore_patterns("__pycache__")
    shutil.copytree(lantern_files.PACKAGE, top / "lantern", ignore=skip)   # as Python loaded it (a release: installed)
    (top / "cloud").mkdir(mode=0o755)
    shutil.copytree(ROOT / "cloud" / "lantern_cloud", top / "cloud" / "lantern_cloud", ignore=skip)
    for p in [top, *top.rglob("*")]:
        os.chown(p, 0, 0, follow_symlinks=False)
        if not p.is_symlink():
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
    yield top
    shutil.rmtree(top, ignore_errors=True)


def _start_cmd(python: str, pkgs: Path) -> list[str]:
    return [python, "-I", "-c", START.format(pkgs=str(pkgs), cloud=str(pkgs / "cloud"))]


@pytest.fixture(scope="module")
def python(pkgs):
    """A Python the switcher may run as root: one the service's user could not change. This computer's own if the
    one running the tests is not (a runner's tool folders may be open to everyone); none is a failure, never a skip."""
    said = {}
    for cand in dict.fromkeys([sys.executable, "/usr/bin/python3"]):
        if not os.path.exists(cand):
            continue
        code = (f"import sys; sys.path[:0] = [{str(pkgs)!r}, {str(pkgs / 'cloud')!r}]\n"
                f"from lantern_cloud.switcher import unchangeable\nprint(unchangeable({SERVICE}, {SERVICE}))")
        r = subprocess.run([cand, "-I", "-c", code], capture_output=True, text=True, encoding="utf-8", timeout=120)
        said[cand] = (r.stdout + r.stderr).strip()[-300:]
        if r.returncode == 0 and r.stdout.strip() == "None":
            return cand
    pytest.fail(f"no Python here that the service's user could not change: {said}")


@pytest.fixture
def data():
    """The service's disk: a folder of the service's user, under /tmp (others may pass through to a check's own
    folder), with its database, another person's results and Lantern's own folder."""
    d = Path(tempfile.mkdtemp(prefix="lantern-switcher-data-", dir="/tmp"))
    os.chmod(d, 0o755)
    (d / "results" / "SoMeOnE").mkdir(parents=True)
    (d / "results" / "SoMeOnE" / "report.html").write_text(SECRET, encoding="utf-8")
    (d / "lantern_cloud.db").write_text(SECRET, encoding="utf-8")
    (d / "lantern").mkdir()
    (d / "work").mkdir()
    for p in [d, *d.rglob("*")]:
        os.chown(p, SERVICE, SERVICE)
    os.chmod(d / "lantern_cloud.db", 0o600)
    os.chmod(d / "results", 0o700)
    os.chmod(d / "work", 0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _env(data: Path, **more) -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1",
           "LANTERN_NO_REAL_PROVIDERS": "1", "LANTERN_CLOUD_SERVICE_USER": str(SERVICE),
           "LANTERN_CLOUD_DATA": str(data), "LANTERN_CLOUD_DB": f"{data}/lantern_cloud.db",
           "LANTERN_CLOUD_RESULTS": f"{data}/results", "LANTERN_CLOUD_WORK": f"{data}/work",
           "LANTERN_CLOUD_UPLOADS": f"{data}/work-uploads", "LANTERN_HOME": f"{data}/lantern"}
    env.update({k: v for k, v in more.items() if v is not None})
    for k in [k for k, v in more.items() if v is None]:
        env.pop(k, None)
    return env


class Switched:
    """A real switcher, started as root, whose service is the relay: the test holds the service's end of the
    socket (a `switcher.Client`), as the service would."""

    def __init__(self, python: str, pkgs: Path, data: Path, monkeypatch, **env):
        self.dir = Path(tempfile.mkdtemp(prefix="lantern-switcher-sock-", dir="/tmp"))
        os.chmod(self.dir, 0o755)
        where = self.dir / "relay.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(where))
        os.chmod(where, 0o777)
        listener.listen(1)
        listener.settimeout(60)
        self.out = open(self.dir / "out.txt", "w+", encoding="utf-8")   # noqa: SIM115 - closed in `end`
        cmd = [*_start_cmd(python, pkgs), "--", python, "-I", "-c", RELAY, str(where)]
        self.proc = subprocess.Popen(cmd, env=_env(data, **env), cwd="/", stdin=subprocess.DEVNULL, stdout=self.out,
                                     stderr=subprocess.STDOUT)
        try:
            self.conn, _ = listener.accept()
            msg, fds, _flags, _ = socket.recv_fds(self.conn, 1 << 16, 2)
        finally:
            listener.close()
        self.me = json.loads(msg)
        monkeypatch.setattr(switcher, "_ended_with_the_switcher", lambda: None)
        self.client = switcher.Client(fds[0])

    def said(self) -> str:
        self.out.flush()
        return (self.dir / "out.txt").read_text(encoding="utf-8")

    def end(self) -> int:
        self.client.sock.close()
        self.conn.close()
        try:
            return self.proc.wait(60)
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(10)
            self.out.close()
            shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def sw(python, pkgs, data, monkeypatch):
    s = Switched(python, pkgs, data, monkeypatch)
    yield s
    rc = s.end()
    assert rc == 0, s.said()
    assert _step_users_running() == []


def _step_users_running() -> list[int]:
    found = []
    for pid in os.listdir("/proc"):
        try:
            with open(f"/proc/{pid}/status", "rb") as f:
                uid = next(int(x.split()[1]) for x in f.read().splitlines() if x.startswith(b"Uid:"))
        except (OSError, ValueError, StopIteration, IndexError):
            continue
        if uid in _jail.STEP_USERS:
            found.append(int(pid))
    return found


def _uids(pid: int) -> list[int]:
    with open(f"/proc/{pid}/status", "rb") as f:
        return [int(x) for x in next(x for x in f.read().splitlines() if x.startswith(b"Uid:")).split()[1:]]


def _new_check(data: Path, name: str = CHECK) -> Path:
    root = data / "work" / name
    (root / "tmp").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "code.py").write_text("print('the project')\n", encoding="utf-8")
    for p in [root, *root.rglob("*")]:
        os.chown(p, SERVICE, SERVICE)
    os.chmod(root, 0o700)
    return root


def _own(lines: list[str]) -> list[str]:
    """A step's own lines, without the launcher's (`sandbox: ...`: which walls stand), as the website's log has both."""
    return [x for x in lines if not x.startswith("sandbox: ")]


def _run_step(sw, python, argv, net=False, name=CHECK, stop_after=None):
    """One step through the switcher, as the service runs one: its lines until it ends (or `stop_after` lines of
    its own), then the stop. Returns (lines, said, left, returncode)."""
    r = sw.client.step(name, [python, *argv], {"PATH": "/usr/bin:/bin"}, net)
    lines = []
    for line in r.stdout:
        lines.append(line.rstrip("\n"))
        if stop_after is not None and len(_own(lines)) >= stop_after:
            break
    if stop_after is None:
        deadline = time.monotonic() + 60
        while not r.ended() and time.monotonic() < deadline:
            time.sleep(0.05)
    said, left = r.stop(2.0)
    r.stdout.close()
    return lines, said, left, r.returncode


LOOK = r"""
import os, socket, sys
st = os.stat(os.getcwd())
print("STEP", os.getuid(), os.geteuid(), os.getgid(), os.getegid(), len(os.getgroups()), st.st_uid,
      oct(st.st_mode & 0o777), flush=True)
def look(kind, path, how):
    try:
        if how == "file":
            with open(path, "rb") as f:
                f.read(1)
        else:
            os.listdir(path)
        said = "read"
    except PermissionError:
        said = "refused"
    except OSError as e:
        said = "error-%d" % e.errno
    print("LOOKED", kind, said, flush=True)
a = sys.argv[1:-1]
for i in range(0, len(a), 3):
    look(*a[i:i + 3])
look("own-code", os.path.join(os.getcwd(), "..", "src", "code.py"), "file")
with open("written", "w") as f:
    f.write("by the step")
look("own-file", "written", "file")
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"STEP", ("127.0.0.1", int(sys.argv[-1])))
    print("SENT", flush=True)
except OSError as e:
    print("NOT-SENT", e.errno, flush=True)
"""


@AS_ROOT
def test_the_switcher_alone_is_root_and_the_service_an_ordinary_user_of_its_own(sw, data):
    """The switcher (root) starts the service as the user it was told, with no other group, its home its own
    folder, and gives what is in that folder to it; the service learns which program the switcher is."""
    assert sw.me["ids"] == [SERVICE] * 4 and sw.me["groups"] == [], sw.me
    assert sw.me["home"] == str(data) and sw.me["user"] == str(SERVICE)
    assert _uids(sw.proc.pid) == [0] * 4 and _uids(sw.me["pid"]) == [SERVICE] * 4
    assert sw.client.pid == sw.proc.pid
    assert _owner(data) == SERVICE and stat.S_IMODE(os.lstat(data).st_mode) == 0o711
    assert "the service runs as user 61000" in sw.said()


@AS_ROOT
def test_a_step_runs_as_its_checks_user_and_reads_none_of_the_services_files(sw, python, data):
    """A step of a check: as the check's own user, no other group, in its temp folder (that user's, owner only),
    with a network of its own (a datagram to this computer's address arrives nowhere). It cannot read the service's
    database, another person's results, the service's environment and open files, or the switcher's environment;
    it reads its own code and writes its own folder. After it, what it wrote is the service's, which reads it. The
    twin: a step that reads the network reaches the same listener."""
    root = _new_check(data)
    uid = sw.client.take(CHECK)
    assert uid in _jail.STEP_USERS and sw.client.take(CHECK) == uid
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(0.3)
    port = rx.getsockname()[1]
    places = ["database", str(data / "lantern_cloud.db"), "file", "results", str(data / "results"), "list",
              "report", str(data / "results" / "SoMeOnE" / "report.html"), "file",
              "service-env", f"/proc/{sw.me['pid']}/environ", "file", "service-fds", f"/proc/{sw.me['pid']}/fd", "list",
              "switcher-env", f"/proc/{sw.proc.pid}/environ", "file", "work", str(data / "work"), "list"]
    try:
        lines, said, left, rc = _run_step(sw, python, ["-S", "-c", LOOK, *places, str(port)])
        step = [x.split()[1:] for x in lines if x.startswith("STEP ")]
        assert step == [[str(uid)] * 4 + ["0", str(uid), "0o700"]], lines
        looked = dict(x.split()[1:] for x in lines if x.startswith("LOOKED "))
        assert {k: v for k, v in looked.items() if not k.startswith("own-")} == {
            k: "refused" for k in ("database", "results", "report", "service-env", "service-fds", "switcher-env",
                                   "work")}, lines
        assert looked["own-code"] == looked["own-file"] == "read", lines
        assert rc == 0 and left == [] and "SENT" in lines, (rc, said, left, lines)
        with pytest.raises(TimeoutError):
            rx.recv(100)
        assert _owner(root / "tmp" / "written") == SERVICE and _owner(root / "tmp") == SERVICE
        assert (root / "tmp" / "written").read_text(encoding="utf-8") == "by the step"
        lines, _said, left, rc = _run_step(sw, python, ["-S", "-c", LOOK, str(port)], net=True)
        assert rc == 0 and left == [] and rx.recv(100) == b"STEP", lines
    finally:
        rx.close()
    assert sw.client.give_back(CHECK) == 0


AFTER = r"""
import os
print("READ", open("audits.json").read(), open(os.path.join("out", "x")).read(), open(os.path.join("out", "more")).read(),
      flush=True)
"""


@AS_ROOT
def test_a_later_step_finds_what_an_earlier_step_wrote(sw, python, data):
    """The dependency audit writes its file, the analysis reads it: between them the switcher hands everything back
    to the service (which reads it and adds to it) and over again."""
    root = _new_check(data)
    sw.client.take(CHECK)
    first = "import os\nopen('audits.json', 'w').write('A')\nos.mkdir('out')\nopen(os.path.join('out', 'x'), 'w').write('X')\n"
    lines, _said, left, rc = _run_step(sw, python, ["-S", "-c", first])
    assert rc == 0 and left == [], lines
    assert [_owner(root / "tmp" / p) for p in ("audits.json", "out", "out/x")] == [SERVICE] * 3
    (root / "tmp" / "out" / "more").write_text("M", encoding="utf-8")     # what the service made for the next step
    os.chown(root / "tmp" / "out" / "more", SERVICE, SERVICE)
    lines, _said, left, rc = _run_step(sw, python, ["-S", "-c", AFTER])
    assert rc == 0 and "READ A X M" in lines, lines
    sw.client.give_back(CHECK)


LINGER = r"""
import subprocess, sys, time
subprocess.Popen(["sleep", "300"], start_new_session=True)
print("STARTED", flush=True)
time.sleep(300)
"""


@AS_ROOT
def test_a_step_stopped_ends_with_everything_it_started(sw, python, data):
    """The service stops a step: the step and what it started in a session of its own are ended, nothing of the
    check's user runs any more, and the run says nothing was left. The twin: a step that ends by itself is said to
    have ended, with its result."""
    _new_check(data)
    uid = sw.client.take(CHECK)
    lines, said, left, rc = _run_step(sw, python, ["-S", "-c", LINGER], stop_after=1)
    assert _own(lines) == ["STARTED"] and left == [] and _jail.processes_of(uid) == [], (lines, said, left)
    lines, said, left, rc = _run_step(sw, python, ["-S", "-c", "import sys; print('DONE'); sys.exit(3)"])
    assert _own(lines) == ["DONE"] and rc == 3 and left == [], (lines, said)
    assert sw.client.give_back(CHECK) == 0


@AS_ROOT
def test_when_the_service_goes_the_steps_go_with_it(python, pkgs, data, monkeypatch):
    """The service ends while a step runs (it was stopped, or it broke): the switcher ends the step with everything
    it started, ends what the check's user still runs, and ends itself with the service's result."""
    s = Switched(python, pkgs, data, monkeypatch)
    try:
        _new_check(data)
        uid = s.client.take(CHECK)
        r = s.client.step(CHECK, [python, "-S", "-c", LINGER], {"PATH": "/usr/bin:/bin"}, False)
        line = r.stdout.readline()
        while line.startswith("sandbox: "):
            line = r.stdout.readline()
        assert line.strip() == "STARTED"
        assert _jail.processes_of(uid)
    finally:
        rc = s.end()
    assert rc == 0 and _step_users_running() == [], s.said() if not s.out.closed else rc


@AS_ROOT
def test_the_switcher_refuses_a_check_folder_that_is_not_the_services(sw, data, tmp_path):
    """A folder of root's in the work folder, a link in place of a check's folder, and a check never given a user:
    refused, and nothing is started. The twin: the service's own folder is given a user."""
    root = data / "work" / "run-root0000"
    root.mkdir()
    with pytest.raises(switcher.Refused, match="not the service's"):
        sw.client.take("run-root0000")
    elsewhere = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        os.chown(elsewhere, SERVICE, SERVICE)
        (data / "work" / "run-link0000").symlink_to(elsewhere, target_is_directory=True)
        os.chown(data / "work" / "run-link0000", SERVICE, SERVICE, follow_symlinks=False)
        with pytest.raises(switcher.Refused, match="no such check folder"):
            sw.client.take("run-link0000")
    finally:
        shutil.rmtree(elsewhere, ignore_errors=True)
    _new_check(data)
    with pytest.raises(switcher.Refused, match="given no user"):
        sw.client.step(CHECK, ["/bin/true"], {}, False)
    assert sw.client.take(CHECK) in _jail.STEP_USERS
    sw.client.give_back(CHECK)


def _refused_at_start(python, pkgs, data, **env) -> tuple[int, str]:
    r = subprocess.run([*_start_cmd(python, pkgs), "--", python, "-I", "-c", "print('SERVICE-RAN')"],
                       env=_env(data, **env), cwd="/", capture_output=True, text=True, encoding="utf-8", timeout=120)
    return r.returncode, r.stdout + r.stderr


@AS_ROOT
def test_the_switcher_starts_nothing_where_root_could_be_misled(python, pkgs, data, tmp_path):
    """Root as the service's user, a service folder that is a link, or somebody else's, a place of the service
    outside its folder: the switcher starts no service. The twin: the right set-up starts it."""
    link = Path(tempfile.mkdtemp(dir="/tmp"))
    os.rmdir(link)
    link.symlink_to(data, target_is_directory=True)
    try:
        cases = {"the service as root": ({"LANTERN_CLOUD_SERVICE_USER": "0"}, "ordinary user"),
                 "a service folder that is a link": ({"LANTERN_CLOUD_DATA": str(link)}, "not a folder"),
                 "a place outside it": ({"LANTERN_CLOUD_DB": "/tmp/elsewhere.db"}, "LANTERN_CLOUD_DB")}
        for name, (env, why) in cases.items():
            rc, out = _refused_at_start(python, pkgs, data, **env)
            assert rc == 2 and why in out and "SERVICE-RAN" not in out, (name, out)
        os.chown(data, OTHER, OTHER)
        rc, out = _refused_at_start(python, pkgs, data)
        assert rc == 2 and "neither" in out and "SERVICE-RAN" not in out, out
        os.chown(data, SERVICE, SERVICE)
        rc, out = _refused_at_start(python, pkgs, data)
        assert rc == 0 and "SERVICE-RAN" in out, out
    finally:
        link.unlink()


@AS_ROOT
def test_the_switcher_starts_nothing_while_the_service_could_change_its_code(python, pkgs, data):
    """A file of Lantern's packages that the service's user may change would be run as root: the switcher says
    which, and starts nothing. The twin: the packages as they are start the service."""
    mod = pkgs / "lantern" / "_jail.py"
    os.chown(mod, SERVICE, SERVICE)
    try:
        rc, out = _refused_at_start(python, pkgs, data)
    finally:
        os.chown(mod, 0, 0)
    assert rc == 2 and "could change" in out and str(mod) in out and "SERVICE-RAN" not in out, out
    rc, out = _refused_at_start(python, pkgs, data)
    assert rc == 0 and "SERVICE-RAN" in out, out


# ---------------------------------------------------------------------------- as root: a whole check under the switcher
WEBSITE = r"""
import json, os, subprocess, sys, time
sys.path[:0] = sys.argv[1].split(os.pathsep)
import httpx
from fastapi.testclient import TestClient
from lantern import remote
from lantern_cloud import worker as worker_mod
from lantern_cloud.app import create_app
from lantern_cloud.settings import Settings
from lantern_gateway.app import Settings as GwSettings, create_app as create_gateway

origin = sys.argv[2]
def clone(link, dest, log):
    subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + origin, str(dest)], check=True, cwd=dest.parent,
                   capture_output=True)
    remote._mark(dest)
    return dest
worker_mod.clone_repo = clone
gw = create_gateway(GwSettings(admin_secret="a" * 24, db_path=os.path.join(os.environ["LANTERN_CLOUD_DATA"], "gw.db")))
cloud = TestClient(create_app(Settings(gateway_url="http://gateway.test/v1", audits=False),
                              transport=httpx.ASGITransport(app=gw)))
end = time.monotonic() + 120
while cloud.get("/v1/health").json()["steps"] == "unchecked" and time.monotonic() < end:
    time.sleep(0.2)
health = cloud.get("/v1/health").json()
tok = gw.state.store.sign_in("github:1", "github:u1")
head = {"authorization": "Bearer " + tok}
rid = cloud.post("/v1/repos", json={"link": "https://github.com/octo/shop"}, headers=head).json()["id"]
while time.monotonic() < end + 240:
    run = cloud.get(f"/v1/runs/{rid}", headers=head).json()
    if run["status"] not in ("queued", "running"):
        break
    time.sleep(0.3)
lines = cloud.app.state.worker.logs.since(rid, 0)[0]
work = os.environ["LANTERN_CLOUD_WORK"]
print("WEBSITE " + json.dumps({"health": health, "run": run, "lines": lines[-60:], "uid": os.getuid(),
                               "left": os.listdir(work), "report": os.path.isfile(os.path.join(
                                   os.environ["LANTERN_CLOUD_RESULTS"], rid, "report.html"))}), flush=True)
cloud.app.state.worker.shutdown()
"""


@AS_ROOT
def test_a_whole_check_of_the_sample_by_the_website_under_the_switcher(python, pkgs, data, tmp_path):
    """The twin of everything above: the website's own service, started by the switcher as its ordinary user,
    proves when it starts that a check's user can read none of its files ("apart"), clones the sample, runs
    Lantern's analysis as the check's user through the switcher, finds what it always finds and keeps the report;
    nothing of the check is left in the work folder and nothing of its user still runs."""
    (data / "lantern_cloud.db").unlink()     # the service makes its own database (the fixture's holds only text)
    origin = Path(tempfile.mkdtemp(prefix="lantern-switcher-origin-", dir="/tmp")) / "shop"
    try:
        shutil.copytree(ROOT / "tests" / "fixtures" / "shop", origin)
        for args in (["init", "-q", "-b", "main"], ["add", "-A"],
                     ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x"]):
            subprocess.run(["git", *args], cwd=origin, check=True, capture_output=True)
        for p in [origin.parent, origin, *origin.rglob("*")]:
            os.chown(p, SERVICE, SERVICE, follow_symlinks=False)
        os.chmod(origin.parent, 0o755)
        paths = os.pathsep.join([str(pkgs), str(pkgs / "cloud"), str(ROOT / "gateway")])
        cmd = [*_start_cmd(python, pkgs), "--", sys.executable, "-I", "-c", WEBSITE, paths, str(origin)]
        r = subprocess.run(cmd, env=_env(data, LANTERN_CLOUD_STEPS_APART="required"), cwd="/", capture_output=True,
                           text=True, encoding="utf-8", timeout=600)
    finally:
        shutil.rmtree(origin.parent, ignore_errors=True)
    got = [x for x in r.stdout.splitlines() if x.startswith("WEBSITE ")]
    assert r.returncode == 0 and got, (r.returncode, r.stdout[-3000:], r.stderr[-3000:])
    w = json.loads(got[0][len("WEBSITE "):])
    assert w["uid"] == SERVICE and (w["health"]["steps"], w["health"]["service_user"]) == ("apart", "own"), w["health"]
    assert w["run"]["status"] == "done", (w["run"], w["lines"])
    assert w["run"]["summary"]["counts"]["critical"] >= 1 and len(w["run"]["commit"]) == 40, w["run"]
    assert apart.APART in w["lines"] and w["report"] and w["left"] == [], (w["lines"], w["left"])
    assert _step_users_running() == []
