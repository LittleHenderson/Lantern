"""The test machine's program (a firm pass or fail, stage 3, step 4; the design: "Website test runs").

The website will run a project's tests on a machine of their own, made for one check and thrown away after it. On
that machine `lantern.runner` takes the project and the libraries the website fetched for it as one archive, runs
the tests in Lantern's sandbox as an ordinary user, and writes the result. It is reached through one door that
answers only to the check's own key.

Each refusal stands beside an honest twin that must still work: a setting of the wrong shape beside the same
setting of the right one, a link npm does not make beside the links it does, a request without the key beside the
same request with it, a test that knocks on the door beside a test that calls a server of its own. The end-to-end
tests start the program as it starts on the machine and need Linux and root, where the sandbox runs the tests as
an ordinary user (CI's Linux jobs are root); everything else runs on every system."""
from __future__ import annotations

import hashlib
import http.client
import importlib.metadata
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import threading
import time
import zipfile
from pathlib import Path

import pytest

from lantern import archive, runner, sandbox

ROOT = Path(__file__).resolve().parent.parent
LINUX_ROOT = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
needs_the_machine = pytest.mark.skipif(not LINUX_ROOT, reason="the test machine is Linux and its program runs as root, "
                                       "so that the tests run as an ordinary user")


def _key() -> tuple[str, str]:
    key = secrets.token_urlsafe(32)
    return key, hashlib.sha256(key.encode()).hexdigest()


def _settings(**more) -> dict:
    said = {"version": 1, "command": ["python", "-m", "unittest", "-v"], "minutes": 5, "memory": 1024,
            "libraries": {"state": "none", "language": "python"}}
    said.update(more)
    return said


def _raw(said: dict) -> bytes:
    return json.dumps(said).encode()


def _zip(path: Path, entries: list) -> Path:
    """`entries`: (name, text or bytes) for a file, (name, None) for a folder, (name, text, mode) for a file with
    that mode, (name, "->", target) for a symbolic link."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for e in entries:
            name, data, *rest = e
            if data is None:
                z.writestr(zipfile.ZipInfo(name.rstrip("/") + "/"), b"")
                continue
            info = zipfile.ZipInfo(name, (2026, 11, 21, 0, 0, 0))
            if data == "->":
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, rest[0])
                continue
            info.external_attr = (stat.S_IFREG | (rest[0] if rest else 0o644)) << 16
            z.writestr(info, data)
    return path


# ---------------------------------------------------------------------------- the check's settings, by shape
def test_the_settings_take_a_test_command_and_nothing_else():
    said = runner.settings(_raw(_settings()))
    assert said["command"] == ["python", "-m", "unittest", "-v"] and said["language"] == "python"
    assert runner.settings(_raw(_settings(command=["npm", "test"], libraries={"state": "none", "language": "node"})))[
        "language"] == "node"
    for bad in (["bash", "-c", "curl x"], [], "python -m pytest", ["python", 3], ["python", "-m", "pytest\x00"],
                ["pytest"] + ["-q"] * 100, ["python", "-m", "pytest", "x" * 5000]):
        with pytest.raises(runner.Refused):
            runner.settings(_raw(_settings(command=bad)))


def test_the_numbers_keep_to_their_ranges():
    for minutes in (1, 240):
        assert runner.settings(_raw(_settings(minutes=minutes)))["minutes"] == minutes
    for minutes in (0, 241, "10", True, 2.5, None):
        with pytest.raises(runner.Refused, match="minutes"):
            runner.settings(_raw(_settings(minutes=minutes)))
    assert runner.settings(_raw(_settings(memory=128)))["memory"] == 128
    for memory in (127, "2048", False, 1 << 21):
        with pytest.raises(runner.Refused, match="memory"):
            runner.settings(_raw(_settings(memory=memory)))


def test_the_folder_the_tests_run_in_is_inside_the_project():
    assert runner.settings(_raw(_settings(cwd="web/app")))["cwd"] == "web/app"
    assert runner.settings(_raw(_settings()))["cwd"] == ""
    for cwd in ("../x", "/etc", "a/../../b", "a\\b", "a\x00b", "C:/x", 3, "a" * 500, "./"):
        with pytest.raises(runner.Refused, match="folder"):
            runner.settings(_raw(_settings(cwd=cwd)))


def test_only_the_languages_the_machine_has():
    for words in (["go", "test", "./..."], ["cargo", "test"], ["mvn", "test"]):
        with pytest.raises(runner.Refused, match="Python and JavaScript"):
            runner.settings(_raw(_settings(command=words)))
    for words in (["pnpm", "test"], ["yarn", "test"]):     # npm is the one that comes with the machine's Node
        with pytest.raises(runner.Refused, match="npm"):
            runner.settings(_raw(_settings(command=words, libraries={"state": "none", "language": "node"})))


def test_what_this_version_does_not_know_is_refused():
    with pytest.raises(runner.Refused):
        runner.settings(_raw(_settings(more="x")))
    with pytest.raises(runner.Refused):
        runner.settings(_raw(_settings(version=2)))
    for raw in (b"", b"[]", b"{", b"\xff\xfe", b"1" * (runner.MOST_SETTINGS + 1)):
        with pytest.raises(runner.Refused):
            runner.settings(raw)
    with pytest.raises(runner.Refused):
        runner.settings(_raw({k: v for k, v in _settings().items() if k != "memory"}))


def test_the_record_of_the_libraries_is_taken_by_shape():
    fetched = {"state": "fetched", "language": "python", "store": "pypi.org", "added": ["pytest"],
               "packages": [{"name": "pytest", "version": "8.4.2", "fingerprint": "sha256:" + "0" * 64,
                             "file": "pytest-8.4.2-py3-none-any.whl", "asked": False, "exact": False, "checked": False}]}
    assert runner.settings(_raw(_settings(libraries=fetched)))["libraries"]["packages"][0]["name"] == "pytest"
    for bad in ({**fetched, "language": "node"}, {**fetched, "state": "installed"}, {**fetched, "packages": "pytest"},
                {**fetched, "packages": [{"name": 3}]}, "fetched", {"language": "python"}):
        with pytest.raises(runner.Refused, match="libraries"):
            runner.settings(_raw(_settings(libraries=bad)))
    assert runner.settings(_raw(_settings(libraries=fetched, fetched_with="/usr/local/bin/python")))[
        "fetched_with"] == "/usr/local/bin/python"
    for bad in ("python", "/usr/bin/py thon", "/usr/bin/python\n", "/" + "p" * 200, 3):
        with pytest.raises(runner.Refused, match="fetched"):
            runner.settings(_raw(_settings(libraries=fetched, fetched_with=bad)))


# ---------------------------------------------------------------------------- the archive, with the website's rules
def test_a_check_is_unpacked_as_it_was_packed_and_nothing_is_unwrapped(tmp_path):
    src = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x = 1\n")])
    said: dict = {}
    assert archive.unpack(src, tmp_path / "out", 1 << 20, strip=False, said=said) == 2
    assert (tmp_path / "out" / "project" / "test_a.py").is_file() and (tmp_path / "out" / "check.json").is_file()
    assert said == {"files": 2, "bytes": len(_raw(_settings())) + 6, "links": 0}
    # the twin: one top folder is unwrapped where the caller asks for that (an upload of a zipped folder)
    archive.unpack(_zip(tmp_path / "u.zip", [("app/test_a.py", "x\n")]), tmp_path / "up", 1 << 20)
    assert (tmp_path / "up" / "test_a.py").is_file()
    archive.unpack(_zip(tmp_path / "k.zip", [("app/test_a.py", "x\n")]), tmp_path / "kept", 1 << 20, strip=False)
    assert (tmp_path / "kept" / "app" / "test_a.py").is_file()


def test_an_archive_with_more_entries_than_allowed_is_refused(tmp_path):
    src = _zip(tmp_path / "c.zip", [(f"project/f{i}.py", "") for i in range(12)])
    with pytest.raises(archive.Refused, match="more than 10"):
        archive.unpack(src, tmp_path / "out", 1 << 20, strip=False, entries=10)
    assert archive.unpack(src, tmp_path / "ok", 1 << 20, strip=False, entries=12) == 12


def test_the_run_bit_is_kept_and_no_other(tmp_path):
    src = _zip(tmp_path / "c.zip", [("project/run.sh", "echo\n", 0o4777), ("project/a.py", "1\n", 0o666),
                                    ("project/b.py", "1\n", 0o700)])
    archive.unpack(src, tmp_path / "out", 1 << 20, strip=False, modes=True)
    mode = {n: stat.S_IMODE(os.stat(tmp_path / "out" / "project" / n).st_mode) for n in ("run.sh", "a.py", "b.py")}
    if os.name == "posix":
        assert mode == {"run.sh": 0o755, "a.py": 0o644, "b.py": 0o755}
    # the twin: without `modes` every file is written as the system writes a new one, as an upload always was
    archive.unpack(src, tmp_path / "plain", 1 << 20, strip=False)
    assert not os.stat(tmp_path / "plain" / "project" / "run.sh").st_mode & stat.S_ISUID


@pytest.mark.skipif(os.name != "posix", reason="a link of npm's is made where the system makes links")
def test_links_only_where_npm_makes_them(tmp_path):
    ok = [("libraries/jest/bin/jest.js", "#!/usr/bin/env node\n", 0o755), ("libraries/.bin/jest", "->", "../jest/bin/jest.js"),
          ("libraries/a/node_modules/b/cli.js", "x\n"), ("libraries/a/node_modules/.bin/b", "->", "../b/cli.js")]
    archive.unpack(_zip(tmp_path / "ok.zip", ok), tmp_path / "ok", 1 << 20, strip=False, links=runner.links_npm_makes)
    made = tmp_path / "ok" / "libraries" / ".bin" / "jest"
    assert made.is_symlink() and os.readlink(made) == "../jest/bin/jest.js" and made.read_text().startswith("#!")
    assert (tmp_path / "ok" / "libraries" / "a" / "node_modules" / ".bin" / "b").is_symlink()
    bad = {"out of the libraries": ("libraries/.bin/x", "->", "../../project/a.py"),
           "a place of the machine": ("libraries/.bin/x", "->", "/etc/passwd"),
           "out of its own folder": ("libraries/a/node_modules/.bin/x", "->", "../../../jest/bin/jest.js"),
           "into a folder of links": ("libraries/.bin/x", "->", "../a/node_modules/.bin/b"),
           "not in a folder of links": ("libraries/jest/x", "->", "bin/jest.js"),
           "in the project": ("project/x", "->", "a.py"),
           "a backslash": ("libraries/.bin/x", "->", "..\\jest\\bin\\jest.js"),
           "nothing": ("libraries/.bin/x", "->", "")}
    for why, link in bad.items():
        with pytest.raises(archive.Refused, match="link"):
            archive.unpack(_zip(tmp_path / "b.zip", [*ok, link]), tmp_path / "b", 1 << 20, strip=False,
                           links=runner.links_npm_makes)
        assert not (tmp_path / "b").exists(), why
    # a file under a link's name is refused too, whichever comes first in the archive
    for order in ([("libraries/.bin/jest/x", "1"), *ok], [*ok, ("libraries/.bin/jest/x", "1")]):
        with pytest.raises(archive.Refused):
            archive.unpack(_zip(tmp_path / "o.zip", order), tmp_path / "o", 1 << 20, strip=False,
                           links=runner.links_npm_makes)
        assert not (tmp_path / "o").exists()
    # and without a rule for links, as for an upload, none is made
    with pytest.raises(archive.Refused, match="link"):
        archive.unpack(_zip(tmp_path / "n.zip", ok), tmp_path / "n", 1 << 20, strip=False)


def test_take_refuses_an_archive_that_is_not_a_check(tmp_path):
    good = [("check.json", _raw(_settings())), ("project/test_a.py", "x = 1\n")]
    taken = runner.take(_zip(tmp_path / "g.zip", good), tmp_path / "g")
    assert taken["settings"]["command"][0] == "python" and taken["project"].is_dir() and taken["libraries"] is None
    assert taken["files"] == 2
    bad = {"no settings": [("project/test_a.py", "x")],
           "no project": [("check.json", _raw(_settings()))],
           "something else at the top": [*good, ("README.md", "hello")],
           "libraries the settings do not name": [*good, ("libraries/x/__init__.py", "")],
           "settings of the wrong shape": [("check.json", b"{}"), ("project/test_a.py", "x")],
           "a folder the settings name that is not there": [("check.json", _raw(_settings(cwd="web"))),
                                                            ("project/test_a.py", "x")]}
    for why, entries in bad.items():
        with pytest.raises(runner.Refused):
            runner.take(_zip(tmp_path / "b.zip", entries), tmp_path / f"b{len(why)}")
    fetched = {"state": "fetched", "language": "python", "packages": []}
    taken = runner.take(_zip(tmp_path / "l.zip", [("check.json", _raw(_settings(libraries=fetched))),
                                                  ("project/test_a.py", "x"), ("libraries/hello/__init__.py", "")]),
                        tmp_path / "l")
    assert (taken["libraries"] / "hello" / "__init__.py").is_file()


def test_take_refuses_what_does_not_fit_on_the_disk(tmp_path):
    src = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/big.py", "x" * 50_000)])
    with pytest.raises(runner.Refused, match="disk"):
        runner.take(src, tmp_path / "out", free=lambda: 10_000)
    assert runner.take(src, tmp_path / "ok", free=lambda: 1 << 40)["files"] == 2


# ---------------------------------------------------------------------------- the door
class _Door:
    """The door on this computer, with a check that only says what it was handed (no test is run)."""

    def __init__(self, tmp_path: Path, **kw):
        self.key, digest = _key()
        self.handed: list = []

        def check(archive_path, work, log, cancel):
            self.handed.append(Path(archive_path).read_bytes())
            log("sandbox: a check that runs nothing")
            return {"version": 1, "state": "done", "why_not": "", "tests": {"returncode": 0}}
        self.runner = runner.Runner(digest, tmp_path / "work", check=kw.pop("check", check), **kw)
        self.door = runner.Door(("127.0.0.1", 0), self.runner)
        self.port = self.door.server_address[1]
        threading.Thread(target=self.door.serve_forever, daemon=True).start()

    def ask(self, method: str, path: str, body: bytes | None = None, key: str | None = "", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if key is not None:
            h["Authorization"] = "Bearer " + (key or self.key)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, (json.loads(data) if data else None), dict(r.getheaders())

    def close(self):
        self.door.shutdown()
        self.door.server_close()


@pytest.fixture()
def door(tmp_path):
    made = []

    def make(**kw):
        made.append(_Door(tmp_path, **kw))
        return made[-1]
    yield make
    for d in made:
        d.close()


def _until(what, seconds: float = 30.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        got = what()
        if got:
            return got
        time.sleep(0.05)
    raise AssertionError("not in time")


def test_the_door_answers_only_to_the_checks_own_key(door, tmp_path):
    d = door()
    other, _digest = _key()                  # another check's key: random too, made for another machine
    for key in (None, "x", other, d.key + "x", d.key[:-1], "Bearer " + d.key):
        for method, path in (("GET", "/v1/check"), ("POST", "/v1/stop"), ("POST", "/v1/end"), ("GET", "/nothing")):
            status, said, _h = d.ask(method, path, key=key)
            assert status == 401 and said == {"error": "not allowed"}, (key, method, path)
    status, said, _h = d.ask("PUT", "/v1/check", body=b"PK" + b"x" * 100, key=other)
    assert status == 401 and not d.handed and not any((tmp_path / "work").iterdir())
    # the twin: the check's own key
    status, said, headers = d.ask("GET", "/v1/check")
    assert status == 200 and said["state"] == "waiting" and headers.get("Cache-Control") == "no-store"
    assert "Python" not in headers.get("Server", "") and "BaseHTTP" not in headers.get("Server", "")
    assert d.ask("GET", "/nothing")[0] == 404


def test_a_key_is_taken_only_as_the_door_writes_it(tmp_path):
    key, digest = _key()
    r = runner.Runner(digest, tmp_path / "work")
    assert r.allowed("Bearer " + key)
    for said in (None, "", key, "bearer " + key, "Bearer  " + key, "Bearer " + key + " ", "Basic " + key,
                 "Bearer " + key + "\x00", "Bearer " + "é" * 40):
        assert not r.allowed(said), said
    with pytest.raises(ValueError):
        runner.Runner("not a digest", tmp_path / "w2")


def test_an_archive_is_taken_once_and_whole(door, tmp_path):
    d = door()
    body = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x\n")]).read_bytes()
    status, said, _h = d.ask("PUT", "/v1/check", body=body)
    assert status == 202 and said["state"] in ("unpacking", "running", "done")
    done = _until(lambda: (lambda s: s if s[1]["state"] == "done" else None)(d.ask("GET", "/v1/check")))
    assert d.handed == [body] and done[1]["result"]["tests"] == {"returncode": 0}
    assert any(line.endswith("a check that runs nothing") for line in done[1]["lines"])
    steps = [s["step"] for s in done[1]["steps"]]
    assert steps[:2] == ["taking", "taken"] and steps[-1] == "done" and all(s["at"].endswith("Z") for s in done[1]["steps"])
    # a second archive for the same machine is refused: one machine, one check
    assert d.ask("PUT", "/v1/check", body=body)[0] == 409
    # the lines can be asked for from where the asker left off
    said = d.ask("GET", f"/v1/check?from={done[1]['next']}")[1]
    assert said["lines"] == [] and said["next"] == done[1]["next"]


def test_a_body_must_say_its_length_and_fit(door, tmp_path):
    d = door(most=10_000)
    c = http.client.HTTPConnection("127.0.0.1", d.port, timeout=30)
    c.putrequest("PUT", "/v1/check")
    c.putheader("Authorization", "Bearer " + d.key)
    c.endheaders()
    r = c.getresponse()
    assert r.status == 411
    c.close()
    status, said, _h = d.ask("PUT", "/v1/check", body=b"x" * 10_001)
    assert status == 413 and "10,000" in said["error"]
    d2 = door(free=lambda: 5_000)
    status, said, _h = d2.ask("PUT", "/v1/check", body=b"x" * 6_000)
    assert status == 507 and "disk" in said["error"]
    assert not d.handed and not d2.handed
    assert d.ask("GET", "/v1/check")[1]["state"] == "waiting"


def test_a_body_sent_in_chunks_is_taken_and_counted(door, tmp_path):
    d = door(most=100_000)
    body = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x\n")]).read_bytes()
    chunked = b"".join(b"%x\r\n" % len(body[i:i + 100]) + body[i:i + 100] + b"\r\n" for i in range(0, len(body), 100))
    s = socket.create_connection(("127.0.0.1", d.port), timeout=30)
    s.sendall(b"PUT /v1/check HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + d.key.encode()
              + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked + b"0\r\n\r\n")
    answer = s.recv(4096)
    s.close()
    assert answer.startswith(b"HTTP/1.1 202"), answer[:200]
    _until(lambda: d.handed)
    assert d.handed == [body]
    # the twin: a chunk that says more than may come, and a size that is no number
    for bad in (b"%x\r\n" % 200_000 + b"x" * 10, b"zz\r\nxx\r\n0\r\n\r\n", b"1" * 40 + b"\r\n"):
        d2 = door(most=100_000)
        s = socket.create_connection(("127.0.0.1", d2.port), timeout=30)
        s.sendall(b"PUT /v1/check HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + d2.key.encode()
                  + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + bad)
        answer = s.recv(4096)
        s.close()
        assert answer.split(b" ")[1] in (b"400", b"413"), answer[:200]
        assert not d2.handed and d2.ask("GET", "/v1/check")[1]["state"] == "waiting"


def test_a_sender_that_stops_halfway_is_cut_off_and_may_send_again(door, tmp_path):
    d = door(read_timeout=0.5)
    s = socket.create_connection(("127.0.0.1", d.port), timeout=30)
    s.sendall(b"PUT /v1/check HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + d.key.encode()
              + b"\r\nContent-Length: 1000\r\n\r\n" + b"x" * 10)
    s.settimeout(10)
    answer = s.recv(4096)               # the door gives up on it after its time and says so, or just closes
    s.close()
    assert answer == b"" or answer.startswith(b"HTTP/1.1 408")
    assert not d.handed and d.ask("GET", "/v1/check")[1]["state"] == "waiting"
    assert not [p for p in (tmp_path / "work").iterdir() if p.name.startswith("archive")]
    body = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x\n")]).read_bytes()
    assert d.ask("PUT", "/v1/check", body=body)[0] == 202          # the twin: sent whole, it is taken


def test_stop_and_end_are_the_websites_alone(door, tmp_path):
    started, stop_seen = threading.Event(), threading.Event()

    def slow(archive_path, work, log, cancel):
        started.set()
        cancel.wait(30)
        stop_seen.set()
        return {"version": 1, "state": "stopped", "why_not": "the website asked for the tests to be stopped"}
    d = door(check=slow)
    body = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x\n")]).read_bytes()
    assert d.ask("PUT", "/v1/check", body=body)[0] == 202
    assert started.wait(10)
    assert d.ask("POST", "/v1/stop", key="x")[0] == 401 and not stop_seen.is_set()
    assert d.ask("POST", "/v1/stop")[0] == 202
    assert stop_seen.wait(10)
    assert _until(lambda: d.ask("GET", "/v1/check")[1]["state"] == "stopped")
    assert d.ask("POST", "/v1/end")[0] == 202 and d.runner.ended.wait(10)


def test_the_program_leaves_when_nobody_comes(tmp_path):
    r = runner.Runner(_key()[1], tmp_path / "work", wait_for_archive=0.3)
    assert r.ended.wait(10) and r.why_ended == "no archive came"


def test_the_result_waits_for_its_taker_only_so_long(door, tmp_path):
    d = door(wait_for_taker=0.5)
    body = _zip(tmp_path / "c.zip", [("check.json", _raw(_settings())), ("project/test_a.py", "x\n")]).read_bytes()
    assert d.ask("PUT", "/v1/check", body=body)[0] == 202
    assert d.runner.ended.wait(15) and d.runner.why_ended == "nobody took the result"


# ---------------------------------------------------------------------------- the walls the design counts on
def test_no_test_runs_where_a_wall_the_design_counts_on_does_not_stand(tmp_path, monkeypatch):
    project = tmp_path / "p"
    project.mkdir()
    (project / "test_a.py").write_text("import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n"
                                       "        open('ran', 'w').close()\n", encoding="utf-8")
    src = tmp_path / "c.zip"
    runner.pack(project, src, ["python", "-m", "unittest"], minutes=1, memory=512)
    monkeypatch.setattr(sandbox, "own_network", lambda: "this system makes no network of a run's own")
    result = runner.check(src, tmp_path / "w", log=lambda line: None, cancel=threading.Event())
    assert result["state"] == "unable" and "tests' own network" in result["why_not"]
    assert "no test was run" in result["why_not"] and "tests" not in result
    row = next(w for w in result["runner"]["walls"] if w["wall"] == "the tests' own network")
    assert row == {"wall": "the tests' own network", "stands": False, "why": "this system makes no network of a run's own"}


def test_the_walls_are_asked_of_this_system():
    rows = {w["wall"]: w for w in runner.walls()}
    assert set(rows) == {"the tests' own network", "a doorman for every connection", "the memory watch",
                         "a limit on the tests' programs", "an ordinary user for the tests"}
    assert rows["the tests' own network"]["stands"] == (sandbox.own_network() == "")
    assert rows["an ordinary user for the tests"]["stands"] == LINUX_ROOT
    # the limit counts every program of the tests' user, so it holds only where they get a user of their own
    assert rows["a limit on the tests' programs"]["stands"] == LINUX_ROOT
    assert all(isinstance(w["why"], str) and (w["why"] == "") == w["stands"] for w in rows.values())


# ---------------------------------------------------------------------------- the image
def _readiness_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("self_readiness", ROOT / "tools" / "self_readiness.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _image() -> list[str]:
    return _readiness_tool()._stage((ROOT / "cloud" / "runner" / "Dockerfile").read_text(encoding="utf-8"))


def test_every_program_of_the_image_is_fixed_to_the_version_it_was_checked_with():
    text = (ROOT / "cloud" / "runner" / "Dockerfile").read_text(encoding="utf-8")
    froms = [line.split()[1] for line in text.splitlines() if line.strip().upper().startswith("FROM ")]
    assert froms and all("@sha256:" in f for f in froms), froms
    digests = {f.split("@", 1)[1] for f in froms}
    assert digests <= {sandbox.IMAGES["python3.12"].split("@", 1)[1], sandbox.IMAGES["node"].split("@", 1)[1]}
    assert "apt-get install" not in text and "pip install" not in text and "npm install" not in text
    assert "curl " not in text and "wget " not in text and "ADD http" not in text.upper()


def test_the_image_starts_the_runner_first_and_holds_no_key():
    stage = _image()
    tool = _readiness_tool()
    assert tool._runner_first(stage)
    cmd = json.loads(tool._last(stage, "CMD"))
    assert cmd[:4] == ["python", "-I", "-m", "lantern.runner"] and cmd[4] == "serve"
    assert tool._last(stage, "ENTRYPOINT") is None
    words = " ".join(stage).upper()
    assert "KEY" not in words.replace("LANTERN_RUNNER_KEY_SHA256", "") and "SECRET" not in words and "TOKEN" not in words
    assert not any(ins.upper().startswith("USER ") for ins in stage)      # root, for the switch to an ordinary user


# ---------------------------------------------------------------------------- end to end, as on the machine
def _copy_dist(name: str, into: Path) -> dict:
    """One installed library copied the way pip lays it into a folder of its own (`--target`), and its row of the
    fetch's record."""
    dist = importlib.metadata.distribution(name)
    for f in dist.files or ():
        src = Path(dist.locate_file(f))
        if src.is_file() and ".." not in Path(f).parts and Path(f).parts[0] != "bin":
            dest = into / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
    return {"name": dist.metadata["Name"], "version": dist.version, "fingerprint": "sha256:" + "0" * 64,
            "file": f"{name}-{dist.version}-py3-none-any.whl", "asked": False, "exact": False, "checked": False}


def _needed(name: str) -> list[str]:
    """`name` and every library it needs on this Python and this system, as pip would have fetched them."""
    from packaging.requirements import Requirement
    seen: list[str] = []
    todo = [name]
    while todo:
        n = todo.pop()
        if n.lower().replace("_", "-") in (s.lower().replace("_", "-") for s in seen):
            continue
        seen.append(n)
        for line in importlib.metadata.requires(n) or ():
            r = Requirement(line)
            if r.marker is None or r.marker.evaluate({"extra": ""}):
                todo.append(r.name)
    return seen


class _Machine:
    """lantern.runner started the way the image starts it, on this computer, with a key made for this test."""

    def __init__(self, tmp_path: Path, *more: str):
        self.key, digest = _key()
        ready = tmp_path / f"ready-{secrets.token_hex(6)}.json"      # one of its own: a test may start several
        env = {k: v for k, v in os.environ.items() if not k.startswith("LANTERN_RUNNER")}
        env[runner.KEY_VARIABLE] = digest
        code = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from lantern.runner import main; sys.exit(main(sys.argv[1:]))"
        self.proc = subprocess.Popen([sys.executable, "-c", code, "serve", "--host", "127.0.0.1", "--port", "0",
                                      "--ready", str(ready), *more], env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        _until(lambda: ready.exists() and ready.read_text(encoding="utf-8").strip(), 60)
        self.port = json.loads(ready.read_text(encoding="utf-8"))["port"]

    def ask(self, method, path, body=None, key=""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request(method, path, body=body, headers={"Authorization": "Bearer " + (key or self.key)})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, json.loads(data) if data else None

    def result(self, seconds: float = 240.0) -> dict:
        said = _until(lambda: (lambda s: s if s[1]["state"] in ("done", "refused", "unable", "stopped") else None)(
            self.ask("GET", "/v1/check")), seconds)[1]
        return said

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(30)
        if self.proc.stdout:
            self.proc.stdout.close()


@pytest.fixture()
def machine(tmp_path):
    made = []

    def make(*more):
        made.append(_Machine(tmp_path, *more))
        return made[-1]
    yield make
    for m in made:
        m.close()


def _project(tmp_path: Path, tests: str, name: str = "p") -> Path:
    project = tmp_path / name
    project.mkdir()
    (project / "test_it.py").write_text(textwrap.dedent(tests), encoding="utf-8")
    return project


@needs_the_machine
def test_a_projects_tests_run_as_an_ordinary_user_and_the_result_says_how_they_went(machine, tmp_path):
    passing = _project(tmp_path, """
        import os, unittest
        class T(unittest.TestCase):
            def test_an_ordinary_user(self):
                self.assertEqual(os.geteuid(), 65534)
    """)
    failing = _project(tmp_path, """
        import unittest
        class T(unittest.TestCase):
            def test_it_fails(self):
                self.assertEqual(1, 2)
    """, "q")
    for project, code in ((passing, 0), (failing, 1)):
        m = machine()
        runner.pack(project, tmp_path / f"{project.name}.zip", ["python", "-m", "unittest", "-v"], minutes=2, memory=512)
        assert m.ask("PUT", "/v1/check", (tmp_path / f"{project.name}.zip").read_bytes())[0] == 202
        said = m.result()
        assert said["state"] == "done", said
        result = said["result"]
        assert result["tests"]["returncode"] == code and result["tests"]["backend"] == "subprocess"
        assert result["tests"]["off_network"] is True and result["tests"]["own_network"] is True
        assert result["check"]["command"] == ["python", "-m", "unittest", "-v"] and result["taken"]["files"] >= 2
        assert all(w["stands"] for w in result["runner"]["walls"])
        assert result["runner"]["lantern"] and result["runner"]["python"]
        assert m.ask("POST", "/v1/end")[0] == 202
        assert m.proc.wait(30) == 0


@needs_the_machine
def test_the_tests_run_on_the_libraries_the_website_fetched_and_on_no_others(machine, tmp_path):
    tests = """
        import unittest
        class T(unittest.TestCase):
            def test_the_library(self):
                import hello_lib
                self.assertEqual(hello_lib.WORD, "hello")
    """
    project = _project(tmp_path, tests)
    libs = tmp_path / "libs"
    (libs / "hello_lib").mkdir(parents=True)
    (libs / "hello_lib" / "__init__.py").write_text('WORD = "hello"\n', encoding="utf-8")
    record = {"state": "fetched", "language": "python", "store": "pypi.org", "added": [],
              "packages": [{"name": "hello-lib", "version": "1.0", "fingerprint": "sha256:" + "1" * 64,
                            "file": "hello_lib-1.0-py3-none-any.whl", "asked": True, "exact": True, "checked": True}]}
    m = machine()
    runner.pack(project, tmp_path / "with.zip", ["python", "-m", "unittest", "-v"], minutes=2, memory=512,
                libraries=libs, record=record)
    assert m.ask("PUT", "/v1/check", (tmp_path / "with.zip").read_bytes())[0] == 202
    result = m.result()["result"]
    assert result["tests"]["returncode"] == 0, result["tests"].get("output_tail")
    assert result["tests"]["libraries"] == record
    # the twin: the same tests without the library fail, and nothing of this computer's stands in for it
    m2 = machine()
    runner.pack(project, tmp_path / "without.zip", ["python", "-m", "unittest", "-v"], minutes=2, memory=512)
    assert m2.ask("PUT", "/v1/check", (tmp_path / "without.zip").read_bytes())[0] == 202
    result = m2.result()["result"]
    assert result["tests"]["returncode"] != 0 and "hello_lib" in result["tests"]["output_tail"]


@needs_the_machine
def test_pytest_brought_by_the_website_runs_and_records_the_calls(machine, tmp_path):
    project = _project(tmp_path, """
        from app import add
        def test_add():
            assert add(1, 2) == 3
    """)
    (project / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    libs = tmp_path / "libs"
    rows = [_copy_dist(n, libs) for n in _needed("pytest")]
    record = {"state": "fetched", "language": "python", "store": "pypi.org", "added": ["pytest"], "packages": rows}
    m = machine()
    runner.pack(project, tmp_path / "c.zip", ["python", "-m", "pytest", "-q"], minutes=3, memory=1024,
                libraries=libs, record=record, fetched_with=sys.executable)
    assert m.ask("PUT", "/v1/check", (tmp_path / "c.zip").read_bytes())[0] == 202
    result = m.result()["result"]
    tests = result["tests"]
    assert tests["returncode"] == 0, tests.get("output_tail")
    assert "1 passed" in tests["output_tail"]
    # the calls the tests made, with the project's own files named from the project's top
    files = {row[side][0] for row in tests["pairs"] for side in ("caller", "callee")}
    assert "app.py" in files and "test_it.py" in files
    assert not any(f.startswith(str(tmp_path)) for f in files)


@needs_the_machine
def test_the_tests_cannot_reach_the_door_or_read_what_the_program_holds(machine, tmp_path):
    m = machine()
    project = _project(tmp_path, f"""
        import os, socket, unittest, threading, http.server
        PORT = {m.port}
        RUNNER = {m.proc.pid}
        class Door(unittest.TestCase):
            def test_the_door_on_this_computers_own_address(self):
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", PORT), timeout=5)
            def test_every_address_of_the_machine(self):
                try:
                    found = socket.getaddrinfo(socket.gethostname(), PORT, type=socket.SOCK_STREAM)
                except OSError:
                    found = []
                for name in sorted({{a[4][0] for a in found}} | {{"127.0.0.1", "::1"}}):
                    with self.assertRaises(OSError):
                        socket.create_connection((name, PORT), timeout=5)
            def test_the_programs_settings(self):
                with self.assertRaises(OSError):
                    open(f"/proc/{{RUNNER}}/environ", "rb").read()
            def test_the_programs_open_files(self):
                with self.assertRaises(OSError):
                    os.listdir(f"/proc/{{RUNNER}}/fd")
            def test_its_own_settings_it_may_read(self):
                self.assertTrue(open("/proc/self/environ", "rb").read())
            def test_a_server_of_its_own_answers(self):
                class H(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"mine")
                    def log_message(self, *a):
                        pass
                s = http.server.HTTPServer(("127.0.0.1", 0), H)
                threading.Thread(target=s.serve_forever, daemon=True).start()
                c = socket.create_connection(("127.0.0.1", s.server_address[1]), timeout=5)
                c.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
                got = b""
                while True:             # the answer may come in more than one piece; the server closes after it
                    piece = c.recv(4096)
                    if not piece:
                        break
                    got += piece
                self.assertIn(b"mine", got)
                c.close()
                s.shutdown()
    """)
    runner.pack(project, tmp_path / "c.zip", ["python", "-m", "unittest", "-v"], minutes=2, memory=512)
    assert m.ask("PUT", "/v1/check", (tmp_path / "c.zip").read_bytes())[0] == 202
    tests = m.result()["result"]["tests"]
    assert tests["returncode"] == 0, tests.get("output_tail")
    for name in ("test_the_door_on_this_computers_own_address", "test_every_address_of_the_machine",
                 "test_the_programs_settings", "test_the_programs_open_files", "test_its_own_settings_it_may_read",
                 "test_a_server_of_its_own_answers"):
        assert f"{name} (test_it." in tests["output_tail"] and "... ok" in tests["output_tail"], name
    # and the door was there all along, for the website
    assert m.ask("GET", "/v1/check")[0] == 200


@needs_the_machine
def test_the_website_may_stop_the_tests_and_nothing_is_left_running(machine, tmp_path):
    project = _project(tmp_path, """
        import subprocess, sys, time, unittest
        class T(unittest.TestCase):
            def test_never_ends(self):
                subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
                open("started", "w").close()
                time.sleep(600)
    """)
    m = machine()
    runner.pack(project, tmp_path / "c.zip", ["python", "-m", "unittest", "-v"], minutes=10, memory=512)
    assert m.ask("PUT", "/v1/check", (tmp_path / "c.zip").read_bytes())[0] == 202
    _until(lambda: m.ask("GET", "/v1/check")[1]["state"] == "running", 120)
    time.sleep(3)
    assert m.ask("POST", "/v1/stop")[0] == 202
    said = m.result(120)
    assert said["state"] == "stopped" and said["result"]["tests"]["cancelled"] is True
    assert said["result"]["tests"]["not_ended"] == []


@needs_the_machine
def test_a_refused_archive_runs_nothing_and_says_why(machine, tmp_path):
    m = machine()
    bad = _zip(tmp_path / "bad.zip", [("check.json", _raw(_settings())), ("project/../x.py", "1")])
    assert m.ask("PUT", "/v1/check", bad.read_bytes())[0] == 202
    said = m.result()
    assert said["state"] == "refused" and "outside its folder" in said["result"]["why_not"]
    assert "tests" not in said["result"]
