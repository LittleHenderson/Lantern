"""One machine of its own for each check's tests, made and removed whatever happens (a firm pass or fail, stage 3,
step 5, 2026-11-21; `cloud/lantern_cloud/machines.py`).

Nothing here reaches the hosting company. Its machine API is stood in for by `Hosting` below, which answers the way
Lantern's notes of its manual say it does (an app with a network of its own, an outbound rule, an address, a
machine, waiting for it, removing it); each machine's door is stood in for by `Doors`, which answers as the test
machine's program does, or is the program's own door (`lantern.runner.Door`) on this computer. The practice copy
(step 7) checks every one of those answers against the hosting company itself before anything goes live.

Each case stands beside a twin: a check that goes through beside each step that fails, the website's own apps beside
the ones the sweep may remove, a result of the runner's shape beside ones of other shapes."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cloud"))
sys.path.insert(0, str(ROOT / "tools"))
from lantern_cloud import machines  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402

from lantern import runner, sandbox  # noqa: E402

KEY = "FlyV1 fm2_" + "a" * 40           # the shape the hosting company's organization keys have; made up
IMAGE = "registry.example/lantern-runner@sha256:" + "ab" * 32
NOW = datetime(2026, 11, 21, 15, 0, 0, tzinfo=timezone.utc)
API = "https://api.machines.test"


def QUIET(line):
    """A log nobody reads."""


def _route(method: str, path: str) -> tuple[str, dict]:
    for kind, verb, shape in (
            ("apps-create", "POST", r"/v1/apps"),
            ("apps-list", "GET", r"/v1/apps"),
            ("apps-delete", "DELETE", r"/v1/apps/(?P<app>[^/]+)"),
            ("policies-create", "POST", r"/v1/apps/(?P<app>[^/]+)/network_policies"),
            ("ips-create", "POST", r"/v1/apps/(?P<app>[^/]+)/ip_assignments"),
            ("machines-create", "POST", r"/v1/apps/(?P<app>[^/]+)/machines"),
            ("machines-list", "GET", r"/v1/apps/(?P<app>[^/]+)/machines"),
            ("machines-wait", "GET", r"/v1/apps/(?P<app>[^/]+)/machines/(?P<id>[^/]+)/wait"),
            ("machines-delete", "DELETE", r"/v1/apps/(?P<app>[^/]+)/machines/(?P<id>[^/]+)")):
        m = re.fullmatch(shape, path)
        if m and method == verb:
            return kind, m.groupdict()
    return "", {}


class Hosting:
    """The hosting company's machine API as Lantern's notes of its manual describe it, in memory. `fail[kind]`:
    answers given before the request is done (one is used up for each request); `fail_done[kind]`: answers given
    after it was done (a request that went through and was answered as if it had not)."""

    def __init__(self, org: str = "lantern-runs"):
        self.org = org
        self.apps: dict[str, dict] = {}
        self.calls: list[tuple[str, str, object]] = []
        self.auth: set[str] = set()
        self.fail: dict[str, list[int]] = {}
        self.fail_done: dict[str, list[int]] = {}
        self.started_after = 0           # "wait" answers 408 this many times before the machine has started
        self.wait_takes = None           # called with the seconds asked for when "wait" answers 408 (it waits that long)
        self.on_machine = None           # called with (app, machine id, config) when a machine is made
        self.most_at_once = 0
        self.lock = threading.Lock()
        self._ids = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        kind, at = _route(request.method, request.url.path)
        body = json.loads(request.content) if request.content else None
        with self.lock:
            self.calls.append((kind, request.url.path, body if body is not None else dict(request.url.params)))
            self.auth.add(request.headers.get("authorization", ""))
            if self.fail.get(kind):
                return httpx.Response(self.fail[kind].pop(0), json={"error": "planted"},
                                      headers={"retry-after": "2"})
            answer = self._do(kind, at, body, request)
            if self.fail_done.get(kind):
                return httpx.Response(self.fail_done[kind].pop(0), json={"error": "planted after"})
            self.most_at_once = max(self.most_at_once, sum(1 for a in self.apps.values() if a["machines"]))
            return answer

    def _do(self, kind, at, body, request) -> httpx.Response:
        app = self.apps.get(at.get("app", ""))
        if kind == "apps-create":
            if body["app_name"] in self.apps:
                return httpx.Response(422, json={"error": "taken"})
            self.apps[body["app_name"]] = {"org": body["org_slug"], "network": body.get("network"), "policies": [],
                                           "ips": [], "machines": {}}
            return httpx.Response(201, json={"id": "app-" + body["app_name"]})
        if kind == "apps-list":
            names = [n for n, a in self.apps.items() if a["org"] == request.url.params.get("org_slug")]
            return httpx.Response(200, json={"total_apps": len(names), "apps": [{"name": n} for n in names]})
        if app is None:
            return httpx.Response(404, json={"error": "no such app"})
        if kind == "apps-delete":
            del self.apps[at["app"]]
            return httpx.Response(202, json={})
        if kind == "policies-create":
            if app["machines"]:
                return httpx.Response(409, json={"error": "a policy made after the machine reaches it at its next start"})
            app["policies"].append(body)
            return httpx.Response(200, json={"id": "pol-1", **body})
        if kind == "ips-create":
            app["ips"].append(body)
            return httpx.Response(200, json={"ip": "203.0.113.7", "type": body.get("type")})
        if kind == "machines-create":
            self._ids += 1
            mid = f"{self._ids:014x}"
            app["machines"][mid] = {"config": body["config"], "region": body.get("region"), "waits": 0}
            if self.on_machine is not None:
                self.on_machine(at["app"], mid, body["config"])
            return httpx.Response(200, json={"id": mid, "instance_id": "i1", "state": "created"})
        if kind == "machines-list":
            return httpx.Response(200, json=[{"id": mid, "state": "started"} for mid in app["machines"]])
        machine = app["machines"].get(at.get("id", ""))
        if machine is None:
            return httpx.Response(404, json={"error": "no such machine"})
        if kind == "machines-wait":
            machine["waits"] += 1
            if machine["waits"] <= self.started_after:
                if self.wait_takes is not None:
                    self.wait_takes(float(request.url.params.get("timeout", "0")))
                return httpx.Response(408, json={"error": "deadline_exceeded"})
            return httpx.Response(200, json={"ok": True})
        if kind == "machines-delete":
            if request.url.params.get("force") != "true":
                return httpx.Response(412, json={"error": "the machine is running: stop it first or force"})
            del app["machines"][at["id"]]
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "no such route"})

    def kinds(self) -> list[str]:
        return [k for k, _, _ in self.calls]


class Doors:
    """Each machine's door, as the test machine's program answers (`lantern.runner`): only to the key whose
    fingerprint the machine was given; one archive; how the check is going; stop and end. `script(door)` gives the
    result of a check once the archive is in (a dict, or None for a check that never ends)."""

    def __init__(self, hosting: Hosting, script=None):
        self.doors: dict[str, dict] = {}
        self.script = script or (lambda door: _result("done"))
        self.refuse_first = 0             # connections refused while a machine's door is not up yet
        self.lock = threading.Lock()
        hosting.on_machine = self._made

    def _made(self, app, mid, config):
        self.doors[app] = {"digest": config["env"][runner.KEY_VARIABLE], "archive": None, "ended": False,
                           "stopped": False, "asked": 0, "refused": 0, "lines": ["sandbox: the tests run"]}

    def url(self, app: str) -> str:
        return f"https://{app}.doors.test"

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        app = request.url.host.split(".")[0]
        with self.lock:
            door = self.doors.get(app)
            if door is None:
                raise httpx.ConnectError("no such machine", request=request)
            if door["refused"] < self.refuse_first:
                door["refused"] += 1
                raise httpx.ConnectError("not up yet", request=request)
            said = request.headers.get("authorization", "")
            key = said[len("Bearer "):] if said.startswith("Bearer ") else ""
            if hashlib.sha256(key.encode()).hexdigest() != door["digest"]:
                return httpx.Response(401, json={"error": "not allowed"})
            path = request.url.path
            if (request.method, path) == ("PUT", "/v1/check"):
                if door["archive"] is not None:
                    return httpx.Response(409, json={"error": "taken already"})
                door["archive"] = request.read()
                return httpx.Response(202, json={"state": "unpacking"})
            if (request.method, path) == ("GET", "/v1/check"):
                door["asked"] += 1
                start = int(request.url.params.get("from", "0"))
                result = self.script(door) if door["archive"] is not None else None
                if door["stopped"] and result is None:
                    result = _result("stopped")
                lines = door["lines"][start:]
                state = result.get("state") if isinstance(result, dict) else "running"
                return httpx.Response(200, json={"state": state, "steps": [], "lines": lines,
                                                 "next": start + len(lines), "result": result})
            if (request.method, path) == ("POST", "/v1/stop"):
                door["stopped"] = True
                return httpx.Response(202, json={"state": "running"})
            if (request.method, path) == ("POST", "/v1/end"):
                door["ended"] = True
                return httpx.Response(202, json={"state": "ended"})
            return httpx.Response(404, json={"error": "not found"})


def _result(state: str, **more) -> dict:
    r = {"version": 1, "state": state, "why_not": None if state == "done" else f"it ended {state}",
         "runner": {"lantern": "0.11.0", "walls": []}, "taken": {"files": 1, "bytes": 10, "links": 0},
         "check": {"command": ["python", "-m", "pytest"], "cwd": "", "minutes": 1, "memory": 2048,
                   "language": "python", "processes": 4096}}
    if state == "done":
        r["tests"] = {"returncode": 0, "pairs": [], "timed_out": False, "over_memory": False}
    r.update(more)
    return r


class Time:
    """A clock that moves only when somebody waits."""

    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += max(s, 0.0)


def _fast_pacer():
    return machines.Pacer(rate=1e6, burst=10**6)


def _setup(tmp_path, script=None, at_once=2, tag="practice", time_=None, **more):
    host = Hosting()
    doors = Doors(host, script)
    t = time_ or Time()
    hosting = machines.Hosting(KEY, api=API, transport=host.transport(), pacer=_fast_pacer(), sleep=t.sleep)
    m = machines.Machines(hosting, IMAGE, tag=tag, at_once=at_once, door_for=doors.url,
                          door_transport=doors.transport(), clock=t.clock, sleep=t.sleep, now=lambda: NOW, **more)
    tmp_path.mkdir(parents=True, exist_ok=True)
    archive = tmp_path / "check.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    return host, doors, m, archive, t


# ------------------------------------------------------------------------------------------------------ names
def test_an_apps_name_says_whose_it_is_and_when_it_was_made():
    name = machines.name_for("practice", NOW)
    assert re.fullmatch(r"lt-practice-20261121t150000-[0-9a-f]{8}", name), name
    assert machines.name_for("practice", NOW) != name               # eight random letters of its own
    assert machines.parse_name(name) == ("practice", NOW)
    assert machines.parse_name(machines.name_for("live", NOW)) == ("live", NOW)
    # the twins: what is no name of this module's shape is nobody's to remove
    for other in ("lantern-cloud", "lantern-cloud-practice", "lt-practice-x", "lt-practice-20261121t150000",
                  "lt-practice-20261121t150000-1A2B3C4D", "lt-practice-20261121t150000-1a2b3c4d-x",
                  "lt-practice-20261321t150000-1a2b3c4d", "xlt-practice-20261121t150000-1a2b3c4d",
                  "lt--20261121t150000-1a2b3c4d", "lt-Practice-20261121t150000-1a2b3c4d", "", None, 7):
        assert machines.parse_name(other) is None, other


@pytest.mark.parametrize("tag", ["", "Practice", "lt-x", "a" * 13, "7up", "prac tice", None, 3])
def test_a_tag_is_a_short_word(tag):
    with pytest.raises(ValueError):
        machines.name_for(tag, NOW)
    for good in ("practice", "live", "p2"):
        machines.name_for(good, NOW)


# --------------------------------------------------------------------------------------------------- the key
def test_the_key_is_sent_the_way_the_hosting_company_made_it():
    assert machines.authorization(KEY) == KEY
    assert machines.authorization("abc123") == "Bearer abc123"
    for odd in ("", "a\nb", "a\rb", "café", "a\tb", " lead", "x" * 9000, None, 5):
        with pytest.raises(ValueError) as e:
            machines.authorization(odd)
        assert odd is None or not isinstance(odd, str) or not odd or odd not in str(e.value)


def test_the_key_goes_to_the_machine_api_alone_and_the_machine_gets_a_fingerprint(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "done", r
    assert host.auth == {KEY}                                   # every request to the machine API carries it
    made = next(body for kind, _, body in host.calls if kind == "machines-create")
    env = made["config"]["env"]
    assert list(env) == [runner.KEY_VARIABLE] and re.fullmatch(r"[0-9a-f]{64}", env[runner.KEY_VARIABLE])
    assert KEY not in json.dumps(host.calls)                    # nor in anything the machine is given
    door = next(iter(doors.doors.values()))
    assert door["digest"] == env[runner.KEY_VARIABLE] and door["archive"] == archive.read_bytes()


def test_the_key_is_named_in_no_setting_shown_and_no_error(tmp_path):
    s = Settings(test_machines_key=KEY, test_machines_image=IMAGE)
    assert KEY not in repr(s) and KEY not in json.dumps(s.limits())
    host = Hosting()
    host.fail["apps-create"] = [500]
    hosting = machines.Hosting(KEY, api=API, transport=host.transport(), pacer=_fast_pacer())
    with pytest.raises(machines.HostingError) as e:
        hosting.make_app(machines.name_for("practice", NOW))
    assert KEY not in str(e.value) and "500" in str(e.value) and "planted" not in str(e.value)


# -------------------------------------------------------------------------------------- what is made, in order
def test_a_check_makes_its_own_app_rule_address_and_machine_in_that_order_and_removes_them(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    lines: list[str] = []
    r = m.run(archive, minutes=3, memory=2048, log=lines.append)
    assert r["state"] == "done" and r["tests"]["returncode"] == 0, r
    assert host.kinds() == ["apps-create", "policies-create", "ips-create", "machines-create", "machines-wait",
                            "machines-delete", "apps-delete"], host.kinds()
    name = host.calls[0][2]["app_name"]
    assert machines.parse_name(name) == ("practice", NOW)
    assert host.calls[0][2] == {"app_name": name, "org_slug": "lantern-runs", "network": name}
    rule = host.calls[1][2]
    assert rule["selector"] == {"all": True}
    assert rule["rules"] == [{"action": "allow", "direction": "egress", "ports": [{"protocol": "tcp", "port": 0}]}]
    assert host.calls[2][2] == {"type": "shared_v4"}
    made = host.calls[3][2]
    assert made["region"] == "sjc"
    c = made["config"]
    assert c["image"] == IMAGE and c["auto_destroy"] is True and c["restart"] == {"policy": "no"}
    assert c["guest"] == {"cpu_kind": "performance", "cpus": 2, "memory_mb": 4096}
    assert c["services"] == [{"protocol": "tcp", "internal_port": 8080, "autostart": False, "autostop": "off",
                              "ports": [{"port": 443, "handlers": ["tls", "http"]}]}]
    assert host.calls[5][1].endswith("/machines/" + "1".zfill(14)) and host.calls[5][2] == {"force": "true"}
    assert host.apps == {}                                       # nothing of the check is left
    door = doors.doors[name]
    assert door["ended"] is True and door["stopped"] is False
    assert r["machine"] == {"image": IMAGE, "region": "sjc", "cpus": 2, "memory_mb": 4096}
    assert any(x.startswith("machine ") and "removed" in x for x in lines), lines
    assert m.health()["apps_going"] == 0


def test_the_machines_memory_holds_the_tests_and_room_for_the_program():
    assert machines.memory_for(2048) == 4096                 # the smallest machine with two processors
    assert machines.memory_for(128) == 4096
    assert machines.memory_for(4000) == 5120                 # 4,000 MB and 1,024 of room, in steps of 256
    assert machines.memory_for(7168) == 8192
    with pytest.raises(ValueError):
        machines.memory_for(7169)                            # over the most a machine is given
    assert machines.memory_for(7169, most=16384) == 8448
    for odd in (0, -1, True, 2.5, "2048", None):
        with pytest.raises(ValueError):
            machines.memory_for(odd)


# ---------------------------------------------------------------------------------- removed whatever happens
FAILURES = {
    "the app": ("apps-create", "fail", [500]),
    "the app, answered as failed after it was made": ("apps-create", "fail_done", [500]),
    "the outbound rule": ("policies-create", "fail", [500]),
    "the address": ("ips-create", "fail", [503]),
    "the machine": ("machines-create", "fail", [500]),
    "the machine, answered as failed after it was made": ("machines-create", "fail_done", [500]),
    "the machine's start": ("machines-wait", "fail", [500]),
}


@pytest.mark.parametrize("step", list(FAILURES))
def test_whatever_step_fails_nothing_of_the_check_is_left(tmp_path, step):
    kind, how, answers = FAILURES[step]
    host, doors, m, archive, _ = _setup(tmp_path)
    getattr(host, how)[kind] = list(answers)
    lines: list[str] = []
    r = m.run(archive, minutes=1, memory=2048, log=lines.append)
    assert r["state"] == "unable" and "test machine" in r["why_not"] and "were not run" in r["why_not"], r
    assert str(answers[0]) in r["why_not"] and "planted" not in r["why_not"], r
    assert host.apps == {}, (step, host.apps)                    # the app and its machine are gone
    assert "apps-delete" in host.kinds() and not m.left
    assert all(not d["archive"] for d in doors.doors.values())   # no archive was handed to a machine half made


def test_a_machine_that_does_not_start_in_time_is_removed(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path, make_wait=180.0)
    host.started_after = 10**6                                   # never
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "did not start" in r["why_not"], r
    assert host.apps == {} and t.t - 1000.0 >= 180.0
    twin_host, _, twin, twin_archive, _ = _setup(tmp_path / "twin", make_wait=180.0)
    twin_host.started_after = 2                                  # starts after two answers of "not yet"
    assert twin.run(twin_archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    # each "not yet" takes the seconds asked for, as the hosting company's own wait does: the machine gets the whole
    # of its time, the last part of a second too (three waits of 60 seconds leave half a second, asked for as one)
    last_host, _, last, last_archive, last_t = _setup(tmp_path / "last", make_wait=180.5)
    last_host.wait_takes = lambda seconds: setattr(last_t, "t", last_t.t + seconds)
    last_host.started_after = 3
    assert last.run(last_archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    timeouts = [body["timeout"] for kind, _, body in last_host.calls if kind == "machines-wait"]
    assert timeouts == ["60", "60", "60", "1"], timeouts


def test_a_door_that_is_not_up_yet_is_asked_again_for_a_while(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path, ready=60.0)
    doors.refuse_first = 3
    assert m.run(archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    host2, doors2, m2, archive2, t2 = _setup(tmp_path / "never", ready=60.0)
    doors2.refuse_first = 10**6
    r = m2.run(archive2, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "could not be reached" in r["why_not"], r
    assert host2.apps == {} and t2.t - 1000.0 >= 60.0
    # the hosting company's proxy answers for a door that is not up yet: those answers are waited out too
    host3, doors3, m3, archive3, _ = _setup(tmp_path / "proxy", ready=60.0)
    m3.door_transport = _door_says(doors3, "/v1/check", "GET", [502, 503, 504])
    assert m3.run(archive3, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    # an answer the program never gives ends it at once, and no archive is handed over
    for i, odd in enumerate([[], "up", 404, 500]):
        host4, doors4, m4, archive4, t4 = _setup(tmp_path / f"odd{i}", ready=60.0)
        m4.door_transport = _door_says(doors4, "/v1/check", "GET", [odd])
        r4 = m4.run(archive4, minutes=1, memory=2048, log=QUIET)
        assert r4["state"] == "unable" and "did not answer as the test machine's program does" in r4["why_not"], r4
        assert all(d["archive"] is None for d in doors4.doors.values()) and host4.apps == {}
        assert t4.t - 1000.0 < 60.0


def test_a_door_that_does_not_know_the_key_runs_nothing(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    real = doors._made
    doors._made = lambda app, mid, config: (real(app, mid, config), doors.doors[app].update(digest="0" * 64))
    host.on_machine = doors._made
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "did not let the website in" in r["why_not"], r
    assert host.apps == {} and all(d["archive"] is None for d in doors.doors.values())


def test_tests_that_do_not_end_in_their_time_are_stopped_and_the_machine_removed(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path, script=lambda door: None)       # never a result
    real, stops = doors.__call__, []

    def timed(request):
        if request.url.path == "/v1/stop":
            stops.append(t.t - 1000.0)
        return real(request)
    m.door_transport = httpx.MockTransport(timed)
    r = m.run(archive, minutes=2, memory=2048, log=QUIET)
    door = next(iter(doors.doors.values()))
    assert door["stopped"] is True and r["state"] == "stopped", r                 # stopped at its time
    # at its time and not later: the tests' minutes and the room after them, within one look at the machine
    assert len(stops) == 1 and 2 * 60 + machines.END_ROOM <= stops[0] < 2 * 60 + machines.END_ROOM + machines.POLL
    assert host.apps == {}


def test_a_check_with_no_result_even_after_its_stop_is_unable(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path, script=lambda door: None)
    real = doors.__call__

    def deaf(request):                     # the stop is heard and nothing ever comes back
        if request.url.path == "/v1/stop":
            return httpx.Response(202, json={})
        out = real(request)
        if request.url.path == "/v1/check" and request.method == "GET":
            body = json.loads(out.content)
            body["result"] = None
            return httpx.Response(200, json=body)
        return out
    m.door_transport = httpx.MockTransport(deaf)
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "did not end" in r["why_not"], r
    assert host.apps == {}
    # the stop is waited for its seconds and not longer, then the machine is removed
    waited = 60 + machines.END_ROOM + machines.STOP_WAIT
    assert waited <= t.t - 1000.0 < waited + machines.POLL, t.t


def test_a_check_stopped_by_the_person_stops_its_tests_and_removes_the_machine(tmp_path):
    cancel = threading.Event()

    def script(door):
        cancel.set()                           # the person presses Stop while the tests run
        return None
    host, doors, m, archive, _ = _setup(tmp_path, script=script)
    r = m.run(archive, minutes=10, memory=2048, log=QUIET, cancel=cancel)
    assert r["state"] == "stopped" and next(iter(doors.doors.values()))["stopped"] is True, r
    assert host.apps == {}
    # stopped before a machine was made: nothing is made at all
    host2, _, m2, archive2, _ = _setup(tmp_path / "early")
    early = threading.Event()
    early.set()
    assert m2.run(archive2, minutes=1, memory=2048, log=QUIET, cancel=early)["state"] == "stopped"
    assert host2.calls == []


@pytest.mark.parametrize("odd", [
    "not a table", {"version": 2, "state": "done"}, {"version": 1, "state": "passed"},
    {"version": 1, "state": "done", "why_not": ["x"]}, {"version": 1, "state": "done", "why_not": None},
    {"version": 1, "state": "done", "why_not": None, "tests": "all good"},
    {"version": 1, "state": "unable", "why_not": "x" * 5000},
    {"version": 1, "state": "done", "why_not": None, "tests": {}, "runner": "me"}])
def test_the_result_is_taken_by_its_shape(tmp_path, odd):
    host, doors, m, archive, _ = _setup(tmp_path, script=lambda door: odd)
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "not of the shape" in r["why_not"], r
    assert host.apps == {}
    # the twin: the runner's own shape goes through as it came, with what the website says of the machine
    assert machines.taken(_result("done")) == _result("done")
    assert machines.taken(_result("unable")) == _result("unable")
    longest_why = dict(_result("unable"), why_not="x" * machines.MOST_WHY)     # the longest reason taken
    assert machines.taken(longest_why) == longest_why
    assert machines.taken(dict(_result("unable"), why_not="x" * (machines.MOST_WHY + 1))) is None


def _door_says(doors: Doors, path: str, method: str, answers: list):
    """The door's answers to one request, in turn, before it answers as the program does: a status, a body, or an
    error to raise; when they are used up, the program's own answer."""
    real = doors.__call__

    def door(request):
        if (request.method, request.url.path) == (method, path) and answers:
            said = answers.pop(0)
            if isinstance(said, Exception):
                raise said
            if isinstance(said, int):
                return httpx.Response(said, json={"error": "planted"})
            return httpx.Response(200, json=said)
        return real(request)
    return httpx.MockTransport(door)


@pytest.mark.parametrize("answer, said", [(500, "it answered 500"), (409, "it answered 409"),
                                          (httpx.ReadError("cut"), "the connection broke")])
def test_an_archive_the_machine_does_not_take_runs_no_tests(tmp_path, answer, said):
    host, doors, m, archive, _ = _setup(tmp_path)
    m.door_transport = _door_says(doors, "/v1/check", "PUT", [answer])
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and f"did not take the check's archive ({said})" in r["why_not"], r
    door = next(iter(doors.doors.values()))
    assert door["ended"] is True and host.apps == {}           # told it is over, and removed
    # the twin: an archive it takes runs the tests
    host2, doors2, m2, archive2, _ = _setup(tmp_path / "twin")
    assert m2.run(archive2, minutes=1, memory=2048, log=QUIET)["state"] == "done"


def test_a_machine_that_stops_answering_for_a_moment_is_waited_for_and_one_that_stays_away_is_not(tmp_path):
    get = ("/v1/check", "GET")
    # the door is up, the archive is in, then two answers fail before the result comes
    host, doors, m, archive, t = _setup(tmp_path)
    m.door_transport = _door_says(doors, *get, [{"state": "running", "steps": [], "lines": [], "next": 0,
                                                 "result": None}, 503, httpx.ConnectError("down")])
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "done" and host.apps == {}, r
    # it stays away: the check ends with no result once it has failed for longer than a door may take to come up
    host2, doors2, m2, archive2, t2 = _setup(tmp_path / "away")
    m2.door_transport = _door_says(doors2, *get, [{"state": "running", "steps": [], "lines": [], "next": 0,
                                                   "result": None}] + [503] * 1000)
    r2 = m2.run(archive2, minutes=10, memory=2048, log=QUIET)
    assert r2["state"] == "unable" and "stopped answering" in r2["why_not"] and host2.apps == {}, r2
    assert machines.READY < t2.t - 1000.0 < machines.READY + 2 * machines.POLL


@pytest.mark.parametrize("odd", [[], "running", 7.5, None])
def test_an_answer_that_is_not_the_programs_ends_the_check_at_once(tmp_path, odd):
    host, doors, m, archive, t = _setup(tmp_path)
    m.door_transport = _door_says(doors, "/v1/check", "GET", [{"state": "running", "steps": [], "lines": [],
                                                               "next": 0, "result": None}, odd])
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "answer is not of the shape" in r["why_not"], r
    assert t.t - 1000.0 < machines.READY and host.apps == {}    # at once, not after waiting for it to come back


def test_an_answer_longer_than_the_website_reads_ends_the_check(tmp_path, monkeypatch):
    monkeypatch.setattr(machines, "MOST_DOOR_ANSWER", 4096)
    host, doors, m, archive, t = _setup(tmp_path)
    long_answer = {"state": "running", "steps": [], "lines": ["x" * 5000], "next": 1, "result": None}
    m.door_transport = _door_says(doors, "/v1/check", "GET", [{"state": "running", "steps": [], "lines": [],
                                                               "next": 0, "result": None}, long_answer])
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "answer is not of the shape" in r["why_not"] and host.apps == {}, r
    # the twin: an answer within the size is read
    host2, doors2, m2, archive2, _ = _setup(tmp_path / "twin")
    short = {"state": "running", "steps": [], "lines": ["x" * 100], "next": 1, "result": None}
    m2.door_transport = _door_says(doors2, "/v1/check", "GET", [{"state": "running", "steps": [], "lines": [],
                                                                 "next": 0, "result": None}, short])
    assert m2.run(archive2, minutes=1, memory=2048, log=QUIET)["state"] == "done"


def test_a_door_that_stops_knowing_the_key_ends_the_check_at_once(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path)
    m.door_transport = _door_says(doors, "/v1/check", "GET", [{"state": "running", "steps": [], "lines": [],
                                                               "next": 0, "result": None}, 401])
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "did not let the website in, so the check has no result" in r["why_not"], r
    assert t.t - 1000.0 < machines.READY and host.apps == {}


def test_an_answer_is_read_up_to_its_size_and_not_a_byte_more(tmp_path, monkeypatch):
    assert machines._read(httpx.Response(200, content=b"x" * 10), 10) == b"x" * 10
    with pytest.raises(machines._TooLong):
        machines._read(httpx.Response(200, content=b"x" * 11), 10)
    # an answer of the hosting company longer than that ends the check, which leaves nothing behind
    monkeypatch.setattr(machines, "MOST_API_ANSWER", 16)
    host, doors, m, archive, _ = _setup(tmp_path)
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "an answer longer than Lantern reads" in r["why_not"], r
    assert host.apps == {}


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308])
def test_the_website_follows_no_redirect_of_the_hosting_company_or_of_a_door(tmp_path, status):
    elsewhere = {"location": "https://elsewhere.test/v1/apps"}
    host, doors, m, archive, _ = _setup(tmp_path)
    hosts, real = [], host.__call__

    def moved(request):
        hosts.append(request.url.host)
        if (request.method, request.url.path) == ("POST", "/v1/apps"):
            return httpx.Response(status, headers=elsewhere, json={})
        return real(request)
    m.hosting.transport = httpx.MockTransport(moved)
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and f"answered {status} when" in r["why_not"], r
    assert set(hosts) == {"api.machines.test"} and host.apps == {}
    # a door that answers with a redirect: the archive goes nowhere else
    host2, doors2, m2, archive2, _ = _setup(tmp_path / "door")
    door_hosts, real_door = [], doors2.__call__

    def moved_door(request):
        door_hosts.append(request.url.host)
        if request.method == "PUT":
            return httpx.Response(status, headers={"location": "https://elsewhere.test/v1/check"}, json={})
        return real_door(request)
    m2.door_transport = httpx.MockTransport(moved_door)
    r2 = m2.run(archive2, minutes=1, memory=2048, log=QUIET)
    assert r2["state"] == "unable" and f"(it answered {status})" in r2["why_not"], r2
    assert "elsewhere.test" not in door_hosts and host2.apps == {}


def test_every_request_takes_nothing_from_the_surroundings(tmp_path, monkeypatch):
    """No proxy, no password file, no certificate list from the website's surroundings, and no redirect followed,
    for the hosting company and for every door (with a transport handed in, httpx takes no proxy anyway, so the
    clients' own settings are what is checked here)."""
    made, real_client = [], httpx.Client

    def client(*args, **kwargs):
        made.append(kwargs)
        return real_client(*args, **kwargs)
    monkeypatch.setattr(machines.httpx, "Client", client)
    host, doors, m, archive, _ = _setup(tmp_path)
    assert m.run(archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    assert len(made) > 5 and all(kw.get("trust_env") is False and kw.get("follow_redirects") is False
                                 for kw in made), made


def test_lines_the_machine_did_not_keep_are_counted_in_the_log(tmp_path):
    def run_with(missed):
        host, doors, m, archive, _ = _setup(tmp_path / f"m{missed}")
        m.door_transport = _door_says(doors, "/v1/check", "GET", [
            {"state": "running", "steps": [], "lines": [], "next": 0, "result": None},
            {"state": "running", "steps": [], "lines": ["sandbox: later"], "next": 9, "result": None,
             "missed": missed}])
        lines: list[str] = []
        assert m.run(archive, minutes=1, memory=2048, log=lines.append)["state"] == "done"
        return [x for x in lines if "were not kept" in x]
    assert run_with(5) == ["machine 5 lines of the test machine's log were not kept"]
    assert run_with(0) == []                                     # nothing missed: nothing said


def test_an_archive_larger_than_the_machine_takes_makes_no_machine(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path, archive_mb=1)
    archive.write_bytes(b"\0" * ((1 << 20) + 1))
    r = m.run(archive, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "refused" and "more than" in r["why_not"] and host.calls == [], r
    archive.write_bytes(b"\0" * (1 << 20))
    assert m.run(archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"


# --------------------------------------------------------------------------------------------------- the sweep
def _plant(host: Hosting, name: str, machines_too: bool = True) -> None:
    host.apps[name] = {"org": "lantern-runs", "network": name, "policies": [], "ips": [],
                       "machines": {"0000000000beef": {"config": {}, "waits": 0}} if machines_too else {}}


def test_a_removal_that_does_not_go_through_is_left_to_the_sweep(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    host.fail["apps-delete"] = [500] * 3                        # the removal's tries all fail
    lines: list[str] = []
    r = m.run(archive, minutes=1, memory=2048, log=lines.append)
    assert r["state"] == "done", r                              # the check's result is the check's
    (name,) = host.apps
    assert m.left == {name} and any("sweep" in x for x in lines), lines
    assert m.health()["left"] == 1
    m.sweep()                                                   # the hosting company answers again
    assert host.apps == {} and m.left == set() and m.health()["left"] == 0
    # the twin: a removal that fails twice and goes through at its third try is done in the run itself
    host2, _, m2, archive2, _ = _setup(tmp_path / "third")
    host2.fail["apps-delete"] = [500, 500]
    assert m2.run(archive2, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    assert host2.apps == {} and m2.left == set()
    assert host2.kinds().count("apps-delete") == machines.REMOVE_TRIES == 3
    # a request that is not a removal is not tried again: the check is unable, and still nothing is left
    host3, _, m3, archive3, _ = _setup(tmp_path / "once")
    host3.fail["machines-create"] = [500]
    assert m3.run(archive3, minutes=1, memory=2048, log=QUIET)["state"] == "unable"
    assert host3.kinds().count("machines-create") == 1 and host3.apps == {}


def test_the_sweep_removes_only_this_websites_own_apps(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    old = NOW - timedelta(hours=6)
    mine_old, mine_young = machines.name_for("practice", old), machines.name_for("practice", NOW - timedelta(minutes=3))
    other_old = machines.name_for("live", old)
    for n in (mine_old, mine_young, other_old, "lantern-cloud", "lantern-cloud-practice", "lt-practice-somebody"):
        _plant(host, n)
    host.apps["lt-practice-somebody"]["org"] = "lantern-runs"
    m.sweep()                                                   # a later sweep: only what is older than any check
    assert set(host.apps) == {mine_young, other_old, "lantern-cloud", "lantern-cloud-practice",
                              "lt-practice-somebody"}, set(host.apps)
    m.sweep(everything=True)                                    # at start nothing of this website is going yet
    assert set(host.apps) == {other_old, "lantern-cloud", "lantern-cloud-practice", "lt-practice-somebody"}
    removed = [path for kind, path, _ in host.calls if kind in ("apps-delete", "machines-delete")]
    assert all(mine_old in p or mine_young in p for p in removed), removed
    assert [k for k, _, _ in host.calls if k == "apps-list"] and \
        all(body == {"org_slug": "lantern-runs"} for k, _, body in host.calls if k == "apps-list")


def test_the_sweep_leaves_the_app_of_a_check_that_is_going(tmp_path):
    seen = {}

    def script(door):
        if "swept" not in seen:
            seen["swept"] = True
            m.sweep(everything=True)                            # a sweep while this check's tests run
            seen["apps"] = set(host.apps)
        return _result("done")
    host, doors, m, archive, _ = _setup(tmp_path, script=script)
    assert m.run(archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    assert len(seen["apps"]) == 1 and host.apps == {}


def test_how_long_an_app_may_live_covers_the_longest_check():
    allowed = machines.longest(archive_mb=2048)
    assert allowed >= 240 * 60 + 2048 + machines.END_ROOM and allowed < 6 * 3600
    # every part of it, written out: the machine's start, its door, the archive at the slowest rate the machine's
    # program takes (1 MB a second, two minutes at least), the longest tests the sandbox runs, their room, their
    # stop and the removal
    parts = machines.MAKE_WAIT + machines.READY + machines.END_ROOM + machines.STOP_WAIT + machines.REMOVE_ROOM
    assert sandbox.MINUTES[1] == 240 and runner.MIN_RATE == 1 << 20 and runner.MIN_SECONDS == 120
    assert allowed == parts + 2048 + 240 * 60
    assert machines.longest(archive_mb=1) == parts + 120 + 240 * 60


# --------------------------------------------------------------------------------------------- limits and order
def _made_in_order(host: Hosting, doors: Doors) -> list:
    made = [body["app_name"] for kind, _, body in host.calls if kind == "apps-create"]
    return [doors.doors.get(name, {}).get("archive") for name in made]


def test_at_most_so_many_machines_at_once_first_come_first_served(tmp_path):
    released: set[bytes] = set()                 # the checks whose tests end, by their archive
    host = Hosting()
    doors = Doors(host, script=lambda door: _result("done") if door["archive"] in released else None)
    hosting = machines.Hosting(KEY, api=API, transport=host.transport(), pacer=_fast_pacer())
    m = machines.Machines(hosting, IMAGE, tag="practice", at_once=2, door_for=doors.url,
                          door_transport=doors.transport(), poll=0.01)
    order, results = [], {}

    def one(i):
        archive = tmp_path / f"{i}.zip"
        archive.write_bytes(b"PK" + bytes([i]))
        results[i] = m.run(archive, minutes=1, memory=2048, log=lambda line, i=i: order.append((i, line)))
    threads = []
    for i in range(4):
        threads.append(threading.Thread(target=one, args=(i,)))
        threads[-1].start()
        time.sleep(0.15)                                        # asked in this order
    time.sleep(0.5)
    assert host.most_at_once == 2 and len(host.apps) == 2, host.apps
    waiting = {i for i, line in order if "waiting for a test machine" in line}
    assert waiting == {2, 3}, order
    released.add(b"PK\x00")                      # one turn comes free: the first of the two that wait takes it
    until = time.monotonic() + 20
    while len(_made_in_order(host, doors)) < 3 or _made_in_order(host, doors)[2] is None:
        assert time.monotonic() < until, _made_in_order(host, doors)
        time.sleep(0.02)
    time.sleep(0.3)
    assert _made_in_order(host, doors) == [b"PK\x00", b"PK\x01", b"PK\x02"]   # and the other still waits
    released.update({b"PK\x01", b"PK\x02", b"PK\x03"})
    for th in threads:
        th.join(30)
    assert all(results[i]["state"] == "done" for i in range(4)) and host.apps == {}
    assert _made_in_order(host, doors) == [b"PK\x00", b"PK\x01", b"PK\x02", b"PK\x03"]
    assert host.most_at_once == 2


def test_the_hosting_company_is_asked_no_faster_than_it_allows():
    t = Time()
    pacer = machines.Pacer(rate=1.0, burst=3, clock=t.clock, sleep=t.sleep)
    for _ in range(5):
        pacer.wait("machines-create")
    assert t.t - 1000.0 == pytest.approx(2.0) and len(t.slept) == 2      # three at once, then one a second
    before = t.t
    pacer.wait("apps-create")                                   # another kind of request has turns of its own
    assert t.t == before
    # the machine API's requests go through the pace they were given
    t2, host = Time(), Hosting()
    paced = machines.Hosting(KEY, api=API, transport=host.transport(),
                             pacer=machines.Pacer(rate=1.0, burst=3, clock=t2.clock, sleep=t2.sleep), sleep=t2.sleep)
    for i in range(5):
        paced.make_app(f"lt-practice-20261121t150000-0000000{i}")
    assert len(host.apps) == 5 and len(t2.slept) == 2 and t2.t - 1000.0 == pytest.approx(2.0)
    # and with none given, the hosting company's own pace: three at once, then one a second
    plain = machines.Hosting(KEY, api=API, transport=host.transport())
    assert isinstance(plain.pacer, machines.Pacer) and (plain.pacer.rate, plain.pacer.burst) == (1.0, 3.0)


def test_too_many_requests_is_waited_out_and_then_given_up(tmp_path):
    host, doors, m, archive, t = _setup(tmp_path)
    host.fail["machines-create"] = [429]
    assert m.run(archive, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    assert 2.0 in t.slept                                       # as long as the answer said
    host2, _, m2, archive2, _ = _setup(tmp_path / "always")
    host2.fail["machines-create"] = [429] * 100
    r = m2.run(archive2, minutes=1, memory=2048, log=QUIET)
    assert r["state"] == "unable" and "429" in r["why_not"] and host2.apps == {}, r
    # exactly so many times: the eighth is waited out, the ninth is not
    host3, _, m3, archive3, t3 = _setup(tmp_path / "eight")
    host3.fail["machines-create"] = [429] * machines.MOST_429
    assert machines.MOST_429 == 8
    assert m3.run(archive3, minutes=1, memory=2048, log=QUIET)["state"] == "done"
    assert t3.slept.count(2.0) >= 8 and host3.kinds().count("machines-create") == 9
    host4, _, m4, archive4, _ = _setup(tmp_path / "nine")
    host4.fail["machines-create"] = [429] * (machines.MOST_429 + 1)
    assert m4.run(archive4, minutes=1, memory=2048, log=QUIET)["state"] == "unable"
    assert host4.kinds().count("machines-create") == 9 and host4.apps == {}


# -------------------------------------------------------------------------------- one real door on this computer
@pytest.mark.skipif(sys.platform == "win32", reason="the test machine's program is started on Linux machines")
def test_the_test_machines_own_door_on_this_computer(tmp_path):
    """The hosting company stood in for, the machine's door not: the program's own `Runner` and `Door`, made with
    the fingerprint the website handed the machine, on 127.0.0.1. Its check is stood in for (the tests themselves
    are `tests/test_runner.py`'s)."""
    host, made = Hosting(), {}

    def check(archive_path, work, log, cancel):
        log("the stand-in check ran")
        return {"version": 1, "state": "done", "why_not": None, "runner": {"walls": []},
                "taken": {"files": 1, "bytes": archive_path.stat().st_size, "links": 0}, "check": {},
                "tests": {"returncode": 0, "pairs": []}}

    def start(app, mid, config):
        r = runner.Runner(config["env"][runner.KEY_VARIABLE], tmp_path / f"work-{app}", check=check)
        door = runner.Door(("127.0.0.1", 0), r)
        threading.Thread(target=door.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        made[app] = (r, door)
    host.on_machine = start
    hosting = machines.Hosting(KEY, api=API, transport=host.transport(), pacer=_fast_pacer())
    m = machines.Machines(hosting, IMAGE, tag="practice", door_for=lambda app: f"http://127.0.0.1:"
                          f"{made[app][1].server_address[1]}", poll=0.05)
    project = tmp_path / "p"
    project.mkdir()
    (project / "test_it.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    runner.pack(project, tmp_path / "c.zip", ["python", "-m", "pytest", "-q"], minutes=1, memory=512)
    lines: list[str] = []
    try:
        r = m.run(tmp_path / "c.zip", minutes=1, memory=512, log=lines.append)
        (app,) = made
        program, door = made[app]
        assert r["state"] == "done" and r["taken"]["bytes"] == (tmp_path / "c.zip").stat().st_size, r
        assert program.ended.wait(5) and program.why_ended == runner.WEBSITE_ENDED
        assert any("the stand-in check ran" in x for x in lines), lines
        assert host.apps == {}
    finally:
        for _program, door in made.values():
            door.shutdown()
            door.server_close()


# ------------------------------------------------------------------------------- settings, health, the uptime check
def test_the_test_machines_are_off_until_their_key_and_image_are_set():
    assert Settings().test_machines() == (None, "")
    m, why = Settings(test_machines_key=KEY, test_machines_image=IMAGE, test_machines_tag="practice").test_machines()
    assert why == "" and isinstance(m, machines.Machines) and m.tag == "practice" and m.at_once == 2
    # two at once unless told otherwise, whoever makes them; one at a time and the most allowed are fine
    assert machines.Machines(m.hosting, IMAGE).at_once == Settings().test_machines_at_once == 2
    for fine in (1, machines.MOST_AT_ONCE):
        assert machines.Machines(m.hosting, IMAGE, at_once=fine).at_once == fine
    for wrong in (0, machines.MOST_AT_ONCE + 1, True, 2.0, "2"):
        with pytest.raises(ValueError):
            machines.Machines(m.hosting, IMAGE, at_once=wrong)
    for wrong in ({"test_machines_image": ""}, {"test_machines_image": "registry.example/lantern-runner:latest"},
                  {"test_machines_tag": "Practice"}, {"test_machines_at_once": 0},
                  {"test_machines_api": "http://api.machines.dev"}, {"test_machines_egress": "tcp:none"},
                  {"test_machines_key": "a\nb"}, {"test_machines_org": "Lantern Runs"},
                  {"test_machines_memory_mb": 1024}):
        settings = {"test_machines_key": KEY, "test_machines_image": IMAGE, **wrong}
        m, why = Settings(**settings).test_machines()
        assert m is None and why and KEY not in why, (wrong, why)


def test_the_owner_sees_what_is_left_and_the_health_page_says_one_word_of_it(tmp_path):
    host, doors, m, archive, _ = _setup(tmp_path)
    assert m.word() == "not yet" and m.health()["apps"] is None   # no sweep has ended yet
    young = machines.name_for("practice", NOW - timedelta(minutes=3))
    _plant(host, young)
    m.sweep()
    h = m.health()
    assert h["on"] is True and h["apps"] == 1 and h["oldest_minutes"] == 3 and h["swept_at"]
    assert h["allowed_minutes"] == int(machines.longest(archive_mb=m.archive_mb) // 60)
    assert m.word() == "ok"
    # an app exactly as old as one may be, in whole minutes, is kept by the sweep and is no reason to say "behind"
    edge = machines.name_for("practice", NOW - timedelta(minutes=h["allowed_minutes"]))
    _plant(host, edge)
    m.sweep()
    assert edge in host.apps and m.health()["oldest_minutes"] == h["allowed_minutes"] and m.word() == "ok"
    del host.apps[edge]
    m.sweep()
    # an app older than any check can be, whose removal does not go through: the word says so
    old = machines.name_for("practice", NOW - timedelta(minutes=h["allowed_minutes"] + 5))
    _plant(host, old)
    host.fail["apps-delete"] = [500] * 3
    m.sweep()
    assert old in host.apps and m.left == {old} and m.health()["oldest_minutes"] > h["allowed_minutes"]
    assert m.word() == "behind"
    m.sweep()                                                   # the hosting company answers again
    assert old not in host.apps and m.word() == "ok"
    host.fail["apps-list"] = [500]                              # and a sweep that cannot ask it
    m.sweep()
    assert m.word() == "failed" and m.health()["sweep"] == "failed"
    m.sweep()
    assert m.word() == "ok"


def test_the_uptime_check_fails_on_a_word_that_says_something_is_wrong(capsys, monkeypatch):
    import uptime

    def judge(word) -> int:
        body = {"ok": True, "version": "x", "engine": "0.11.0", "cleanup": "ok", "steps": "apart",
                "service_user": "own"}
        if word is not None:
            body["test_machines"] = word
        monkeypatch.setattr(uptime, "health", lambda url, timeout: (body, 0.1, "HTTP 200"))
        return uptime.main(["--cloud", "https://cloud.test"])
    for fine in (None, "off", "ok", "not yet"):                 # None: a website from before the test machines
        assert judge(fine) == 0, fine
    capsys.readouterr()
    for wrong in ("behind", "failed", "misset", "something else", {"on": True}):
        assert judge(wrong) == 1, wrong
        assert "test machine" in capsys.readouterr().err


def test_the_websites_health_page_and_the_owners_page(tmp_path):
    from fastapi.testclient import TestClient
    from lantern_cloud.app import create_app

    def settings(**more):
        return Settings(admin_secret="admin-" + "y" * 20, db_path=str(tmp_path / "c.db"),
                        results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"), audits=False, **more)
    admin = {"authorization": "Bearer admin-" + "y" * 20}
    with TestClient(create_app(settings(), start_worker=False)) as off:
        assert off.get("/v1/health").json()["test_machines"] == "off"
        assert off.get("/v1/admin/stats", headers=admin).json()["test_machines"] == {"on": False}
    with TestClient(create_app(settings(test_machines_key=KEY, test_machines_image="lantern-runner:latest"),
                               start_worker=False)) as misset:
        assert misset.get("/v1/health").json()["test_machines"] == "misset"
        stats = misset.get("/v1/admin/stats", headers=admin).json()["test_machines"]
        assert stats["on"] is False and "fingerprint" in stats["why"] and KEY not in json.dumps(stats)
    # switched on (the hosting company stood in for): the website's start sweeps away what an earlier one left
    host, doors, m, archive, _ = _setup(tmp_path / "on")
    left_before = machines.name_for("practice", NOW - timedelta(minutes=1))
    _plant(host, left_before)
    with TestClient(create_app(settings(), start_worker=False, test_machines=m)) as on:
        health = on.get("/v1/health").json()
        assert health["test_machines"] == "ok" and left_before not in host.apps, (health, host.apps)
        assert "apps" not in json.dumps(health)                 # the public page holds no counts
        stats = on.get("/v1/admin/stats", headers=admin).json()["test_machines"]
        assert stats["on"] is True and stats["apps"] == 0 and stats["left"] == 0 and KEY not in json.dumps(stats)
