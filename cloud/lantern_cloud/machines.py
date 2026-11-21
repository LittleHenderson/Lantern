"""One test machine of its own for each check's tests (a firm pass or fail, stage 3, step 5, 2026-11-21; the design
"Website test runs").

A project's tests never run on the website's own machine. For each check the website makes, at the hosting company,
an app of the check's own with a private network of its own (so no check's machine can reach another check's, nor the
website's), an outbound rule made before the machine (`egress`), a shared address for its one door, and one machine:
the test machine's image (`cloud/runner/Dockerfile`, named by its fingerprint), two processors, the memory the tests
were given and room for the program beside them (`memory_for`), removed by the hosting company when its program
ends and never started again. The machine is handed the SHA-256 fingerprint of a key made for this one check
(`lantern.runner.KEY_VARIABLE`) and nothing else; the key itself stays with the website, which hands the check's
archive over through the door, follows the check, takes the result by its shape (`taken`), ends the program and
removes the machine and the app, whatever happened before.

    m = Machines(Hosting(key), image, tag="live")
    result = m.run(archive, minutes=10, memory=2048, log=print, cancel=event)
    m.sweep()                 # this website's apps a check left (`left`), or older than any check can be

**Whatever happens.** Every step that makes something is undone in `run`'s `finally`: the machine is removed with
force, then the app (and with it its network, rule and address); a removal is tried `REMOVE_TRIES` times, and what
could not be removed is written down (`left`) for the next sweep. `sweep` removes only apps whose names are of this
module's shape (`name_for`: `lt-<tag>-<UTC time made>-<8 random letters>`) and carry this website's tag: those a check
left, those older than any check can be (`longest`), or, when the website starts, every one (`everything`); never one
of a check that is going. The website sweeps at its start and every `SWEEP_EVERY` seconds (`sweep_forever`), and its
health page says one word about it (`word`), which the uptime check reads.

**Limits.** At most `at_once` machines at once, first come first served (`_Turns`), and a check that waits says so.
The hosting company is asked no faster than it allows (`Pacer`, per kind of request); an answer 429 is waited out for
as long as it says, `MOST_429` times. An answer of the machine API is read up to `MOST_API_ANSWER` bytes, one of the
door up to `MOST_DOOR_ANSWER`. An archive larger than `archive_mb` makes no machine. The tests have their minutes and
`END_ROOM` more; then they are stopped (`POST /v1/stop`) and their result is waited for `STOP_WAIT` seconds.

**The key.** The hosting company's key goes to its machine API alone (`authorization`), is held in memory only and is
named in no error, line of the log or result: `HostingError` says what was being done and the status, never the
answer's text.

Nothing here runs a test: that is the machine's program (`lantern/runner.py`). Every answer of the hosting company
written down here is what Lantern's notes of its manual say; the practice copy (step 7) checks each against the
hosting company itself before anything goes live."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import httpx

from lantern import runner, sandbox

API = "https://api.machines.dev"
ORG = "lantern-runs"
REGION = "sjc"
EGRESS = "tcp:0"                    # the one outbound connection the rule allows: to port 0, where none goes
CPUS = 2
FLOOR_MB = 4096                     # the least memory the hosting company gives two performance processors
ROOM_MB = 1024                      # memory beside the tests': the machine's system, its program, the sandbox's own
STEP_MB = 256                       # memory is given in steps of 256 MB
MOST_MB = 8192                      # the most memory a test machine is given unless the website's settings say more
HIGHEST_MB = 16384                  # the most two performance processors can have
PORT = 8080                         # the machine's program's door (cloud/runner/Dockerfile)
ARCHIVE_MB = 2048                   # the largest archive a test machine is handed, unless the settings say otherwise
MOST_AT_ONCE = 16
MAKE_WAIT = 300.0                   # seconds a machine has to start
READY = 180.0                       # seconds its door has, once it started, to answer (and an answer that stops)
READY_PAUSE = 2.0
POLL = 2.0                          # seconds between two looks at how a check is going
END_ROOM = 600.0                    # seconds a check has beyond its tests' minutes: unpacking, the sandbox, the result
STOP_WAIT = 120.0                   # seconds the result of stopped tests is waited for
REMOVE_ROOM = 600.0                 # seconds the removal of a machine and its app may take, tries and waits counted
MOST_429 = 8                        # answers 429 waited out for one request
MOST_PAUSE = 30.0                   # seconds one answer 429 is waited out at most
REMOVE_TRIES = 3                    # tries of a removal the hosting company failed (5xx) or could not be reached for
SWEEP_EVERY = 300.0
STALE = 4 * SWEEP_EVERY             # a sweep older than this means the sweeps stopped
MOST_API_ANSWER = 4 << 20
MOST_DOOR_ANSWER = 128 << 20
MOST_WHY = 4000                     # characters of a result's `why_not`
MOST_LINE = 2000                    # characters of one line of the machine's log
MOST_KEY = 8192
API_TIMEOUT = 30.0
DOOR_TIMEOUT = 60.0
TAG = re.compile(r"[a-z][a-z0-9]{0,11}")
ORG_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_NAME = re.compile(r"lt-(?P<tag>[a-z][a-z0-9]{0,11})-(?P<at>[0-9]{8}t[0-9]{6})-[0-9a-f]{8}")
_TOKEN = re.compile(r"[\x21-\x7e]+")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,250}@sha256:[0-9a-f]{64}")
_REGION = re.compile(r"[a-z]{3}")
_EGRESS = re.compile(r"(tcp|udp):([0-9]{1,5})")
_MACHINE_ID = re.compile(r"[0-9a-z]{1,64}")
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
DONE = "done"

# What was being done when the hosting company answered (`HostingError`), in the words a person reads.
DOING = {"apps-create": "its app was made", "policies-create": "its outbound rule was made",
         "ips-create": "its address was made", "machines-create": "the machine was made",
         "machines-wait": "the machine was asked whether it had started", "machines-delete": "the machine was removed",
         "apps-delete": "its app was removed", "apps-list": "the test machines' apps were listed",
         "machines-list": "an app's machines were listed"}


# ---------------------------------------------------------------------------------------------- names and shapes
def name_for(tag: str, now: datetime) -> str:
    """The name of a check's app: `lt-<tag>-<UTC time it was made>-<8 random letters>`. ValueError for a tag that
    is no short word (`TAG`)."""
    if not isinstance(tag, str) or not TAG.fullmatch(tag):
        raise ValueError("a tag is a short word: a small letter, then up to 11 small letters or digits")
    return f"lt-{tag}-{now.astimezone(timezone.utc).strftime('%Y%m%dt%H%M%S')}-{secrets.token_hex(4)}"


def parse_name(name) -> tuple[str, datetime] | None:
    """(tag, time made) of a name `name_for` makes; None for anything else, which is nobody's to remove."""
    if not isinstance(name, str):
        return None
    m = _NAME.fullmatch(name)
    if m is None:
        return None
    at = m["at"]
    try:
        made = datetime(int(at[0:4]), int(at[4:6]), int(at[6:8]), int(at[9:11]), int(at[11:13]), int(at[13:15]),
                        tzinfo=timezone.utc)
    except ValueError:
        return None
    return m["tag"], made


def authorization(key) -> str:
    """The header the machine API is sent: an organization key as the hosting company made it (`FlyV1 …`), any other
    token as `Bearer <token>`. ValueError (whose words never hold the key) for what no key looks like."""
    if not isinstance(key, str) or not 0 < len(key) <= MOST_KEY:
        raise ValueError("the hosting company's key for the test machines is not set, or is not as long as a key is")
    for scheme in ("FlyV1 ", "Bearer "):
        if key.startswith(scheme):
            if _TOKEN.fullmatch(key[len(scheme):]):
                return key
            break
    else:
        if _TOKEN.fullmatch(key):
            return "Bearer " + key
    raise ValueError("the hosting company's key for the test machines holds what no key holds (a space, a line break "
                     "or a letter outside plain ASCII)")


def memory_for(memory, most: int = MOST_MB) -> int:
    """Megabytes of the machine for tests given `memory` MB: theirs and `ROOM_MB` more, in steps of `STEP_MB`, and
    at least `FLOOR_MB`. ValueError for memory the sandbox does not take or a machine larger than `most`."""
    low, high = sandbox.MEGABYTES
    if isinstance(memory, bool) or not isinstance(memory, int) or not low <= memory <= high:
        raise ValueError(f"the tests' memory is a whole number of megabytes from {low:,}")
    mb = max(FLOOR_MB, -(-(memory + ROOM_MB) // STEP_MB) * STEP_MB)
    if mb > most:
        raise ValueError(f"tests given {memory:,} MB need a machine of {mb:,} MB, and a test machine has at most "
                         f"{most:,} MB")
    return mb


def taken(result):
    """The machine's result when it has the shape the machine's program writes (`lantern.runner.check`), as it came;
    None otherwise. Version 1; a state of `lantern.runner.END_STATES`; `why_not` None or text of at most `MOST_WHY`
    characters, and some text for every state but done; `runner`, `taken`, `check` and `tests` tables where they are
    there, and `tests` there when the tests ran."""
    if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1:
        return None
    state = result.get("state")
    if state not in runner.END_STATES or "why_not" not in result:
        return None
    why = result["why_not"]
    if why is not None and (not isinstance(why, str) or len(why) > MOST_WHY):
        return None
    if state != DONE and not (isinstance(why, str) and why.strip()):
        return None
    if any(part in result and not isinstance(result[part], dict) for part in ("runner", "taken", "check", "tests")):
        return None
    if state == DONE and "tests" not in result:
        return None
    return result


def longest(archive_mb: int = ARCHIVE_MB) -> float:
    """Seconds a check's app can live at most: the machine's start, its door, the archive sent as slowly as the
    machine's program allows, the longest tests and their room, their stop, the removal."""
    send = max(runner.MIN_SECONDS, (archive_mb << 20) / runner.MIN_RATE)
    return MAKE_WAIT + READY + send + sandbox.MINUTES[1] * 60 + END_ROOM + STOP_WAIT + REMOVE_ROOM


def egress_rules(egress: str) -> list[dict]:
    """The outbound rule of every check's app, from the setting `<tcp|udp>:<port>`; ValueError otherwise."""
    m = _EGRESS.fullmatch(egress) if isinstance(egress, str) else None
    if m is None or int(m[2]) > 65535:
        raise ValueError("the test machines' outbound rule is written <tcp|udp>:<port>")
    return [{"action": "allow", "direction": "egress", "ports": [{"protocol": m[1], "port": int(m[2])}]}]


def _ended(state: str, why: str) -> dict:
    return {"version": 1, "state": state, "why_not": why}


def _printable(line: str) -> str:
    return _CONTROL.sub("?", line[:MOST_LINE])


class _TooLong(Exception):
    pass


def _read(response: httpx.Response, most: int) -> bytes:
    got = bytearray()
    for chunk in response.iter_bytes():
        got += chunk
        if len(got) > most:
            raise _TooLong()
    return bytes(got)


def _retry_after(value) -> float | None:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds != seconds:              # not a number
        return None
    return min(max(seconds, 0.0), MOST_PAUSE)


# ---------------------------------------------------------------------------------------------- the hosting company
class HostingError(Exception):
    """The hosting company did not do what it was asked: `kind` (a key of `DOING`), `status` (its answer's number, or
    None where it could not be reached), and `how` where its answer could not be read. Its words never hold the
    answer's text or the key."""

    def __init__(self, kind: str, status: int | None, how: str = ""):
        self.kind, self.status = kind, status
        doing = DOING.get(kind, "it was asked")
        if how:
            said = f"the hosting company gave {how}"
        elif status is None:
            said = "the hosting company could not be reached"
        else:
            said = f"the hosting company answered {status}"
        super().__init__(f"{said} when {doing}")


class Pacer:
    """No more than `rate` requests a second of each kind, `burst` of them at once (a bucket of turns per kind)."""

    def __init__(self, rate: float = 1.0, burst: int = 3, clock=time.monotonic, sleep=time.sleep):
        if not rate > 0 or burst < 1:
            raise ValueError("a pace is a rate above 0 and a burst of 1 or more")
        self.rate, self.burst, self.clock, self.sleep = float(rate), float(burst), clock, sleep
        self._lock = threading.Lock()
        self._turns: dict[str, tuple[float, float]] = {}

    def wait(self, kind: str) -> None:
        with self._lock:
            now = self.clock()
            turns, at = self._turns.get(kind, (self.burst, now))
            turns = min(self.burst, turns + (now - at) * self.rate)
            if turns >= 1.0:
                self._turns[kind] = (turns - 1.0, now)
                return
            need = (1.0 - turns) / self.rate
            self._turns[kind] = (0.0, now + need)        # this turn is taken; the next is counted from its time
        self.sleep(need)


class Hosting:
    """The hosting company's machine API, asked with the organization's key (`authorization`). `transport`: an httpx
    transport (a stand-in in tests); `pacer`: the pace of the requests (`Pacer`); `sleep`: how a wait is waited."""

    def __init__(self, key: str, org: str = ORG, api: str = API, transport=None, pacer: Pacer | None = None,
                 sleep=time.sleep, timeout: float = API_TIMEOUT):
        self._auth = authorization(key)
        if not isinstance(org, str) or not ORG_SLUG.fullmatch(org):
            raise ValueError("the test machines' organization is named by its short name: small letters, digits and "
                             "dashes")
        try:
            url = httpx.URL(api) if isinstance(api, str) else None
        except (httpx.InvalidURL, TypeError, ValueError):
            url = None
        if url is None or url.scheme != "https" or not url.host or url.userinfo or url.query or url.fragment \
                or url.path not in ("", "/"):
            raise ValueError("the machine API is an https address with nothing after its host")
        self.org, self.api = org, str(api).rstrip("/")
        self.transport, self.sleep, self.timeout = transport, sleep, timeout
        self.pacer = pacer or Pacer()

    def __repr__(self) -> str:
        return f"Hosting(org={self.org!r}, api={self.api!r})"

    def _ask(self, kind: str, method: str, path: str, body=None, params=None, gone_ok: bool = False, tries: int = 1,
             timeout: float | None = None):
        """One request: its answer's JSON ({} for an answer with none), None for 404 where `gone_ok`, HostingError
        otherwise. A 429 is waited out (`MOST_429` times); a 5xx or no connection is tried again only `tries`
        times in all, for the requests that may be (removals)."""
        waited = attempt = 0
        while True:
            attempt += 1
            self.pacer.wait(kind)
            status, retry, raw, how, done = None, None, b"", "", False
            try:
                with httpx.Client(transport=self.transport, timeout=timeout or self.timeout, follow_redirects=False,
                                  trust_env=False) as client:
                    with client.stream(method, self.api + path, json=body, params=params,
                                       headers={"Authorization": self._auth, "Accept": "application/json"}) as r:
                        status = r.status_code
                        retry = _retry_after(r.headers.get("retry-after"))
                        done = 200 <= status < 300           # the one place that says what a done request is
                        if done:
                            raw = _read(r, MOST_API_ANSWER)
            except _TooLong:
                how = "an answer longer than Lantern reads"
            except httpx.HTTPError:
                status, done = None, False
            if how:
                raise HostingError(kind, status, how)
            if done:
                if not raw.strip():
                    return {}
                try:
                    return json.loads(raw)
                except ValueError:
                    raise HostingError(kind, status, "an answer Lantern could not read") from None
            if status == 404 and gone_ok:
                return None
            if status == 429 and waited < MOST_429:
                waited += 1
                self.sleep(retry if retry is not None else 1.0)
                continue
            if (status is None or status >= 500) and attempt < tries:
                self.sleep(float(attempt))
                continue
            raise HostingError(kind, status)

    def make_app(self, name: str) -> None:
        """The check's app, on a private network of its own named after it."""
        self._ask("apps-create", "POST", "/v1/apps", {"app_name": name, "org_slug": self.org, "network": name})

    def allow_out(self, name: str, rules: list[dict]) -> None:
        """The app's outbound rule, for every machine it will hold (made before the machine)."""
        self._ask("policies-create", "POST", f"/v1/apps/{name}/network_policies",
                  {"name": "lantern-check", "selector": {"all": True}, "rules": rules})

    def address(self, name: str) -> None:
        """A shared address, so the app's door can be reached at its name."""
        self._ask("ips-create", "POST", f"/v1/apps/{name}/ip_assignments", {"type": "shared_v4"})

    def make_machine(self, name: str, region: str, config: dict) -> str:
        """The machine; its id."""
        said = self._ask("machines-create", "POST", f"/v1/apps/{name}/machines", {"region": region, "config": config})
        mid = said.get("id") if isinstance(said, dict) else None
        if not isinstance(mid, str) or not _MACHINE_ID.fullmatch(mid):
            raise HostingError("machines-create", None, "an answer that names no machine")
        return mid

    def started(self, name: str, mid: str, seconds: int) -> bool:
        """True once the machine has started, asked to wait up to `seconds` (at most 60); False where the hosting
        company said it had not yet (408)."""
        try:
            self._ask("machines-wait", "GET", f"/v1/apps/{name}/machines/{mid}/wait",
                      params={"state": "started", "timeout": seconds}, timeout=seconds + 15.0)
        except HostingError as e:
            if e.status == 408:
                return False
            raise
        return True

    def remove_machine(self, name: str, mid: str) -> None:
        self._ask("machines-delete", "DELETE", f"/v1/apps/{name}/machines/{mid}", params={"force": "true"},
                  gone_ok=True, tries=REMOVE_TRIES)

    def remove_app(self, name: str) -> None:
        self._ask("apps-delete", "DELETE", f"/v1/apps/{name}", gone_ok=True, tries=REMOVE_TRIES)

    def apps(self) -> list[str]:
        """The names of the organization's apps."""
        said = self._ask("apps-list", "GET", "/v1/apps", params={"org_slug": self.org})
        rows = said.get("apps") if isinstance(said, dict) else None
        if not isinstance(rows, list):
            raise HostingError("apps-list", None, "an answer that lists no apps")
        return [r["name"] for r in rows if isinstance(r, dict) and isinstance(r.get("name"), str)]

    def machines(self, name: str) -> list[str]:
        """The ids of an app's machines ([] for an app that is not there)."""
        said = self._ask("machines-list", "GET", f"/v1/apps/{name}/machines", gone_ok=True)
        if said is None:
            return []
        if not isinstance(said, list):
            raise HostingError("machines-list", None, "an answer that lists no machines")
        return [r["id"] for r in said if isinstance(r, dict) and isinstance(r.get("id"), str)
                and _MACHINE_ID.fullmatch(r["id"])]


# ---------------------------------------------------------------------------------------------- turns
class _Turns:
    """At most `at_once` checks at a time, in the order they asked."""

    def __init__(self, at_once: int):
        self.at_once = at_once
        self._cond = threading.Condition()
        self._queue: deque = deque()
        self._busy = 0

    def take(self, cancel: threading.Event, waiting) -> bool:
        """True once it is this check's turn; False when `cancel` was set first. `waiting(n)` is told how many
        checks asked before this one, each time that changes while it waits."""
        me, told = object(), None
        with self._cond:
            self._queue.append(me)
        while True:
            with self._cond:
                if self._queue[0] is me and self._busy < self.at_once:
                    self._queue.popleft()
                    self._busy += 1
                    self._cond.notify_all()
                    return True
                if cancel.is_set():
                    self._queue.remove(me)
                    self._cond.notify_all()
                    return False
                ahead = self._queue.index(me)
                if ahead == told:
                    self._cond.wait(0.5)
                    continue
            told = ahead
            waiting(ahead)

    def give_back(self) -> None:
        with self._cond:
            self._busy -= 1
            self._cond.notify_all()


class _Stopped(Exception):
    pass


class _Not(Exception):
    """A check that cannot go on, with the sentence its result says."""


# ---------------------------------------------------------------------------------------------- the machines
class Machines:
    """The test machines of one website (`tag`: its own word, which the sweep goes by; a practice copy and the live
    website have their own). `hosting`: the machine API (`Hosting`); `image`: the test machine's image, named by its
    fingerprint. `door_for(app)`: the door's address (its name at the hosting company); `door_transport`: an httpx
    transport for the doors (a stand-in in tests), read when a check begins. `clock`, `sleep` and `now` are the
    clock's (a stand-in in tests); `make_wait`, `ready`, `poll` and `stop_wait` the seconds of `MAKE_WAIT`, `READY`,
    `POLL` and `STOP_WAIT`."""

    def __init__(self, hosting: Hosting, image: str, tag: str = "live", at_once: int = 2, region: str = REGION,
                 egress: str = EGRESS, most_memory: int = MOST_MB, archive_mb: int = ARCHIVE_MB, door_for=None,
                 door_transport=None, clock=time.monotonic, sleep=time.sleep, now=None, make_wait: float = MAKE_WAIT,
                 ready: float = READY, poll: float = POLL, stop_wait: float = STOP_WAIT):
        if not isinstance(image, str) or not _IMAGE.fullmatch(image):
            raise ValueError("the test machines' image is not named by its fingerprint (<image>@sha256:<64 letters>)")
        if not isinstance(tag, str) or not TAG.fullmatch(tag):
            raise ValueError("the test machines' tag is a short word: a small letter, then up to 11 small letters or "
                             "digits")
        if isinstance(at_once, bool) or not isinstance(at_once, int) or not 1 <= at_once <= MOST_AT_ONCE:
            raise ValueError(f"the test machines at once are a whole number from 1 to {MOST_AT_ONCE}")
        if not isinstance(region, str) or not _REGION.fullmatch(region):
            raise ValueError("the test machines' region is named by its three small letters")
        if isinstance(most_memory, bool) or not isinstance(most_memory, int) \
                or not FLOOR_MB <= most_memory <= HIGHEST_MB or most_memory % STEP_MB:
            raise ValueError(f"a test machine's memory is from {FLOOR_MB:,} to {HIGHEST_MB:,} MB, in steps of "
                             f"{STEP_MB}")
        if isinstance(archive_mb, bool) or not isinstance(archive_mb, int) \
                or not 1 <= archive_mb <= runner.MOST_ARCHIVE >> 20:
            raise ValueError(f"the largest archive is from 1 to {runner.MOST_ARCHIVE >> 20:,} MB")
        self.hosting, self.image, self.tag, self.at_once, self.region = hosting, image, tag, at_once, region
        self.rules = egress_rules(egress)
        self.most_memory, self.archive_mb = most_memory, archive_mb
        self.door_for = door_for or (lambda app: f"https://{app}.fly.dev")
        self.door_transport = door_transport
        self.clock, self.sleep = clock, sleep
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.make_wait, self.ready, self.poll, self.stop_wait = make_wait, ready, poll, stop_wait
        self.left: set[str] = set()          # apps a check could not remove, for the next sweep
        self.first_sweep = threading.Event()
        self._going: set[str] = set()        # apps of checks under way, which no sweep touches
        self._seen: dict[str, datetime] = {}  # this website's apps the last sweep left in place, with when made
        self._lock = threading.Lock()        # held for this bookkeeping only, never across a request
        self._sweeping = threading.Lock()
        self._turns = _Turns(at_once)
        self.swept_at: str | None = None
        self._swept_clock: float | None = None
        self.sweep_state = "not yet"

    # ------------------------------------------------------------------------------------------ one check
    def run(self, archive, minutes: int, memory: int, log=None, cancel: threading.Event | None = None) -> dict:
        """One check's tests on a machine of their own: the result of the machine's program (`taken`) with
        `machine` = {image, region, cpus, memory_mb}, or the website's own result where the tests could not run there
        (`unable`, `refused` or `stopped` with `why_not`). Whatever happened, nothing of the check is left at the
        hosting company, or what is left is in `left`."""
        log = log or (lambda line: None)
        cancel = cancel if cancel is not None else threading.Event()
        if cancel.is_set():
            return _ended("stopped", "The check was stopped before a test machine was made.")
        archive = Path(archive)
        try:
            size = archive.stat().st_size
        except OSError:
            return _ended("unable", "The check's archive could not be read on the website, so the tests were not run.")
        if size > self.archive_mb << 20:
            return _ended("refused", f"The check's archive has more than {self.archive_mb:,} MB, the most a test "
                                     "machine is handed, so the tests were not run.")
        low, high = sandbox.MINUTES
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not low <= minutes <= high:
            return _ended("refused", f"A check's tests have from {low} to {high} minutes, so the tests were not run.")
        try:
            memory_mb = memory_for(memory, self.most_memory)
        except ValueError as e:
            return _ended("refused", f"No test machine fits: {e}, so the tests were not run.")

        def waiting(ahead: int) -> None:
            more = f", and {ahead} more {'check' if ahead == 1 else 'checks'} asked before this one" if ahead else ""
            log(f"machine waiting for a test machine: at most {self.at_once} at once{more}")
        if not self._turns.take(cancel, waiting):
            return _ended("stopped", "The check was stopped while it waited for a test machine.")
        try:
            return self._run(archive, size, minutes, memory_mb, log, cancel)
        finally:
            self._turns.give_back()

    def _run(self, archive: Path, size: int, minutes: int, memory_mb: int, log, cancel: threading.Event) -> dict:
        name = name_for(self.tag, self.now())
        key = secrets.token_urlsafe(32)
        digest = hashlib.sha256(key.encode("ascii")).hexdigest()
        made = {"app": False, "machine": False, "id": None}
        with self._lock:
            self._going.add(name)
        try:
            try:
                log(f"machine making a test machine of this check's own: {CPUS} processors, {memory_mb:,} MB of memory")
                made["app"] = True
                self.hosting.make_app(name)
                self._go_on(cancel)
                self.hosting.allow_out(name, self.rules)
                self.hosting.address(name)
                self._go_on(cancel)
                made["machine"] = True
                made["id"] = self.hosting.make_machine(name, self.region, self._config(digest, memory_mb))
                self._wait_started(name, made["id"], cancel)
                log("machine started")
                result = self._check(name, key, archive, size, minutes, log, cancel)
            except _Stopped:
                return _ended("stopped", "The check was stopped before its tests ran.")
            except HostingError as e:
                return _ended("unable", f"A test machine could not be made: {e}, so the tests were not run.")
            except _Not as e:
                return _ended("unable", str(e))
            except Exception as e:  # noqa: BLE001 - whatever went wrong, the check has a result and its machine goes
                return _ended("unable", f"The test machine could not be used ({type(e).__name__}), so the tests were "
                                        "not run.")
            log(f"machine the check ended: {result['state']}")
            return dict(result, machine={"image": self.image, "region": self.region, "cpus": CPUS,
                                         "memory_mb": memory_mb})
        finally:
            self._remove(name, made, log)
            with self._lock:
                self._going.discard(name)

    @staticmethod
    def _go_on(cancel: threading.Event) -> None:
        if cancel.is_set():
            raise _Stopped()

    def _config(self, digest: str, memory_mb: int) -> dict:
        return {"image": self.image, "env": {runner.KEY_VARIABLE: digest},
                "guest": {"cpu_kind": "performance", "cpus": CPUS, "memory_mb": memory_mb},
                "auto_destroy": True, "restart": {"policy": "no"},
                "services": [{"protocol": "tcp", "internal_port": PORT, "autostart": False, "autostop": "off",
                              "ports": [{"port": 443, "handlers": ["tls", "http"]}]}]}

    def _wait_started(self, name: str, mid: str, cancel: threading.Event) -> None:
        until = self.clock() + self.make_wait
        while True:
            self._go_on(cancel)
            left = until - self.clock()
            if left <= 0:
                raise _Not(f"The test machine did not start in {int(self.make_wait)} seconds, so the tests were not run.")
            asked = max(1, min(60, int(left)))
            began = self.clock()
            if self.hosting.started(name, mid, asked):
                return
            pause = min(5.0, asked - (self.clock() - began))     # an answer "not yet" that came early is not asked
            if pause > 0:                                          # again at once
                self.sleep(pause)

    # ------------------------------------------------------------------------------------------ the door
    def _door(self, client: httpx.Client, method: str, url: str, headers: dict, content=None,
              params=None) -> tuple[int | None, object]:
        """(status, JSON body or None); status None where the door could not be reached, -1 for an answer longer
        than `MOST_DOOR_ANSWER`."""
        try:
            with client.stream(method, url, headers=headers, content=content, params=params) as r:
                status = r.status_code
                raw = _read(r, MOST_DOOR_ANSWER) if 200 <= status < 300 else b""
        except _TooLong:
            return -1, None
        except httpx.HTTPError:
            return None, None
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def _check(self, name: str, key: str, archive: Path, size: int, minutes: int, log, cancel) -> dict:
        url = self.door_for(name).rstrip("/")
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        with httpx.Client(transport=self.door_transport, timeout=httpx.Timeout(DOOR_TIMEOUT, connect=10.0),
                          follow_redirects=False, trust_env=False) as client:
            self._door_up(client, url, headers, cancel)
            try:
                with archive.open("rb") as f:
                    status, _ = self._door(client, "PUT", url + "/v1/check", headers, content=f)
                if status == 401:
                    raise _Not("The test machine did not let the website in, so the tests were not run.")
                if status != 202:
                    said = f"it answered {status}" if status not in (None, -1) else "the connection broke"
                    raise _Not(f"The test machine did not take the check's archive ({said}), so the tests were not run.")
                log(f"machine the check's archive was handed over ({size:,} bytes); the tests run on the test machine")
                return self._follow(client, url, headers, minutes, log, cancel)
            finally:
                self._door(client, "POST", url + "/v1/end", headers)

    def _door_up(self, client: httpx.Client, url: str, headers: dict, cancel: threading.Event) -> None:
        until = self.clock() + self.ready
        while True:
            self._go_on(cancel)
            status, body = self._door(client, "GET", url + "/v1/check", headers)
            if status == 200 and isinstance(body, dict):
                return
            if status == 401:
                raise _Not("The test machine did not let the website in, so the tests were not run.")
            if status not in (None, 502, 503, 504):
                raise _Not("The test machine did not answer as the test machine's program does, so the tests were "
                           "not run.")
            if self.clock() >= until:
                raise _Not(f"The test machine could not be reached in {int(self.ready)} seconds, so the tests were not "
                           "run.")
            self.sleep(min(READY_PAUSE, max(until - self.clock(), 0.0)))

    def _follow(self, client: httpx.Client, url: str, headers: dict, minutes: int, log, cancel) -> dict:
        deadline = self.clock() + minutes * 60 + END_ROOM
        start, stopping_until, failing_since = 0, None, None
        while True:
            status, body = self._door(client, "GET", url + "/v1/check", headers, params={"from": start})
            if status == 200 and isinstance(body, dict):
                failing_since = None
                lines = body.get("lines")
                for line in lines if isinstance(lines, list) else ():
                    if isinstance(line, str):
                        log(_printable(line))
                missed = body.get("missed")
                if type(missed) is int and missed > 0:
                    log(f"machine {missed:,} lines of the test machine's log were not kept")
                nxt = body.get("next")
                if type(nxt) is int and nxt >= start:
                    start = nxt
                if body.get("result") is not None:
                    got = taken(body["result"])
                    if got is None:
                        raise _Not("The test machine's result is not of the shape the test machine's program writes, "
                                   "so the check has no result.")
                    return got
            elif status == 401:
                raise _Not("The test machine did not let the website in, so the check has no result.")
            elif status in (200, -1):
                raise _Not("The test machine's answer is not of the shape the test machine's program writes, so the "
                           "check has no result.")
            else:
                failing_since = self.clock() if failing_since is None else failing_since
                if self.clock() - failing_since > self.ready:
                    raise _Not("The test machine stopped answering, so the check has no result.")
            now = self.clock()
            if stopping_until is None and (cancel.is_set() or now >= deadline):
                log("machine stopped by the person: the tests are stopped" if cancel.is_set()
                    else f"machine the tests ran past their {minutes} minutes and the room after them: they are stopped")
                self._door(client, "POST", url + "/v1/stop", headers)
                stopping_until = now + self.stop_wait
            elif stopping_until is not None and now >= stopping_until:
                raise _Not(f"The test machine did not end the tests in the {int(self.stop_wait)} seconds after it was "
                           "asked to stop them, so the check has no result.")
            self.sleep(self.poll)

    # ------------------------------------------------------------------------------------------ removal and the sweep
    def _remove(self, name: str, made: dict, log) -> None:
        if not made["app"]:
            return
        try:
            if made["machine"]:
                for mid in [made["id"]] if made["id"] else self.hosting.machines(name):
                    self.hosting.remove_machine(name, mid)
            self.hosting.remove_app(name)
        except HostingError as e:
            with self._lock:
                self.left.add(name)
            log(f"machine not removed yet ({e}); the sweep removes it")
            return
        with self._lock:
            self.left.discard(name)
            self._seen.pop(name, None)
        log("machine removed: nothing of the check is left")

    def _remove_found(self, name: str) -> bool:
        try:
            for mid in self.hosting.machines(name):
                self.hosting.remove_machine(name, mid)
            self.hosting.remove_app(name)
        except HostingError:
            with self._lock:
                self.left.add(name)
            return False
        with self._lock:
            self.left.discard(name)
        return True

    def sweep(self, everything: bool = False) -> None:
        """Removes this website's apps that a check left (`left`), that are older than any check can be (`longest`),
        or, with `everything` (when the website starts, before any check of its own), every one; never one of a
        check that is going, nor any app whose name is not of `name_for`'s shape with this website's tag."""
        with self._sweeping:
            try:
                names = self.hosting.apps()
            except HostingError:
                with self._lock:
                    self.sweep_state = "failed"
                    self.swept_at, self._swept_clock = self.now().isoformat(timespec="seconds"), self.clock()
                return
            now, allowed, kept = self.now(), longest(self.archive_mb), {}
            for name in names:
                parsed = parse_name(name)
                if parsed is None or parsed[0] != self.tag:
                    continue
                with self._lock:
                    going, left = name in self._going, name in self.left
                if going or not (everything or left or (now - parsed[1]).total_seconds() > allowed):
                    kept[name] = parsed[1]
                elif not self._remove_found(name):
                    kept[name] = parsed[1]
            with self._lock:
                self._seen = kept
                self.sweep_state = "ok"
                self.swept_at, self._swept_clock = now.isoformat(timespec="seconds"), self.clock()

    def sweep_forever(self, over: threading.Event, every: float = SWEEP_EVERY) -> None:
        """The website's sweeper: every one of its apps at the start, then what is left or too old, every `every`
        seconds until `over` is set."""
        first = True
        while not over.is_set():
            try:
                self.sweep(everything=first)
            except Exception:  # noqa: BLE001 - the sweeper goes on; the health page says the sweep failed
                with self._lock:
                    self.sweep_state = "failed"
            finally:
                self.first_sweep.set()
            first = False
            over.wait(every)

    # ------------------------------------------------------------------------------------------ what the owner sees
    def health(self) -> dict:
        """For the owner (`/v1/admin/stats`): this website's apps the last sweep left in place, the oldest one's age,
        how old one may be, the last sweep, what is left for the next one, the checks going."""
        with self._lock:
            stamps = list(self._seen.values())
            now = self.now()
            return {"on": True, "apps": len(stamps) if self.swept_at else None,
                    "oldest_minutes": int((now - min(stamps)).total_seconds() // 60) if stamps else None,
                    "allowed_minutes": int(longest(self.archive_mb) // 60), "swept_at": self.swept_at,
                    "sweep": self.sweep_state, "left": len(self.left), "apps_going": len(self._going),
                    "at_once": self.at_once}

    def word(self) -> str:
        """One word for the public health page: "not yet" (no sweep has ended), "failed" (the last sweep could not ask
        the hosting company), "behind" (an app of this website is older than any check can be, or the sweeps
        stopped) or "ok"."""
        h = self.health()
        if h["sweep"] in ("not yet", "failed"):
            return h["sweep"]
        if h["oldest_minutes"] is not None and h["oldest_minutes"] > h["allowed_minutes"]:
            return "behind"
        if self._swept_clock is not None and self.clock() - self._swept_clock > STALE:
            return "behind"
        return "ok"
