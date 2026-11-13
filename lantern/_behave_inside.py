"""Inside the sandbox: start a project's web app with no network, ask it things as different people, and write
down what it answered and what changed (directive point 5: "A rejected request that already changed the database
is a failure. Test the side effects, not just the response code.").

Standard library only, and only ever started by `lantern.sandbox.run_inside` (it refuses to work without the
sandbox's guard). Two kinds of process:

* the recorder (`python -m lantern._behave_inside SCENE OUT APP`): reads the scene `lantern.behave` wrote, keeps the
  app's data in a folder of the sandbox's temp folder, starts workers, sends each step, and after every step looks
  at the database and the files and writes down what differs from before. It decides nothing: `lantern.behave`
  judges from what is written down.
* a worker (`... worker MODULE:NAME`): imports the app (ASGI) and serves one request at a time that the recorder
  sends as a line of JSON over a pipe. There is no socket anywhere, so nothing can be reached from outside and the
  app is the same on every system. The worker counts what the app writes to SQLite and can be told to fail, stop
  or wait at the n-th write, which is how "the database fails half-way" and "two at the same moment" are made to
  happen on purpose.

What the app prints goes to a file the recorder reads only for the guard's own lines (a refused write or a refused
connection, with the address that was tried).

Where a name leads is answered by the worker itself (`_Names`), never by the network: an address written as
numbers is itself, a name the plan gives an address has that one, any other name gets an address of its own out
of the ranges kept for examples. So an app that asks first and then refuses is seen to refuse, and an app that
goes on is seen to set out for a real address, which the guard refuses and writes down.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib
import io
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile

MARK = "LANTERN-SANDBOX-BLOCKED:"
READY_SECONDS = 60.0        # a worker has this long to import the app and start it
REQUEST_SECONDS = 20.0      # and an answer this long
BODY_KEPT = 32 * 1024       # bytes of an answer that are written down
SWEEP_MOST = 12             # of one request's writes (and of its commits), how many are each made to fail
WRITES = ("INSERT", "UPDATE", "DELETE", "REPLACE")
COMMITS = ("COMMIT", "END")
SIDE_FILES = ("-journal", "-wal", "-shm")
NAME = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
EXAMPLE_RANGES = ("198.51.100.", "203.0.113.")      # kept for examples (RFC 5737): no computer has these
KEPT = 40                   # of one request's questions about names, how many are written down
_REAL_CONNECT = sqlite3.connect
_REAL_ADDRINFO = socket.getaddrinfo
_V6 = getattr(socket, "AF_INET6", None)


def _guarded() -> bool:
    return getattr(sys, "lantern_sandbox_guard", None) == "on"


# ------------------------------------------------------------------------------------------------ the worker
class _Armed:
    """What the recorder asked to happen during the request being served, and the counts of that request."""

    def __init__(self):
        self.out = None
        self.depth = threading.local()
        self.arm(None)

    def arm(self, fault) -> None:
        fault = fault or {}
        self.kind, self.on, self.at = fault.get("kind"), fault.get("on", "write"), int(fault.get("at", 1))
        self.writes = self.commits = 0

    def say(self, message: dict) -> None:
        self.out.write(json.dumps(message) + "\n")
        self.out.flush()

    def before(self, what: str) -> None:
        """Called before the app's n-th write (or commit) is handed to SQLite."""
        if what == "write":
            self.writes += 1
            n = self.writes
        else:
            self.commits += 1
            n = self.commits
        if self.kind is None or self.on != what or n != self.at:
            return
        kind, self.kind = self.kind, None
        if kind == "error":
            raise sqlite3.OperationalError("disk I/O error")
        if kind == "kill":
            os._exit(137)
        if kind == "pause":
            self.say({"paused": True})
            sys.stdin.readline()            # the recorder's "go on"


_ARMED = _Armed()


def _what(sql) -> str | None:
    word = sql.lstrip().split(None, 1)[0].upper() if isinstance(sql, str) and sql.strip() else ""
    return "write" if word in WRITES else "commit" if word in COMMITS else None


def _counted(sql, call):
    """Count one statement once, however many layers of sqlite3 it passes through."""
    if getattr(_ARMED.depth, "n", 0):
        return call()
    what = _what(sql)
    if what:
        _ARMED.before(what)
    _ARMED.depth.n = 1
    try:
        return call()
    finally:
        _ARMED.depth.n = 0


class _Cursor(sqlite3.Cursor):
    def execute(self, sql, *a, **k):
        return _counted(sql, lambda: super(_Cursor, self).execute(sql, *a, **k))

    def executemany(self, sql, *a, **k):
        return _counted(sql, lambda: super(_Cursor, self).executemany(sql, *a, **k))

    def executescript(self, script):
        return _counted("UPDATE" if any(_what(s) == "write" for s in str(script).split(";")) else "", lambda: super(_Cursor, self).executescript(script))


class _Connection(sqlite3.Connection):
    def cursor(self, factory=None):
        return super().cursor(factory or _Cursor)

    def execute(self, sql, *a, **k):
        return _counted(sql, lambda: super(_Connection, self).execute(sql, *a, **k))

    def executemany(self, sql, *a, **k):
        return _counted(sql, lambda: super(_Connection, self).executemany(sql, *a, **k))

    def executescript(self, script):
        return _counted("UPDATE" if any(_what(s) == "write" for s in str(script).split(";")) else "", lambda: super(_Connection, self).executescript(script))

    def commit(self):
        if self.in_transaction:
            _ARMED.before("commit")
        return super().commit()

    def __exit__(self, kind, value, trace):
        if kind is None:
            self.commit()
        else:
            self.rollback()
        return False


def _connect(*a, **k):
    k.setdefault("factory", _Connection)
    return _REAL_CONNECT(*a, **k)


def _written_out(host: str) -> str | None:
    """The address a host is when it is one already, in any spelling the system reads as numbers (`127.1`,
    `0x7f.0.0.1`, `2130706433`, `::1`). Read here, with no question to anything."""
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except (OSError, ValueError, TypeError):
        pass
    try:
        return str(ipaddress.IPv6Address(host.split("%", 1)[0]))
    except ValueError:
        return None


def _has_six() -> bool:
    try:
        socket.socket(_V6, socket.SOCK_STREAM).close()
        return True
    except (OSError, TypeError):
        return False


class _Names:
    """The runner's own answer to "what is the address of this name", in place of the system's."""

    def __init__(self):
        self.table: dict = {}           # name -> address: the plan's, and what was handed out since
        self.asked: list = []           # this request: [name, address, port]
        self.began: list = []           # this request: [address, port] the app set out for and could not begin
        self.six = True                 # this computer can open an IPv6 socket
        self.lock = threading.Lock()

    def start(self, names: dict) -> None:
        self.table = {str(k).rstrip(".").lower(): str(v) for k, v in names.items()}
        self.six = _has_six()
        socket.getaddrinfo = self.getaddrinfo
        socket.gethostbyname = self.gethostbyname
        socket.gethostbyname_ex = self.gethostbyname_ex
        sys.addaudithook(self.watch)

    def address(self, host, family: int = 0) -> str | None:
        name = (host.decode("ascii", "replace") if isinstance(host, (bytes, bytearray)) else str(host)).rstrip(".").lower()
        with self.lock:
            address = _written_out(name) or self.table.get(name)
            if address is None and (name == "localhost" or name.endswith(".localhost")):
                address = "::1" if family == _V6 and _V6 is not None else "127.0.0.1"
            if address is None:
                handed = sum(1 for a in self.table.values() if a.startswith(EXAMPLE_RANGES))
                if handed >= 2 * 254:
                    return None
                address = EXAMPLE_RANGES[handed // 254] + str(handed % 254 + 1)
                self.table[name] = address
            return address

    def note(self, host, address: str, port: int) -> None:
        name = (host.decode("ascii", "replace") if isinstance(host, (bytes, bytearray)) else str(host)).rstrip(".").lower()
        with self.lock:
            if [name, address, port] not in self.asked and len(self.asked) < KEPT:
                self.asked.append([name, address, port])

    def getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        if host is None or host in ("", b""):
            return _REAL_ADDRINFO(host, port, family, type, proto, flags)       # this computer itself
        address = self.address(host, family)
        if address is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        if port is None:
            number = 0
        elif isinstance(port, int):
            number = port
        else:
            text = port.decode("ascii", "replace") if isinstance(port, (bytes, bytearray)) else str(port)
            try:
                number = int(text) if text.isdigit() else socket.getservbyname(text)
            except OSError:
                raise socket.gaierror(getattr(socket, "EAI_SERVICE", socket.EAI_NONAME), "Servname not supported") from None
        six = ":" in address
        if (six and family == socket.AF_INET) or (not six and _V6 is not None and family == _V6) or (six and _V6 is None):
            raise socket.gaierror(getattr(socket, "EAI_ADDRFAMILY", socket.EAI_NONAME),
                                  "Address family for hostname not supported")
        self.note(host, address, number)
        kinds = [(socket.SOCK_STREAM, socket.IPPROTO_TCP), (socket.SOCK_DGRAM, socket.IPPROTO_UDP)]
        if type:
            kinds = [(type, proto or dict(kinds).get(type, 0))]
        elif proto:
            kinds = [k for k in kinds if k[1] == proto] or [(0, proto)]
        where = (address, number, 0, 0) if six else (address, number)
        canon = str(host) if flags & getattr(socket, "AI_CANONNAME", 0) else ""
        return [(_V6 if six else socket.AF_INET, kind, pr, canon if i == 0 else "", where) for i, (kind, pr) in enumerate(kinds)]

    def gethostbyname(self, host):
        address = self.address(host, socket.AF_INET)
        if address is None or ":" in address:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        self.note(host, address, 0)
        return address

    def gethostbyname_ex(self, host):
        return (str(host), [], [self.gethostbyname(host)])

    def watch(self, event: str, args: tuple) -> None:
        # A computer with no IPv6 refuses the socket itself, before the app can ask to be connected: the guard
        # then has nothing to refuse and nothing would be written down. Asking for such a socket after asking
        # where an IPv6 address is, is the app setting out for it, and that is kept in the guard's place.
        if event == "socket.__new__" and not self.six and len(args) > 1 and args[1] == _V6:
            with self.lock:
                for _name, address, port in self.asked:
                    if ":" in address and [address, port] not in self.began:
                        self.began.append([address, port])

    def take(self) -> dict:
        with self.lock:
            asked, began, self.asked, self.began = self.asked, self.began, [], []
        return {key: value for key, value in (("asked", asked), ("began", began)) if value}


_NAMES = _Names()


async def _started(app) -> dict:
    """Tell the app it is starting, the way a server does. An app that takes no such message is started already."""
    to_app, from_app = asyncio.Queue(), asyncio.Queue()
    state: dict = {}
    scope = {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}, "state": state}
    task = asyncio.ensure_future(app(scope, to_app.get, from_app.put))
    await to_app.put({"type": "lifespan.startup"})
    answer = asyncio.ensure_future(from_app.get())
    done, _ = await asyncio.wait({task, answer}, timeout=READY_SECONDS, return_when=asyncio.FIRST_COMPLETED)
    if answer in done and answer.result().get("type") == "lifespan.startup.failed":
        raise RuntimeError("the app said it could not start")
    if answer not in done:
        answer.cancel()
        if task in done:
            task.exception()                # an app with no start-up of its own: nothing to wait for
        else:
            raise RuntimeError("the app did not finish starting")
    return state


async def _served(app, message: dict, state: dict) -> dict:
    body = base64.b64decode(message.get("body") or "")
    path, _, query = message["path"].partition("?")
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": message["method"].upper(), "scheme": "http", "path": urllib.parse.unquote(path),
             "raw_path": path.encode("utf-8"), "query_string": query.encode("utf-8"), "root_path": "",
             "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in message["headers"]],
             "client": ("127.0.0.1", 50000), "server": ("app.test", 80), "state": dict(state)}
    got = {"status": None, "headers": [], "body": bytearray(), "bytes": 0}
    finished = asyncio.Event()
    handed = False

    async def receive():
        nonlocal handed
        if not handed:
            handed = True
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(event):
        if event["type"] == "http.response.start":
            got["status"] = event["status"]
            got["headers"] = [[k.decode("latin-1").lower(), v.decode("latin-1")] for k, v in event.get("headers", [])]
            if _ARMED.kind == "kill" and _ARMED.on == "answer":
                os._exit(137)               # the work is done and saved; the answer never leaves
        elif event["type"] == "http.response.body":
            piece = event.get("body", b"")
            got["bytes"] += len(piece)
            if len(got["body"]) < BODY_KEPT:
                got["body"] += piece[:BODY_KEPT - len(got["body"])]
            if not event.get("more_body"):
                finished.set()

    error = None
    try:
        await asyncio.wait_for(app(scope, receive, send), REQUEST_SECONDS)
    except asyncio.TimeoutError:
        error = "no answer in time"
    except BaseException as e:              # a server answers 500 and carries on; so does this
        error = type(e).__name__
    reply = {"status": got["status"] if got["status"] is not None else 500, "headers": got["headers"],
             "body": base64.b64encode(bytes(got["body"])).decode("ascii"), "bytes": got["bytes"],
             "writes": _ARMED.writes, "commits": _ARMED.commits, **_NAMES.take()}
    if error:
        reply["error"] = error
    return reply


def worker(target: str, names: str = "{}") -> int:
    _ARMED.out = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n")
    os.dup2(2, 1)                           # whatever the app prints is not part of the conversation
    sys.stdout = sys.stderr
    if not _guarded():
        _ARMED.say({"ready": False, "error": "the sandbox's guard is not in place"})
        return 97
    sqlite3.connect = _connect
    _NAMES.start(json.loads(names))
    sys.path.insert(0, os.getcwd())         # the app's own folder first, as a server started there has it
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        made = target.endswith("()")           # the name is a function that makes the app (a server's --factory)
        module, _, name = target.removesuffix("()").partition(":")
        app = getattr(importlib.import_module(module), name or "app")
        app = app() if made else app
        state = loop.run_until_complete(_started(app))
    except BaseException as e:
        _ARMED.say({"ready": False, "error": f"{type(e).__name__}: {e}"[:300]})
        return 3
    _ARMED.say({"ready": True})
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        message = json.loads(line)
        if message.get("op") != "request":
            break
        _ARMED.arm(message.get("fault"))
        _ARMED.say(loop.run_until_complete(_served(app, message, state)))
    return 0


# ------------------------------------------------------------------------------------------------ the recorder
class _Worker:
    """One running copy of the app."""

    def __init__(self, target: str, cwd: str, env: dict, log_file: str, names: dict | None = None):
        self.err_path = log_file
        self.err = open(log_file, "wb")
        self.read_to = 0
        self.paused = False
        self.proc = subprocess.Popen([sys.executable, "-P", "-m", "lantern._behave_inside", "worker", target,
                                      json.dumps(names or {})], cwd=cwd, env=env, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self.err)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.hello = self.get(READY_SECONDS)

    def _read(self) -> None:
        try:
            for line in self.proc.stdout:
                self.lines.put(line)
        except (OSError, ValueError):
            pass
        self.lines.put(None)

    def get(self, seconds: float) -> dict:
        try:
            line = self.lines.get(timeout=seconds)
        except queue.Empty:
            return {"timeout": True}
        if line is None:
            return {"died": True}
        try:
            message = json.loads(line)
        except ValueError:
            return {"died": True}
        return message if isinstance(message, dict) else {"died": True}

    def send(self, message: dict) -> bool:
        try:
            self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def alive(self) -> bool:
        return self.proc.poll() is None

    def blocked(self) -> list[str]:
        """The guard's lines since the last look: what the app tried and was refused."""
        try:
            with open(self.err_path, "rb") as f:
                f.seek(self.read_to)
                new = f.read(1 << 20)
                self.read_to += len(new)
        except OSError:
            return []
        lines = [ln.split(MARK, 1)[1].strip()[:200] for ln in new.decode("utf-8", "replace").splitlines() if MARK in ln]
        return list(dict.fromkeys(lines))[:20]

    def stop(self) -> None:
        if self.alive():
            self.send({"op": "stop"})
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.end()

    def end(self) -> None:
        if self.alive():
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for stream in (self.proc.stdin, self.proc.stdout, self.err):
            try:
                stream.close()
            except OSError:
                pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signed(head: dict, claims: dict, key: str) -> str:
    first = _b64(json.dumps(head, separators=(",", ":")).encode()) + "." + _b64(json.dumps(claims, separators=(",", ":")).encode())
    return first + "." + _b64(hmac.new(key.encode("utf-8"), first.encode("ascii"), hashlib.sha256).digest())


def token_variant(token: str, variant: str, secret: str | None = None, claims: dict | None = None) -> str | None:
    """A sign-in token as somebody who should not get in would send it. None: send no token at all. ValueError
    (with the reason) when this token cannot be made into that variant."""
    if variant == "valid":
        return token
    if variant == "none":
        return None
    if variant == "empty":
        return ""
    if variant == "garbage":
        return "not-a-token"
    if variant == "truncated":
        # Cut short. Of a signed token it is the signature that is cut, at a place where what is left is still
        # whole text: cut anywhere, a library may or may not refuse the leftover letters before the app is asked
        # anything, which made the same app pass on one run and fail on the next.
        head, dot, tail = token.rpartition(".")
        return head + dot + tail[:(len(tail) - 1) // 4 * 4] if token.count(".") == 2 and tail else token[:-4]
    if claims and "sub" in claims:
        claims = {**claims, "sub": str(claims["sub"])}      # who a token is for is always text
    parts = token.split(".")
    try:
        head, body = json.loads(_unb64(parts[0])), json.loads(_unb64(parts[1]))
        if len(parts) != 3 or not isinstance(head, dict) or not isinstance(body, dict):
            raise ValueError
    except (ValueError, IndexError):
        raise ValueError("the sign-in token is not a signed token of three parts") from None
    if variant == "altered":                # other claims, the old signature
        body.update(claims or {"sub": "1"})
        return ".".join([parts[0], _b64(json.dumps(body, separators=(",", ":")).encode()), parts[2]])
    if variant == "unsigned":               # says of itself that it needs no signature
        return _b64(json.dumps({**head, "alg": "none"}, separators=(",", ":")).encode()) + "." + parts[1] + "."
    if variant == "other-key":
        return _signed({"alg": "HS256", "typ": "JWT"}, {**body, **(claims or {})}, "k" * 32)
    if variant == "expired":
        if not secret:
            raise ValueError("the plan names no test secret to sign an expired token with")
        return _signed({"alg": "HS256", "typ": "JWT"}, {**body, "exp": int(time.time()) - 3600}, secret)
    raise ValueError("no such variant")


class _NotRun(Exception):
    pass


class Recorder:
    def __init__(self, scene: dict, app_dir: str, work: str):
        self.scene, self.app_dir, self.work = scene, app_dir, work
        self.world = os.path.join(work, "world")
        self.image = os.path.join(work, "image")
        self.logs = os.path.join(work, "logs")
        os.makedirs(self.logs, exist_ok=True)
        self.vars: dict = {"data": os.path.join(self.world, "data"), "secret": secrets.token_hex(24)}
        self.workers: dict[int, _Worker] = {}
        self.started = 0
        app = scene.get("app") or {}
        self.target = str(app.get("asgi") or "") + ("()" if app.get("factory") is True else "")
        self.cwd = os.path.join(app_dir, str(app.get("cwd") or "")) if app.get("cwd") else app_dir
        self.app_env = app.get("env") or {}
        state = scene.get("state") or {}
        self.sqlite = [str(p) for p in state.get("sqlite") or []]
        self.quiet = {str(t) for t in scene.get("quiet_tables") or []}
        self.home = ""
        self.folders = [str(p) for p in state.get("folders") or []]

    # -------------------------------------------------------------------------------------------- words
    def fill(self, value):
        """`{name}` in a text becomes what was saved under that name; a text that is one name becomes the value
        itself (a number stays a number); `{"$fill": n}` becomes n characters."""
        if isinstance(value, str):
            whole = NAME.fullmatch(value)
            if whole and whole.group(1) in self.vars:
                return self.vars[whole.group(1)]
            return NAME.sub(lambda m: str(self.vars[m.group(1)]) if m.group(1) in self.vars else m.group(0), value)
        if isinstance(value, list):
            return [self.fill(v) for v in value]
        if isinstance(value, dict):
            if set(value) <= {"$fill", "of"} and "$fill" in value:
                return str(value.get("of", "x"))[:1] * int(value["$fill"])
            return {k: self.fill(v) for k, v in value.items()}
        return value

    # -------------------------------------------------------------------------------------------- workers
    def worker(self, n: int) -> _Worker:
        w = self.workers.get(n)
        if w is not None and w.alive():
            return w
        if w is not None:
            w.end()
        env = dict(os.environ)
        # The sandbox keeps compiled Python in its temp folder (PYTHONPYCACHEPREFIX) and tells a test run not to
        # write any. The app is started many times here, so its copies may: the first start compiles the app and
        # its libraries, the later ones read that (a start takes a third of the time). Same code, same checks.
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        env.update({str(k): str(self.fill(v)) for k, v in self.app_env.items()})
        self.started += 1
        w = _Worker(self.target, self.cwd, env, os.path.join(self.logs, f"worker-{n}-{self.started}.txt"),
                    self.scene.get("names"))
        self.workers[n] = w
        if not w.hello.get("ready"):
            why = w.hello.get("error") or ("it did not start in time" if w.hello.get("timeout") else "it stopped while starting")
            w.end()
            del self.workers[n]
            raise _NotRun("the app could not be started: " + str(why)[:300])
        return w

    def stop_all(self, kill: bool = False) -> None:
        for w in self.workers.values():
            w.end() if kill else w.stop()
        self.workers.clear()

    # -------------------------------------------------------------------------------------------- state
    def look(self) -> dict:
        """The database's rows, the files of the folders the plan names, and whatever else is in the temp folder."""
        tables: dict = {}
        for path in self.sqlite:
            path = self.fill(path)
            if not os.path.isfile(path):
                continue
            try:
                conn = _REAL_CONNECT(path, timeout=5)
                try:
                    names = [r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                    for name in names:
                        quoted = '"' + name.replace('"', '""') + '"'
                        try:
                            rows = conn.execute(f"SELECT rowid, * FROM {quoted}").fetchall()   # nosec B608: a table's own name
                            tables[name] = {str(r[0]): hashlib.sha256(repr(r[1:]).encode()).hexdigest()[:16] for r in rows}
                        except sqlite3.Error:
                            rows = conn.execute(f"SELECT * FROM {quoted}").fetchall()   # nosec B608: a table's own name
                            tables[name] = {hashlib.sha256(repr(r).encode()).hexdigest()[:16]: "" for r in rows}
                finally:
                    conn.close()
            except sqlite3.Error as e:
                tables["(the database could not be read)"] = {type(e).__name__: ""}
        files: dict = {}
        folders = [os.path.realpath(self.fill(f)) for f in self.folders]
        quiet = {os.path.realpath(self.fill(p)) + end for p in self.sqlite for end in ("", *SIDE_FILES)}
        outside: dict = {}
        top = os.path.realpath(os.environ.get("LANTERN_SANDBOX_WRITABLE") or self.work)
        mine = (os.path.realpath(self.image), os.path.realpath(self.logs), os.path.join(top, "pycache"))
        for base, dirs, names in os.walk(top):
            dirs[:] = sorted(d for d in dirs if not os.path.join(base, d).startswith(mine))
            for name in sorted(names):
                full = os.path.join(base, name)
                if full in quiet or full.startswith(mine) or full.endswith(".observed.json") or full.endswith(".scene.json"):
                    continue
                inside = next((f for f in folders if full.startswith(f + os.sep)), None)
                try:
                    if inside is not None:
                        with open(full, "rb") as f:
                            files[os.path.relpath(full, self.vars["data"]).replace(os.sep, "/")] = \
                                hashlib.sha256(f.read(64 << 20)).hexdigest()[:16]
                    else:
                        st = os.lstat(full)
                        outside[os.path.relpath(full, top).replace(os.sep, "/")] = f"{st.st_size}:{st.st_mtime_ns}"
                except OSError:
                    continue
        return {"tables": tables, "files": files, "outside": outside}

    def mark(self, seen: dict) -> dict:
        """A snapshot as short marks: one for everything, one (`loud`) without the tables the plan says may change
        when a request is refused, one per table."""
        def short(x) -> str:
            return hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()[:16]
        tables = {name: short(rows) for name, rows in seen["tables"].items()}
        rest = [seen["files"], sorted(seen["outside"])]
        return {"all": short([tables, rest]), "tables": tables, "files": short(seen["files"]),
                "loud": short([{name: m for name, m in tables.items() if name not in self.quiet}, rest])}

    @staticmethod
    def changes(before: dict, after: dict) -> dict:
        out: dict = {}
        tables = {}
        for name in sorted(set(before["tables"]) | set(after["tables"])):
            a, b = before["tables"].get(name, {}), after["tables"].get(name, {})
            counts = [len(set(b) - set(a)), len(set(a) - set(b)), sum(1 for k in set(a) & set(b) if a[k] != b[k])]
            if any(counts):
                tables[name] = counts           # rows added, removed, changed
        if tables:
            out["tables"] = tables
        for zone in ("files", "outside"):
            a, b = before[zone], after[zone]
            new = sorted(set(b) - set(a))
            gone = sorted(set(a) - set(b))
            other = sorted(k for k in set(a) & set(b) if a[k] != b[k])
            if new or gone or other:
                out[zone] = {"added": new[:20], "removed": gone[:20], "changed": other[:20],
                             "count": len(new) + len(gone) + len(other)}
        return out

    def restore(self) -> None:
        self.stop_all(kill=True)
        shutil.rmtree(self.world)
        shutil.copytree(self.image, self.world)

    # -------------------------------------------------------------------------------------------- steps
    def body(self, req: dict) -> tuple[bytes, str | None]:
        if "json" in req:
            return json.dumps(self.fill(req["json"])).encode("utf-8"), "application/json"
        if "text" in req:
            return str(self.fill(req["text"])).encode("utf-8"), None
        if "bytes" in req:
            return b"x" * int(req["bytes"]), "application/octet-stream"
        if "base64" in req:
            return base64.b64decode(req["base64"]), "application/octet-stream"
        if "zip" in req:
            packed = io.BytesIO()
            with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as z:
                for entry in req["zip"]:
                    data = b"\0" * int(entry["zeros"]) if "zeros" in entry else str(entry.get("text", "")).encode("utf-8")
                    z.writestr(zipfile.ZipInfo(str(entry["name"])), data, zipfile.ZIP_DEFLATED)
            return packed.getvalue(), "application/zip"
        return b"", None

    def request(self, step: dict) -> dict:
        req = step["request"]
        n = int(step.get("worker", 0))
        headers = {str(k).lower(): str(self.fill(v)) for k, v in (req.get("headers") or {}).items()}
        person = (self.scene.get("people") or {}).get(step.get("as") or "")
        if step.get("as") and person is None:
            raise _NotRun("the plan names nobody called " + str(step["as"])[:60])
        if person:
            token = str(self.fill(person.get("token", "")))
            variant = step.get("token") or {}
            try:
                token = token_variant(token, str(variant.get("variant", "valid")),
                                      str(self.fill((self.scene.get("tokens") or {}).get("hs256_secret") or "")) or None,
                                      self.fill(variant.get("claims")))
            except ValueError as e:
                raise _NotRun(str(e)) from None
            if token is not None:
                scheme = str(person.get("scheme", "Bearer"))
                headers[str(person.get("header", "Authorization")).lower()] = (scheme + " " + token) if scheme else token
        body, kind = self.body(req)
        if kind and "content-type" not in headers:
            headers["content-type"] = kind
        if "content-length" not in headers and not req.get("no_length") and (body or req.get("method", "GET").upper() != "GET"):
            headers["content-length"] = str(len(body))
        headers.setdefault("host", "app.test")
        path = str(self.fill(req.get("path", "/")))
        if req.get("query"):
            path += "?" + urllib.parse.urlencode({k: self.fill(v) for k, v in req["query"].items()})
        w = self.worker(n)
        if w.paused:
            raise _NotRun("that copy of the app is still in the middle of an earlier request")
        w.blocked()
        fault = step.get("fault")
        ok = w.send({"op": "request", "method": str(req.get("method", "GET")), "path": path,
                     "headers": sorted(headers.items()), "body": base64.b64encode(body).decode("ascii"), "fault": fault})
        return self.answer(w, step, sent=ok)

    def answer(self, w: _Worker, step: dict, sent: bool = True) -> dict:
        reply = w.get(REQUEST_SECONDS + 10) if sent else {"died": True}
        seen: dict = {}
        if reply.get("paused"):
            w.paused = True
            seen["paused"] = True
        elif reply.get("died") or reply.get("timeout"):
            w.paused = False
            seen["died" if reply.get("died") else "timeout"] = True
            w.end()
        else:
            w.paused = False
            raw = base64.b64decode(reply.get("body") or "")
            seen.update(status=reply.get("status"), headers=dict(reply.get("headers") or []),
                        body=raw.decode("utf-8", "replace"), bytes=reply.get("bytes", len(raw)),
                        writes=reply.get("writes", 0), commits=reply.get("commits", 0))
            if reply.get("error"):
                seen["error"] = str(reply["error"])[:200]
            for key in ("asked", "began"):          # where it asked a name leads, and what it then set out for
                if reply.get(key):
                    seen[key] = reply[key]
            for name, where in (step.get("save") or {}).items():
                value = None
                if where.startswith("json:"):
                    try:
                        value = json.loads(seen["body"])
                        for key in where[5:].split("."):
                            value = value[int(key)] if isinstance(value, list) else value[key]
                    except (ValueError, KeyError, IndexError, TypeError):
                        value = None
                elif where.startswith("header:"):
                    value = seen["headers"].get(where[7:].lower())
                if value is not None:
                    self.vars[name] = value
        tried = w.blocked()
        if tried:
            seen["blocked"] = tried
        return seen

    def step(self, step: dict) -> dict:
        try:
            if "request" in step:
                return self.request(step)
            if "resume" in step:
                w = self.workers.get(int(step["resume"].get("worker", 0)))
                if w is None or not w.paused:
                    return {"skipped": "nothing was waiting"}
                return self.answer(w, step, sent=w.send({"op": "resume"}))
            if "sql" in step:
                run = step["sql"]
                conn = _REAL_CONNECT(str(self.fill(run["db"])), timeout=5)
                try:
                    row = conn.execute(str(run["run"]), tuple(self.fill(run.get("args") or []))).fetchone()
                    conn.commit()
                finally:
                    conn.close()
                if run.get("save") and row is not None:
                    self.vars[str(run["save"])] = row[0]
                return {"sql": True}
            if "restart" in step:
                self.stop_all(kill=step["restart"] == "kill")
                return {"restarted": True}
            return {"skipped": "not a step this version knows"}
        except _NotRun as e:
            return {"not_run": str(e)}
        except sqlite3.Error as e:
            return {"not_run": "the plan's own SQL failed: " + type(e).__name__}

    def steps(self, steps: list, start: dict) -> list:
        seen = []
        for step in steps:
            t = time.monotonic()
            got = self.step(step)
            now = self.look()
            got["state"] = self.mark(now)
            changed = self.changes(start, now)
            if changed:
                got["changes"] = changed
            if step.get("name"):
                got["name"] = str(step["name"])[:80]
            got["seconds"] = round(time.monotonic() - t, 3)
            seen.append(got)
            if got.get("not_run"):
                break
        return seen

    # -------------------------------------------------------------------------------------------- the run
    @staticmethod
    def failed(seen: list) -> int | None:
        """The first set-up step that did not work."""
        return next((i for i, s in enumerate(seen) if s.get("not_run") or s.get("died") or s.get("timeout")
                     or (isinstance(s.get("status"), int) and s["status"] >= 400)), None)

    def begin(self, probe: dict) -> tuple[dict, dict | None]:
        """The state a case starts from: the seed's, after the case's own set-up steps. With what to write down
        in place of the case when one of those steps did not work."""
        start = self.look()
        before = probe.get("arrange") or []
        if not before:
            return start, None
        seen = self.steps(before, start)
        bad = self.failed(seen)
        if bad is not None:
            why = seen[bad].get("not_run") or f"status {seen[bad].get('status')}"
            return start, {"not_run": f"the case's own set-up failed at step {bad + 1} ({str(why)[:200]})"}
        return self.look(), None

    def case(self, probe: dict, steps: list) -> list:
        """One case: what its steps save under a name is forgotten when it ends (the seed's names stay)."""
        kept = dict(self.vars)
        try:
            start, wrong = self.begin(probe)
            return [wrong] if wrong else self.steps(steps, start)
        finally:
            self.vars = kept

    def settle(self, fresh: bool = False) -> bool:
        """Back to the seed's state when the last case left anything else behind: a table the plan does not call
        quiet, a file, a copy of the app that stopped or still waits. `fresh`: whatever it left."""
        dirty = fresh or any(w.paused or not w.alive() for w in self.workers.values()) \
            or self.mark(self.look())["loud"] != self.home
        if dirty:
            self.restore()
        return dirty

    def sweep(self, probe: dict) -> dict:
        """One request made to fail in every place it can: first as it is (which says how many writes and commits
        it makes), then once per failure, each from the seed's state: the database refuses the n-th write or
        commit, the app is cut off before the n-th write or commit, and it is cut off when the work is done and
        the answer has not left. After each, the steps of `then` (somebody else's ordinary request)."""
        spec = probe["sweep"]
        step, then = spec["step"], list(spec.get("then") or [])

        def once(steps: list) -> list:
            seen = self.case(probe, steps)
            self.restore()
            return seen

        out: dict = {"plain": once([step])}
        last = out["plain"][-1]
        if last.get("not_run") or not isinstance(last.get("status"), int) or last["status"] >= 400:
            return out
        if then:
            out["then_alone"] = once(then)
        writes, commits = int(last.get("writes") or 0), int(last.get("commits") or 0)
        out.update(writes=writes, commits=commits)
        faults = [{"kind": kind, "on": on, "at": n} for kind in ("error", "kill")
                  for on, most in (("write", writes), ("commit", commits)) for n in range(1, min(most, SWEEP_MOST) + 1)]
        faults.append({"kind": "kill", "on": "answer", "at": 1})
        out["runs"] = [{"fault": fault, "steps": once([dict(step, fault=fault)] + then)} for fault in faults]
        return out

    def run(self, out_path: str, say=print) -> dict:
        t0 = time.monotonic()
        result: dict = {"version": 1, "guard": "on", "seed": {}, "probes": []}
        shutil.rmtree(self.world, ignore_errors=True)
        os.makedirs(self.vars["data"], exist_ok=True)
        seeded = self.steps(self.scene.get("seed") or [], self.look())
        self.stop_all()
        bad = self.failed(seeded)
        result["seed"] = {"ok": bad is None, "steps": [{k: v for k, v in s.items() if k != "body"} for s in seeded]}
        if bad is not None:
            result["seed"]["failed_at"] = bad
            result["seed"]["body"] = str(seeded[bad].get("body", ""))[:500]
        else:
            shutil.rmtree(self.image, ignore_errors=True)
            shutil.copytree(self.world, self.image)
            result["seed"]["state"] = self.mark(self.look())
            self.home = result["seed"]["state"]["loud"]
            probes = self.scene.get("probes") or []
            for i, probe in enumerate(probes, 1):
                t = time.monotonic()
                entry: dict = {"id": str(probe.get("id", i))}
                try:
                    if "sweep" in probe:
                        entry.update(sweep=self.sweep(probe), restored=True)
                    else:
                        entry["steps"] = self.case(probe, probe.get("steps") or [])
                        entry["restored"] = self.settle(bool(probe.get("fresh")))
                except Exception as e:      # one case that cannot be asked does not end the others
                    entry.pop("sweep", None)
                    entry.update(steps=[{"not_run": f"the case could not be asked ({type(e).__name__}: {e})"[:300]}],
                                 restored=True)
                    self.restore()
                entry["seconds"] = round(time.monotonic() - t, 3)
                result["probes"].append(entry)
                if i % 25 == 0 or i == len(probes):
                    say(f"behave: {i} of {len(probes)} cases asked")
                    self.write(out_path, result, t0)
        self.stop_all()
        return self.write(out_path, result, t0)

    def write(self, out_path: str, result: dict, t0: float) -> dict:
        result.update(seconds=round(time.monotonic() - t0, 3), workers_started=self.started)
        part = out_path + ".part"
        with open(part, "w", encoding="utf-8") as f:
            json.dump(result, f)
        os.replace(part, out_path)
        return result


def main(argv: list[str]) -> int:
    if argv[:1] == ["worker"]:
        return worker(*argv[1:3])
    if len(argv) != 3:
        print("usage: python -m lantern._behave_inside SCENE OUT APP")
        return 2
    if not _guarded():
        print("behave: the sandbox's guard is not in place, so the app was not started")
        return 97
    scene_path, out_path, app_dir = argv
    with open(scene_path, encoding="utf-8") as f:
        scene = json.load(f)
    work = os.path.join(os.path.dirname(os.path.abspath(out_path)), "behave")
    os.makedirs(work, exist_ok=True)
    recorder = Recorder(scene, app_dir, work)
    try:
        recorder.run(out_path)
    finally:
        recorder.stop_all(kill=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
