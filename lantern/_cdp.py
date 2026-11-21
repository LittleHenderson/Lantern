"""Lantern's own driver for a browser of the Chromium family (Chrome, Chromium, Edge, Brave), standard library only
(a firm pass or fail, stage 5, the browser checks: docs/browser.md).

The browser is spoken to through a pipe (`--remote-debugging-pipe`: it reads what it is told from its descriptor 3
and writes its answers to its descriptor 4, each message JSON ending in a NUL), never through a port: no program on
this computer, and no page's script, can reach its controls. It keeps its own sandbox: Lantern never starts it with
that sandbox switched off, and a browser that cannot have it here does not start (`BrowserError` "no-browser-sandbox").
As root it is started as `nobody` (uid 65534), as an ordinary user never needs a switch to stay sandboxed. It gets a
profile of the run's own, empty, removed afterwards, an environment of a few variables (no proxy, display or bus of
the person's), and one way out: the door it is handed (`Browser(door=...)`), with no name looked up by itself.

POSIX: Python starts a small program of its own (`TRAMPOLINE`, `python -I -S`) under the browser's user, which puts
the two ends of the pipes at 3 and 4 and then becomes the browser. Windows: Chrome reads the same pipe from the
handles it is given with `--remote-debugging-io-pipes` (to come)."""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

START_SECONDS = 30          # the browser has this long to answer its first question
CALL_SECONDS = 30           # and this long for any other
CLOSE_SECONDS = 5           # to end after it was asked to
MOST_MESSAGE = 256 << 20    # bytes of one message from the browser; a longer one ends the run
NOBODY = 65534

# Becomes the browser, with the two ends of the pipes at 3 and 4 (`a`, `b` are above 9, so neither is 3 or 4).
TRAMPOLINE = ("import os,sys\n"
              "a,b=int(sys.argv[1]),int(sys.argv[2])\n"
              "os.dup2(a,3)\n"
              "os.dup2(b,4)\n"
              "os.close(a)\n"
              "os.close(b)\n"
              "os.execv(sys.argv[3],sys.argv[3:])\n")

# How the browser is started: headless, no first-run pages, none of its own services that call home (each of those
# would be refused at the door anyway, and written down as the browser's own), no name looked up by itself, no
# connection round the door (WebRTC), no prompt, no stored password, no sound.
ARGS = (
    "--headless=new",
    "--remote-debugging-pipe",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-client-side-phishing-detection",
    "--disable-domain-reliability",
    "--disable-breakpad",
    "--disable-features=OptimizationHints,OptimizationGuideModelDownloading,MediaRouter,DialMediaRouteProvider,"
    "Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions",
    "--no-pings",
    "--metrics-recording-only",
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-quic",
    "--deny-permission-prompts",
    "--password-store=basic",
    "--use-mock-keychain",
    "--mute-audio",
    "--hide-scrollbars",
    "--window-size=1280,900",
)
# What the browser's own lines say when it cannot have its sandbox here (Linux: no user namespaces for this user and
# no set-uid helper; the words of Chromium's own message)
NO_SANDBOX_WORDS = ("No usable sandbox", "sandbox_host_linux", "Failed to move to new namespace",
                    "credentials.cc", "zygote_host_impl_linux")


class BrowserError(Exception):
    """The browser could not be used: `why` is one of browse.WHY_NOT's reasons."""

    def __init__(self, why: str, detail: str = ""):
        super().__init__(why)
        self.why = why
        self.detail = detail


def _high(fd: int) -> int:
    """`fd` again, at 10 or above and closed on exec, and the old number closed (POSIX)."""
    import fcntl                # not on Windows, where this module is imported too and the browser gets no pipe yet
    high = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(fd)
    return high


def _base_python() -> str:
    """This Python's own program, not a link of a virtual environment in a folder the browser's user may not
    enter: the small program that becomes the browser needs nothing but Python itself (`-I -S`)."""
    return os.path.realpath(sys.executable)


class Browser:
    """One browser, started by `start()` and ended by `close()`. `call()` asks it something and waits for the
    answer; `send()` asks without waiting; `events` is a callable given each event (method, params, session) on a
    thread of its own, which may call `call()`."""

    def __init__(self, path: str, door: int, *, events=None, log=None):
        self.path = path
        self.door = door
        self.events = events
        self.log = log or (lambda line: None)
        self.proc: subprocess.Popen | None = None
        self.profile: Path | None = None
        self.lines: Path | None = None
        self._out = -1                  # Lantern writes here (the browser's 3)
        self._in = -1                   # and reads here (the browser's 4)
        self._write = threading.Lock()
        self._ids = 0
        self._ids_lock = threading.Lock()
        self._waiting: dict[int, list] = {}
        self._queue: queue.Queue = queue.Queue()
        self._closed = threading.Event()
        self._threads: list[threading.Thread] = []
        self.as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
        self.version: dict = {}

    # ------------------------------------------------------------------------------------------------ start, end
    def start(self) -> dict:
        """Start the browser and ask it who it is (`Browser.getVersion`). BrowserError when it cannot be used."""
        if os.name == "nt":
            raise BrowserError("browser-failed", "this version of Lantern drives the browser on Linux and macOS")
        self.profile = Path(tempfile.mkdtemp(prefix="lantern-browser-"))
        own = Path(tempfile.mkdtemp(prefix="lantern-browser-lines-"))
        self.lines = own / "browser.txt"
        for sub in ("tmp", ".config", ".cache"):
            (self.profile / sub).mkdir()
        if self.as_nobody:
            for place in (self.profile, *(self.profile / s for s in ("tmp", ".config", ".cache"))):
                os.chown(place, NOBODY, NOBODY)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.profile), "TMPDIR": str(self.profile / "tmp"),
               "XDG_CONFIG_HOME": str(self.profile / ".config"), "XDG_CACHE_HOME": str(self.profile / ".cache"),
               "LANG": "C.UTF-8", "DBUS_SESSION_BUS_ADDRESS": "disabled:"}
        args = [self.path, *ARGS, f"--user-data-dir={self.profile}",
                f"--proxy-server=http://127.0.0.1:{self.door}", "--proxy-bypass-list=<-loopback>", "about:blank"]
        to_browser, from_lantern = os.pipe()        # the browser reads `to_browser` as its 3
        from_browser, to_lantern = os.pipe()        # and writes `to_lantern` as its 4
        a, b = _high(to_browser), _high(to_lantern)
        err = os.open(self.lines, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            extra = {"user": NOBODY, "group": NOBODY, "extra_groups": []} if self.as_nobody else {}
            self.proc = subprocess.Popen([_base_python(), "-I", "-S", "-c", TRAMPOLINE, str(a), str(b), *args],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                                         pass_fds=(a, b), env=env, cwd=str(self.profile), start_new_session=True,
                                         **extra)
        except OSError as e:
            for fd in (a, b, from_lantern, from_browser):
                os.close(fd)
            os.close(err)
            self._tidy()
            raise BrowserError("browser-failed", f"the browser could not be started ({e.strerror or e})") from e
        for fd in (a, b, err):
            os.close(fd)
        self._out, self._in = from_lantern, from_browser
        for target in (self._read, self._dispatch):
            t = threading.Thread(target=target, daemon=True, name="lantern-browser")
            t.start()
            self._threads.append(t)
        try:
            self.version = self.call("Browser.getVersion", timeout=START_SECONDS)
        except BrowserError:
            said = self.said()
            self.close()
            if any(w in said for w in NO_SANDBOX_WORDS):
                raise BrowserError("no-browser-sandbox", said[-600:]) from None
            raise BrowserError("browser-failed", said[-600:]) from None
        return self.version

    def said(self) -> str:
        """The last of what the browser wrote on its own lines (stderr), for Lantern's own reading of why it
        stopped; never shown as a reason."""
        try:
            with open(self.lines, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 65536))
                return f.read().decode("utf-8", "replace")
        except (OSError, TypeError):
            return ""

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None and not self._closed.is_set()

    def close(self) -> None:
        """End the browser and everything it started, and remove its profile."""
        if self.proc is not None:
            if self.proc.poll() is None and not self._closed.is_set():
                try:
                    self.send("Browser.close")
                except BrowserError:
                    pass
            try:
                self.proc.wait(timeout=CLOSE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.proc.pid, sig)
                except (ProcessLookupError, PermissionError, OSError):
                    break
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    continue
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)     # what the browser started and left in its group
            except (ProcessLookupError, PermissionError, OSError):
                pass
        self._closed.set()
        for fd in (self._out, self._in):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._out = self._in = -1
        self._queue.put(None)
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(timeout=5)
        self._fail_waiting()
        self._tidy()

    def _tidy(self) -> None:
        from . import removal
        for place in (self.profile, self.lines.parent if self.lines else None):
            if place is not None and os.path.lexists(place):
                why = removal.remove(place)
                if why:
                    self.log(f"browser: a folder of the run could not be removed ({place}): {why}")
                    removal.note(place)

    # ------------------------------------------------------------------------------------------------ messages
    def _write_message(self, n: int, method: str, params: dict | None, session: str | None) -> None:
        message = {"id": n, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        data = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\0"
        with self._write:
            if self._out < 0 or self._closed.is_set():
                raise BrowserError("browser-failed", "the browser has ended")
            view = memoryview(data)
            try:
                while view:
                    view = view[os.write(self._out, view):]
            except OSError as e:
                raise BrowserError("browser-failed", f"the browser has ended ({e.strerror})") from e

    def send(self, method: str, params: dict | None = None, session: str | None = None) -> int:
        """Ask without waiting for the answer; the number of the question."""
        with self._ids_lock:
            self._ids += 1
            n = self._ids
        self._write_message(n, method, params, session)
        return n

    def call(self, method: str, params: dict | None = None, session: str | None = None,
             timeout: float = CALL_SECONDS) -> dict:
        """Ask and wait for the answer: its `result`. BrowserError when the browser ended or did not answer in
        time; CallError when it answered with an error."""
        slot: list = [threading.Event(), None]
        with self._ids_lock:
            self._ids += 1
            n = self._ids
            self._waiting[n] = slot
        try:
            self._write_message(n, method, params, session)
        except BrowserError:
            with self._ids_lock:
                self._waiting.pop(n, None)
            raise
        if not slot[0].wait(timeout):
            with self._ids_lock:
                self._waiting.pop(n, None)
            raise BrowserError("browser-failed", f"the browser did not answer {method} in time")
        answer = slot[1]
        if answer is None:
            raise BrowserError("browser-failed", "the browser has ended")
        if "error" in answer:
            raise CallError(method, answer["error"])
        return answer.get("result") or {}

    def _read(self) -> None:
        buf = bytearray()
        while True:
            try:
                chunk = os.read(self._in, 1 << 20)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while True:
                end = buf.find(b"\0")
                if end < 0:
                    break
                raw = bytes(buf[:end])
                del buf[:end + 1]
                try:
                    message = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(message, dict):
                    self._take(message)
            if len(buf) > MOST_MESSAGE:
                self.log("browser: a message longer than Lantern reads; the browser is ended")
                break
        self._closed.set()
        self._fail_waiting()
        self._queue.put(None)

    def _take(self, message: dict) -> None:
        n = message.get("id")
        if isinstance(n, int):
            with self._ids_lock:
                slot = self._waiting.pop(n, None)
            if slot is not None:            # an answer nobody waits for is one to `send`
                slot[1] = message
                slot[0].set()
            return
        method = message.get("method")
        if isinstance(method, str):
            self._queue.put((method, message.get("params") or {}, message.get("sessionId")))

    def _fail_waiting(self) -> None:
        with self._ids_lock:
            slots = list(self._waiting.values())
            self._waiting.clear()
        for slot in slots:
            slot[0].set()

    def _dispatch(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            if self.events is not None:
                try:
                    self.events(*item)
                except Exception as e:  # noqa: BLE001 - one event Lantern could not handle ends nothing else
                    self.log(f"browser: an event was not handled ({type(e).__name__}: {e})"[:300])


class CallError(Exception):
    """The browser answered a question with an error."""

    def __init__(self, method: str, error):
        message = error.get("message") if isinstance(error, dict) else str(error)
        super().__init__(f"{method}: {message}")
        self.method = method
        self.message = str(message)
