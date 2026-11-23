"""How Lantern starts the browser and ends it, on every system (`lantern._cdp`; a firm pass or fail, stage 5, the
browser checks: docs/browser.md).

A stand-in browser, a small Python program that speaks the browser's pipe (it reads what it is told from its
descriptor 3 and answers on its descriptor 4, each message JSON ending in a NUL), is started exactly as the browser
is: through the small program that becomes the browser on Linux and macOS, on Windows by `lantern.winspawn` inside a
Windows job. So every system shows that the browser gets the two ends of the pipe and nothing else of Lantern's, an
environment of the run's own, its profile as its folder (as `nobody` where Lantern runs as root), and that whatever
it started ends with it: also when it does not close when asked, never answers, or cannot have its sandbox. The real
browser is driven by tests/test_browse.py where LANTERN_TESTS_BROWSER names one."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from lantern import _cdp

# The Python that plays the browser: this one's own program (on Windows not a virtual environment's launcher, which
# would start the real one as a program of its own)
PYTHON = (getattr(sys, "_base_executable", None) or sys.executable) if sys.platform == "win32" \
    else os.path.realpath(sys.executable)
DOOR = 9                    # the browser's one way out; the stand-in never uses it

STAND_IN = r'''
import json, os, signal, subprocess, sys, time
mode, told = sys.argv[1], sys.argv[2:]
if mode == "sandbox":                   # what Chromium writes where it cannot have its sandbox, and it ends
    sys.stderr.write("[1:1:FATAL:zygote_host_impl_linux.cc(127)] No usable sandbox! You are probably running on\n")
    sys.stderr.flush()
    sys.exit(1)
if mode == "silent":                    # it never answers
    time.sleep(600)
    sys.exit(0)
if mode == "stay" and hasattr(signal, "SIGTERM") and os.name == "posix":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)       # and it does not end when asked to
child = None
if mode == "child":                     # a program of its own, which must end with it (on Windows one that leaves
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0    # its console and group: the job holds it anyway)
    child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(600)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=flags)


def descriptors():
    found = []
    for n in range(64):
        try:
            os.fstat(n)
        except OSError:
            continue
        found.append(n)
    return found


def say(message):
    data = json.dumps(message).encode("utf-8") + b"\0"
    while data:
        data = data[os.write(4, data):]


buf = b""
while True:
    chunk = os.read(3, 1 << 16)
    if not chunk:
        break
    buf += chunk
    while b"\0" in buf:
        raw, buf = buf.split(b"\0", 1)
        asked = json.loads(raw)
        n, method, params = asked.get("id"), asked.get("method"), asked.get("params") or {}
        if method == "Browser.getVersion":
            say({"id": n, "result": {"product": "StandIn/1.0", "told": told, "env": dict(os.environ),
                                      "cwd": os.getcwd(), "uid": os.getuid() if hasattr(os, "getuid") else None,
                                      "descriptors": descriptors(), "child": child.pid if child else None}})
        elif method == "Echo":
            say({"id": n, "result": params})
        elif method == "Fail":
            say({"id": n, "error": {"code": -32601, "message": "no such method"}})
        elif method == "Tell":
            say({"method": "StandIn.told", "params": params, "sessionId": asked.get("sessionId")})
        elif method == "Browser.close" and mode != "stay":
            say({"id": n, "result": {}})
            sys.exit(0)
'''


@pytest.fixture(scope="module")
def stand_in():
    """The stand-in's program, in a folder of its own that every user may read (the browser's user is `nobody`
    where these tests run as root)."""
    place = Path(tempfile.mkdtemp(prefix="lantern-stand-in-"))
    try:
        os.chmod(place, 0o755)
        program = place / "browser.py"
        program.write_text(STAND_IN, encoding="utf-8")
        os.chmod(program, 0o644)
        yield program
    finally:
        shutil.rmtree(place, ignore_errors=True)


class StandIn(_cdp.Browser):
    """The browser, played by the stand-in: started and ended by Lantern's own code, told what the browser is told."""

    def __init__(self, program: Path, mode: str, **kw):
        super().__init__(PYTHON, DOOR, **kw)
        self.program, self.mode = program, mode

    def command(self) -> list[str]:
        return [PYTHON, "-I", "-S", str(self.program), self.mode, *self.switches()]


def _alive(pid: int) -> bool:
    if sys.platform == "win32":   # asked of Windows itself (os.kill would end the process there)
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype, k32.OpenProcess.argtypes = ctypes.c_void_p, [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = k32.OpenProcess(0x1000, 0, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_uint32(0)
        ok = k32.GetExitCodeProcess(handle, ctypes.byref(code))
        k32.CloseHandle(handle)
        return bool(ok) and code.value == 259      # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except OSError:
        return True


def _ended(pid: int, seconds: float = 15) -> bool:
    end = time.monotonic() + seconds
    while _alive(pid):
        if time.monotonic() > end:
            return False
        time.sleep(0.05)
    return True


def _same(a, b) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _left_nothing(b: _cdp.Browser) -> None:
    assert b.profile is not None and not os.path.lexists(b.profile), b.profile
    assert b.lines is not None and not os.path.lexists(b.lines.parent), b.lines
    assert not b.alive()


def test_the_browser_is_told_what_lantern_starts_it_with_and_never_to_drop_its_sandbox(tmp_path):
    b = _cdp.Browser(str(tmp_path / "chrome"), 4321)
    b.profile = tmp_path / "profile"
    told = b.switches()
    assert told[:len(_cdp.ARGS)] == list(_cdp.ARGS)
    assert told[len(_cdp.ARGS):] == [f"--user-data-dir={tmp_path / 'profile'}", "--proxy-server=http://127.0.0.1:4321",
                                     "--proxy-bypass-list=<-loopback>", "about:blank"]
    assert b.command() == [str(tmp_path / "chrome"), *told]
    assert "--remote-debugging-pipe" in told and not any(s.startswith("--remote-debugging-port") for s in told)
    assert not any("sandbox" in s for s in told), told          # never --no-sandbox, nor anything else about it


def test_on_windows_the_browser_is_handed_its_descriptors_the_way_its_c_library_reads_them():
    from lantern.winspawn import FDEV, FOPEN, FPIPE
    ends = {0: 10, 1: 11, 2: 12, 3: 13, 4: 14}          # NUL to read, NUL to write, its lines, the pipe's two ends
    assert _cdp._windows_fds(ends, lambda fd: fd * 4) == {
        0: (40, FOPEN | FDEV), 1: (44, FOPEN | FDEV), 2: (48, FOPEN), 3: (52, FOPEN | FPIPE), 4: (56, FOPEN | FPIPE)}
    with pytest.raises(KeyError):
        _cdp._windows_fds({0: 10, 1: 11, 2: 12, 3: 13}, lambda fd: fd)   # the browser has no pipe without its 4


def test_the_browser_gets_the_pipe_and_nothing_else_of_lanterns(stand_in, monkeypatch):
    monkeypatch.setenv("LANTERN_NOT_HANDED_ON", "this program's own")
    got, heard = [], threading.Event()

    def events(method, params, session):
        got.append((method, params, session))
        heard.set()
    b = StandIn(stand_in, "answer", events=events)
    try:
        said = b.start()
        assert said["product"] == "StandIn/1.0" and b.alive()
        assert said["told"] == b.switches()
        assert said["descriptors"] == [0, 1, 2, 3, 4], said["descriptors"]    # the pipe's two ends and nothing more
        assert _same(said["cwd"], b.profile)
        env = {k.upper(): v for k, v in said["env"].items()}
        if sys.platform == "win32":
            want = {n.upper() for n in _cdp.WINDOWS_KEPT if os.environ.get(n)} | {
                "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"}
            assert set(env) == want, sorted(env)
            assert _same(env["USERPROFILE"], b.profile) and _same(env["TEMP"], b.profile / "tmp")
            assert all(os.path.isdir(p) for p in (env["TEMP"], env["APPDATA"], env["LOCALAPPDATA"]))
        else:
            want = {"PATH", "HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "LANG", "DBUS_SESSION_BUS_ADDRESS"}
            extra = set(env) - want
            assert want <= set(env) and extra <= ({"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()), sorted(env)
            assert _same(env["HOME"], b.profile) and env["DBUS_SESSION_BUS_ADDRESS"] == "disabled:"
            assert said["uid"] == (_cdp.NOBODY if os.geteuid() == 0 else os.getuid())
        assert "LANTERN_NOT_HANDED_ON" not in env
        assert b.call("Echo", {"a": [1, "two"]}) == {"a": [1, "two"]}
        with pytest.raises(_cdp.CallError, match="no such method"):
            b.call("Fail")
        b.send("Tell", {"n": 1}, "S1")
        assert heard.wait(10) and got == [("StandIn.told", {"n": 1}, "S1")]
    finally:
        b.close()
    assert b.proc.returncode == 0            # it closed when it was asked to
    _left_nothing(b)
    with pytest.raises(_cdp.BrowserError):
        b.call("Echo")


def test_what_the_browser_started_ends_with_it(stand_in):
    b = StandIn(stand_in, "child")
    try:
        child = b.start()["child"]
        assert isinstance(child, int) and _alive(child)
    finally:
        b.close()
    assert _ended(child), f"the program the browser started is still running: {child}"
    _left_nothing(b)


def test_a_browser_that_does_not_close_when_asked_is_ended(stand_in, monkeypatch):
    monkeypatch.setattr(_cdp, "CLOSE_SECONDS", 1)
    b = StandIn(stand_in, "stay")
    try:
        assert b.start()["product"] == "StandIn/1.0"
    finally:
        t0 = time.monotonic()
        b.close()
    assert time.monotonic() - t0 < 15
    assert _ended(b.proc.pid)
    _left_nothing(b)


def test_a_browser_that_never_answers_is_not_used(stand_in, monkeypatch):
    monkeypatch.setattr(_cdp, "START_SECONDS", 3)
    monkeypatch.setattr(_cdp, "CLOSE_SECONDS", 1)
    b = StandIn(stand_in, "silent")
    with pytest.raises(_cdp.BrowserError) as e:
        b.start()
    assert e.value.why == "browser-failed"
    assert _ended(b.proc.pid)
    _left_nothing(b)


def test_a_browser_that_cannot_have_its_sandbox_says_so_and_is_not_used(stand_in):
    b = StandIn(stand_in, "sandbox")
    with pytest.raises(_cdp.BrowserError) as e:
        b.start()
    assert e.value.why == "no-browser-sandbox", (e.value.why, e.value.detail)
    _left_nothing(b)


def test_a_browser_that_cannot_be_started_leaves_nothing(tmp_path):
    b = _cdp.Browser(str(tmp_path / ("no-browser.exe" if sys.platform == "win32" else "no-browser")), DOOR)
    with pytest.raises(_cdp.BrowserError) as e:
        b.start()
    assert e.value.why == "browser-failed"
    _left_nothing(b)
