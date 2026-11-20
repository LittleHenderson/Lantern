"""What the sealed box lets a project's tests do on Windows, and what it keeps from them (a firm pass or fail,
stage 4, 2026-11-20).

Until this stage three kinds of honest tests could not run in the box on Windows, where they run at home and in
the box on Linux (found 2026-11-11, `lantern.sandbox` "Known and not fixed"):
* a test that waits on several things at once: an event loop, which every async test starts, and every test of a
  FastAPI or Starlette app through its test client. Windows has no call that makes a pair of connected sockets,
  so Python builds the pair a loop wakes itself with from a listener on this computer, which the guard refuses;
* a test that starts its own server and calls it, in the same program or in another program of the tests;
* an app started by one of Lantern's own drivers, so the behaviour checks (`lantern behave`) start nothing there.
Each test of those here is beside twins that reach for something outside the run: another program's listener,
datagram socket or pipe, and an address outside this computer. What is outside must stay out of reach on every
system, through a plain socket and through an event loop of either kind, and on Windows each try must be named in
what the run says it refused: there the loop Windows uses by default connects with calls Python tells no hook
about, and a box that let a loop start without covering them would let it connect unseen. Windows has two more
ways to other programs and other computers that look like files: a pipe is opened by a file's name, and a share
of a computer on the network is a file's place (`\\\\computer\\share\\file`), which Windows reaches over the
network when a program only opens, looks at or lists it.

The same tests run on every system, but for those two. Where a run has a network of its own (Linux) the twins'
tries end in that network, which holds nothing of this computer's, and the guard names only the address outside;
where it has none and is not Windows, nothing on this computer is let through, as before."""
import json
import os
import re
import secrets
import socket
import sys
from pathlib import Path

import pytest

from lantern import _jail, sandbox
from test_behave import FETCHES_ANYTHING, INSIDE, PREVIEW_PLAN, _by_case, _expected, _repo, _run
from test_sandbox import _guard_alone

WINDOWS = sys.platform == "win32"
# A network of the run's own: the restricted subprocess on a Linux that lets the launcher make one.
OWN = sys.platform.startswith("linux") and not sandbox.own_network()
# Where a test may start its own server and call it.
SERVES = OWN or WINDOWS
COMMAND = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]
ONLY_WINDOWS = pytest.mark.skipif(not WINDOWS, reason="named pipes and the network's shares are Windows' own")
# A share of a computer outside, at an address kept for examples, which no computer answers.
SHARE = "\\\\192.0.2.1\\share"
# Ends of the other program's pipe that a client may open, before anybody came to them.
PIPE_ENDS = 12


def _project(folder: Path, source: str, outside: dict | None = None) -> Path:
    (folder / "tests").mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    if outside is not None:
        (folder / "tests" / "outside.json").write_text(json.dumps(outside), encoding="utf-8")
    return folder


def _box(repo: Path) -> tuple[dict, list[str]]:
    lines: list[str] = []
    r = sandbox.run(repo, COMMAND, log=lines.append, backend="subprocess")
    return r, lines


# `pytest -q` prints a test's dot where the next test begins to print, so a try's line may come after dots.
SAID = re.compile(r"[.sFExX]*(refused|failed|done): (.+)$")


def _said(lines: list[str]) -> dict[str, str]:
    """What the project's own tests printed about each try: `<how>: <what>`."""
    out = {}
    for line in lines:
        m = SAID.match(line)
        if m:
            out[m.group(2).strip()] = m.group(1)
    return out


def _named(r: dict) -> list[str]:
    return [b["what"] for b in r["blocked"] if b["kind"] == "network"]


class _Outside:
    """Another program of this computer: a listener, a datagram socket and, on Windows, a pipe with ends a client
    may open, none of them the run's. Afterwards it says whether anybody came."""

    def __enter__(self):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.tcp.setblocking(False)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.setblocking(False)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as free:
            free.bind(("127.0.0.1", 0))
            self.free = free.getsockname()[1]      # a port nobody listens at once this is closed
        self.pipe, self.ends, self.spellings = None, [], {}
        if WINDOWS:
            import _winapi
            tail = "lantern-outside-" + secrets.token_hex(8)
            self.pipe = "\\\\.\\pipe\\" + tail
            # The same pipe under the other names Windows gives it.
            self.spellings = {"written with forward slashes": "//./pipe/" + tail,
                              "by this computer's name on the network": "\\\\localhost\\pipe\\" + tail,
                              "by the system's own name for it": "\\\\?\\GLOBALROOT\\Device\\NamedPipe\\" + tail}
            for n in range(PIPE_ENDS):
                self.ends.append(_winapi.CreateNamedPipe(
                    self.pipe, _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
                    | (_winapi.FILE_FLAG_FIRST_PIPE_INSTANCE if n == 0 else 0),
                    _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
                    _winapi.PIPE_UNLIMITED_INSTANCES, 4096, 4096, _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL))
        return self

    def where(self) -> dict:
        disk = ""
        if WINDOWS:
            drive, rest = os.path.splitdrive(sys.executable)
            disk = "\\\\localhost\\" + drive[:1] + "$" + rest     # this computer's own disk, the network's way
        return {"tcp": self.tcp.getsockname()[1], "udp": self.udp.getsockname()[1], "free": self.free,
                "pipe": self.pipe, "spellings": self.spellings, "share": SHARE, "disk": disk}

    def came(self) -> list[str]:
        came = []
        while True:
            try:
                self.tcp.accept()[0].close()
            except BlockingIOError:
                break
            came.append("a connection to the listener")
        try:
            self.udp.recvfrom(64)
            came.append("a datagram")
        except (BlockingIOError, ConnectionResetError):
            pass
        if self.ends:
            import _winapi
            for end in self.ends:
                try:
                    ov = _winapi.ConnectNamedPipe(end, overlapped=True)
                    nobody = ov.GetOverlappedResult(False)[1] == 996     # ERROR_IO_INCOMPLETE
                except OSError:          # ERROR_NO_DATA: somebody came and has gone
                    nobody = False
                if nobody:
                    ov.cancel()
                else:
                    came.append("a connection to the pipe")
        return came

    def __exit__(self, *exc):
        self.tcp.close()
        self.udp.close()
        if self.ends:
            import _winapi
            for end in self.ends:
                _winapi.CloseHandle(end)


# ------------------------------------------------------------------------------- waiting on several things at once
WAITS = '''
import asyncio, sys, threading
import pytest

# The loop a project gets unless it asks (on Windows the one that uses the system's own way of waiting), and on
# Windows also the other one a project may ask for.
LOOPS = [None] + ([asyncio.SelectorEventLoop] if sys.platform == "win32" else [])

@pytest.fixture(params=LOOPS, ids=lambda f: "default" if f is None else "selector")
def run(request):
    def go(main):
        with asyncio.Runner(loop_factory=request.param) as runner:
            return runner.run(main())
    go.selector = request.param is not None
    return go

def test_a_thread_wakes_the_loop(run):
    async def main():
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        threading.Thread(target=lambda: loop.call_soon_threadsafe(done.set_result, "woken")).start()
        return await asyncio.wait_for(done, 20)
    assert run(main) == "woken"

def test_tasks_wait_together(run):
    async def one(n):
        await asyncio.sleep(0.01 * n)
        return n
    async def main():
        return await asyncio.gather(*(one(n) for n in range(5)))
    assert run(main) == [0, 1, 2, 3, 4]

def test_a_program_started_from_the_loop_answers(run):
    if run.selector and sys.platform == "win32":
        pytest.skip("the selector loop starts no programs on Windows")
    async def main():
        child = await asyncio.create_subprocess_exec(sys.executable, "-c", "print('child')",
                                                     stdout=asyncio.subprocess.PIPE)
        out, _ = await child.communicate()
        return out.decode().strip()
    assert run(main) == "child"
'''


def test_a_test_that_waits_on_several_things_at_once_runs_in_the_box(tmp_path):
    r, lines = _box(_project(tmp_path / "waits", WAITS))
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == [], r["blocked"]


# A try: each of the project's tests below prints how it ended (`refused` by the box, `failed` for another reason,
# `done`), and the harness looks at its own listener, datagram socket and pipe afterwards.
TRIES = '''
import json, socket, sys
from pathlib import Path

OUT = json.loads((Path(__file__).parent / "outside.json").read_text(encoding="utf-8"))

def say(what, how):
    print("%s: %s" % (how, what), flush=True)

def ended(what, e):
    why = getattr(e, "reason", None)          # what urllib was handed by the socket it could not connect
    say(what, "refused" if isinstance(e, PermissionError) or isinstance(why, PermissionError) else "failed")

def close(got):
    for one in (got if isinstance(got, tuple) else (got,)):
        shut = getattr(one, "close", None)
        if shut is not None:
            shut()

def tried(what, do):
    try:
        got = do()
    except OSError as e:
        ended(what, e)
    else:
        say(what, "done")
        close(got)
'''
LOOP_TRIES = TRIES + '''
import asyncio, pytest

LOOPS = [None] + ([asyncio.SelectorEventLoop] if sys.platform == "win32" else [])

async def atried(what, make):
    try:
        got = await make()
    except OSError as e:
        ended(what, e)
    else:
        say(what, "done")
        close(got)

@pytest.mark.parametrize("factory", LOOPS, ids=lambda f: "default" if f is None else "selector")
def test_what_an_event_loop_reaches_for(factory):
    kind = "default" if factory is None else "selector"
    async def main():
        loop = asyncio.get_running_loop()
        tcp, udp = OUT["tcp"], OUT["udp"]
        await atried(kind + ": another program's listener", lambda: asyncio.open_connection("127.0.0.1", tcp))
        async def by_socket():
            s = socket.socket()
            s.setblocking(False)
            try:
                await loop.sock_connect(s, ("127.0.0.1", tcp))
            finally:
                s.close()
        await atried(kind + ": another program's listener, by the socket", by_socket)
        await atried(kind + ": an address outside", lambda: asyncio.open_connection("192.0.2.1", 9))
        async def datagram():
            t, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", udp))
            t.sendto(b"x")
            await asyncio.sleep(0.2)
            t.close()
        await atried(kind + ": another program's datagram socket", datagram)
        async def sendto():
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setblocking(False)
            try:
                await loop.sock_sendto(u, b"x", ("127.0.0.1", udp))
            finally:
                u.close()
        await atried(kind + ": a datagram to another program", sendto)
        if OUT["pipe"] and hasattr(loop, "create_pipe_connection"):
            await atried(kind + ": another program's pipe",
                         lambda: loop.create_pipe_connection(asyncio.Protocol, OUT["pipe"]))
    with asyncio.Runner(loop_factory=factory) as runner:
        runner.run(main())
'''
LOOP_OUTSIDE = ("another program's listener", "another program's listener, by the socket", "an address outside",
                "another program's datagram socket", "a datagram to another program")


def test_what_an_event_loop_reaches_for_outside_the_run_is_out_of_reach_and_named(tmp_path):
    with _Outside() as outside:
        where = outside.where()
        r, lines = _box(_project(tmp_path / "tries", LOOP_TRIES, where))
        came = outside.came()
    said = _said(lines)
    assert came == [], (came, said, r["output_tail"])
    loops = ["default", "selector"] if WINDOWS else ["default"]
    tries = [f"{kind}: {what}" for kind in loops for what in LOOP_OUTSIDE]
    if WINDOWS:
        tries += ["default: another program's pipe"]
    assert sorted(said) == sorted(tries), (said, r["output_tail"])
    named = _named(r)
    assert any("192.0.2.1" in what for what in named), r["blocked"]
    if OWN:
        # The run's own network holds nothing of this computer's; the guard names the address outside.
        assert said["default: an address outside"] == "refused", said
        return
    assert set(said.values()) == {"refused"}, said
    assert any(str(where["tcp"]) in what for what in named), r["blocked"]
    # A datagram is named by its address, or, where a doorman of the run's own makes no datagram socket at all
    # (Linux with no network of the run's own), by the doorman's line.
    assert any(str(where["udp"]) in what or what == _jail.SAID["udp"][:200] for what in named), r["blocked"]
    if WINDOWS:
        assert any(outside.pipe in what for what in named), r["blocked"]


# ---------------------------------------------------------------------------------------- a test's own server
SERVERS = '''
import asyncio, http.server, subprocess, sys, threading, urllib.request
import pytest

class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

def test_a_server_in_a_thread_of_the_test_answers():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/" % server.server_address[1], timeout=20) as page:
            assert page.read() == b"hello"
    finally:
        server.shutdown()
        server.server_close()

LOOPS = [None] + ([asyncio.SelectorEventLoop] if sys.platform == "win32" else [])

@pytest.mark.parametrize("factory", LOOPS, ids=lambda f: "default" if f is None else "selector")
def test_a_server_on_the_event_loop_answers(factory):
    async def main():
        async def echo(reader, writer):
            writer.write(await reader.readline())
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"ping\\n")
        await writer.drain()
        line = await reader.readline()
        writer.close()
        server.close()
        await server.wait_closed()
        return line
    with asyncio.Runner(loop_factory=factory) as runner:
        assert runner.run(main()) == b"ping\\n"

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)

class Heard(asyncio.DatagramProtocol):
    def __init__(self):
        self.heard = asyncio.get_running_loop().create_future()
    def datagram_received(self, data, addr):
        if not self.heard.done():
            self.heard.set_result(data)

@pytest.mark.parametrize("factory", LOOPS, ids=lambda f: "default" if f is None else "selector")
def test_a_datagram_server_on_the_event_loop_answers(factory):
    async def main():
        loop = asyncio.get_running_loop()
        server, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        client, heard = await loop.create_datagram_endpoint(Heard, remote_addr=server.get_extra_info("sockname"))
        try:
            client.sendto(b"ping")
            return await asyncio.wait_for(heard.heard, 20)
        finally:
            client.close()
            server.close()
    with asyncio.Runner(loop_factory=factory) as runner:
        assert runner.run(main()) == b"ping"

SERVER = """
import http.server
class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", 0), Hello)
print(server.server_address[1], flush=True)
server.handle_request()
"""

def test_a_server_in_another_program_of_the_tests_answers():
    child = subprocess.Popen([sys.executable, "-c", SERVER], stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=20) as page:
            assert page.read() == b"hello"
    finally:
        assert child.wait(timeout=30) == 0
'''


def test_a_test_with_its_own_server_runs_in_the_box(tmp_path):
    r, lines = _box(_project(tmp_path / "serves", SERVERS))
    if SERVES:
        assert r["returncode"] == 0, r["output_tail"]
        assert r["blocked"] == [], r["blocked"]
    else:
        # No network of the run's own, and a system where nothing on this computer is let through.
        assert r["returncode"] != 0, r["output_tail"]
        assert any(what.startswith("network bind") for what in _named(r)), r["blocked"]


# A program's own listener and datagram socket open no other door: another program's listener and datagram
# socket, every address at once (so the network around this computer too), a port somebody else holds, and a port
# the test chose itself rather than one the system picks.
PLAIN_TRIES = TRIES + '''
import urllib.request

def connect(to):
    return socket.create_connection(to, timeout=5)

def bind(at, kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(at)
        if kind == socket.SOCK_STREAM:
            s.listen()
    except BaseException:
        s.close()
        raise
    return s

def sendto(to):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", to)

def mine(what, kind, then):
    """A listener or a datagram socket of the test's own, at a port the system picks, and then a try at it."""
    try:
        own = bind(("127.0.0.1", 0), kind)
    except PermissionError:
        say(what, "refused")
        return
    try:
        tried(what, lambda: then(own.getsockname()))
    finally:
        own.close()

def test_what_a_program_reaches_for_beside_its_own_listener():
    mine("a connection to a listener of its own", socket.SOCK_STREAM, connect)
    mine("a datagram to a socket of its own", socket.SOCK_DGRAM, sendto)
    tried("another program's listener", lambda: connect(("127.0.0.1", OUT["tcp"])))
    tried("another program's listener, by address",
          lambda: urllib.request.urlopen("http://127.0.0.1:%d/" % OUT["tcp"], timeout=5))
    tried("another program's datagram socket", lambda: sendto(("127.0.0.1", OUT["udp"])))
    tried("an address outside", lambda: connect(("192.0.2.1", 9)))
    tried("every address at once", lambda: bind(("0.0.0.0", 0)))
    tried("every address at once, unnamed", lambda: bind(("", 0)))
    tried("a port somebody else holds", lambda: bind(("127.0.0.1", OUT["tcp"])))
    tried("a port the test chose", lambda: bind(("127.0.0.1", OUT["free"])))
'''
OWN_PLAIN = ("a connection to a listener of its own", "a datagram to a socket of its own")
PLAIN_OUTSIDE = ("another program's listener", "another program's listener, by address",
                 "another program's datagram socket", "an address outside", "every address at once",
                 "every address at once, unnamed", "a port somebody else holds", "a port the test chose")


def test_a_programs_own_listener_opens_no_other_door(tmp_path):
    with _Outside() as outside:
        where = outside.where()
        r, lines = _box(_project(tmp_path / "plain", PLAIN_TRIES, where))
        came = outside.came()
    said = _said(lines)
    assert came == [], (came, said, r["output_tail"])
    assert sorted(said) == sorted(OWN_PLAIN + PLAIN_OUTSIDE), (said, r["output_tail"])
    named = _named(r)
    assert any("192.0.2.1" in what for what in named), r["blocked"]
    if OWN:
        assert said["an address outside"] == "refused", said
        assert {what: said[what] for what in OWN_PLAIN} == dict.fromkeys(OWN_PLAIN, "done"), said
        return
    assert {what: said[what] for what in OWN_PLAIN} == dict.fromkeys(OWN_PLAIN, "done" if WINDOWS else "refused"), said
    assert {said[what] for what in PLAIN_OUTSIDE} == {"refused"}, said
    assert any(str(where["tcp"]) in what for what in named), r["blocked"]


# ------------------------------------------------------------------------------- what looks like a file on Windows
# A pipe of the run's own (made with the pipe's two ends together, as `multiprocessing.Pipe` does), a pipe of another
# program of the tests (a `multiprocessing.Manager`, which serves from a program of its own at a pipe it names), and
# another program's pipe under each of its names, to read, to read and write, as a connection, by the system's own
# call, and a second end of it that its clients may come to.
PIPES = TRIES + '''
import multiprocessing, _winapi
from multiprocessing.connection import Client

def own_pipe():
    a, b = multiprocessing.Pipe()
    a.send("x")
    assert b.recv() == "x"
    a.close()
    b.close()

def another_program_of_the_tests():
    with multiprocessing.Manager() as manager:
        d = manager.dict()
        d["x"] = 1
        assert d["x"] == 1

def by_the_system(name):
    h = _winapi.CreateFile(name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                           _winapi.OPEN_EXISTING, 0, _winapi.NULL)
    _winapi.CloseHandle(h)

def a_second_end(name):
    h = _winapi.CreateNamedPipe(name, _winapi.PIPE_ACCESS_DUPLEX,
                                _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
                                _winapi.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, _winapi.NULL)
    _winapi.CloseHandle(h)

def test_what_a_program_reaches_for_among_the_pipes_of_this_computer():
    tried("a pipe of its own", own_pipe)
    tried("a pipe of another program of the tests", another_program_of_the_tests)
    pipe = OUT["pipe"]
    tried("another program's pipe, to read", lambda: open(pipe, "rb"))
    for how, name in OUT["spellings"].items():
        tried("another program's pipe, " + how, lambda: open(name, "rb"))
    tried("another program's pipe, to read and write", lambda: open(pipe, "r+b"))
    tried("another program's pipe, as a connection", lambda: Client(pipe))
    tried("another program's pipe, by the system's own call", lambda: by_the_system(pipe))
    tried("another program's pipe, a second end of it", lambda: a_second_end(pipe))
'''
OWN_PIPES = ("a pipe of its own", "a pipe of another program of the tests")
OTHER_PIPES = ("to read", "to read and write", "as a connection", "by the system's own call", "a second end of it")


@ONLY_WINDOWS
def test_the_pipes_of_other_programs_are_out_of_reach_and_named(tmp_path):
    with _Outside() as outside:
        r, lines = _box(_project(tmp_path / "pipes", PIPES, outside.where()))
        came = outside.came()
    said = _said(lines)
    assert came == [], (came, said, r["output_tail"])
    others = [f"another program's pipe, {how}" for how in (*OTHER_PIPES, *outside.spellings)]
    assert sorted(said) == sorted((*OWN_PIPES, *others)), (said, r["output_tail"])
    assert {what: said[what] for what in OWN_PIPES} == dict.fromkeys(OWN_PIPES, "done"), (said, r["output_tail"])
    assert {said[what] for what in others} == {"refused"}, said
    assert any(outside.pipe[len("\\\\.\\pipe\\"):] in what for what in _named(r)), r["blocked"]


# A share of a computer outside, opened, looked at and listed (Windows asks the computer each time), and a file of
# this computer reached as a share of it on the network.
SHARES = TRIES + '''
import os

def test_what_a_program_reaches_for_through_a_files_place():
    share = OUT["share"]
    tried("a share of a computer outside, opened", lambda: open(share + "\\\\x.txt", "rb"))
    tried("a share of a computer outside, looked at", lambda: os.stat(share + "\\\\x.txt"))
    tried("a share of a computer outside, listed", lambda: os.listdir(share))
    tried("this computer's own disk, the network's way", lambda: open(OUT["disk"], "rb"))
'''
SHARE_TRIES = ("a share of a computer outside, opened", "a share of a computer outside, looked at",
               "a share of a computer outside, listed", "this computer's own disk, the network's way")


@ONLY_WINDOWS
def test_the_networks_shares_are_out_of_reach_and_named(tmp_path):
    with _Outside() as outside:
        r, lines = _box(_project(tmp_path / "shares", SHARES, outside.where()))
    said = _said(lines)
    assert sorted(said) == sorted(SHARE_TRIES), (said, r["output_tail"])
    assert {said[what] for what in SHARE_TRIES} == {"refused"}, said
    named = _named(r)
    assert any("192.0.2.1" in what for what in named), r["blocked"]
    assert any("localhost" in what for what in named), r["blocked"]


def test_a_file_is_not_handed_to_another_program_to_open(tmp_path):
    """`os.startfile` hands a file or an address to whatever program this computer opens it with, a browser for an
    address, and that program is none of the run's. Python tells its hooks before it hands anything over; the event
    is raised here by hand, so that this test opens nothing on any computer."""
    r = _guard_alone(tmp_path, '''
        import sys
        assert sys.lantern_sandbox_guard == "on"
        for event, args in (("os.startfile", ("https://192.0.2.1/", None)),
                            ("os.startfile/2", ("https://192.0.2.1/", None, None, None, 1))):
            try:
                sys.audit(event, *args)
            except PermissionError:
                print("refused:", event)
            else:
                print("let through:", event)
    ''')
    assert r.stdout.splitlines() == ["refused: os.startfile", "refused: os.startfile/2"], r.stdout + r.stderr[-2000:]
    assert sandbox.MARK + " network" in r.stderr and "192.0.2.1" in r.stderr, r.stderr[-2000:]


# ---------------------------------------------------------------------------------------------- an app started
def test_an_app_is_started_in_the_box_and_what_it_sets_out_for_is_reported(tmp_path):
    """The behaviour checks start the project's app in the box (`sandbox.run_inside`) and judge what it did. Here,
    as on Linux, an app that fetches whatever address it is given is reported for each address inside, and held
    for the site the plan lists."""
    record = _run(_repo(tmp_path / "preview", FETCHES_ANYTHING, PREVIEW_PLAN))
    assert _by_case(record) == _expected(INSIDE)
