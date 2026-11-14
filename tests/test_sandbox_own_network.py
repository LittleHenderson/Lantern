"""A project may talk to itself (2026-11-13). In the sandbox the tests get a network of their own: it holds this
computer's own address and nothing else, so a test suite that starts a server and calls it runs, and the internet,
the person's network and what the other programs of the computer listen at stay out of reach (by address and by
socket name for every language; a socket file is a file, which the Python guard refuses outside the run's folders).

Before, the sandbox refused every listener and every connection, also on this computer: any project whose tests
start their app's server ended "Incomplete" ("the sandbox refused something they tried"), Lantern's own tests
among them. Each case here stands beside a twin that reaches outside, which must still be refused and written down.

Where no such network can be made (not Linux; a Linux system that refuses the rights it takes), nothing on this
computer is let through, as before: a listener there is a place other programs of the computer could reach, and a
connection there could reach them."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest
from test_sandbox import BACKENDS, _guard_alone, _tiny

from lantern import _jail, sandbox

PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]
def QUIET(line):
    """A log nobody reads."""


def _own(backend: str = "subprocess") -> bool:
    """Does this run get a network of its own? A container always has one; the restricted process where this
    system can make it (asked of Lantern, as the app asks it before it shows the sheet)."""
    return backend == "docker" or sandbox.own_network() == ""


def _udp_made_here() -> bool:
    """Does whatever stands around this test let a program make a UDP socket at all?"""
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()
    except OSError:
        return False
    return True


def _datagram_line(backend: str) -> str | None:
    """What a datagram for another computer leaves in the record of the run that refused it. The guard refuses the
    send and writes it down. Where the run has no network of its own and stands behind a doorman of its own, the
    UDP socket itself is not made (there a UDP message would go wherever it is sent), so the test never gets to
    send and the line is the doorman's: GitHub's Linux machines, where an ordinary user may make no network. Inside
    another sandbox that makes no UDP socket the refusal is that sandbox's, written in its record and not in this
    run's (None). Until 2026-11-14 the test asked for the guard's line everywhere, which the doorman of stage 2
    made untrue on such a machine; on the change's first version another failure in the same test hid it."""
    send = "network sendto ('192.0.2.1', 53)"
    if backend == "docker":
        return send
    no_doorman = sandbox.own_sockets()
    if not no_doorman:                                   # a doorman of the run's own
        return send if _own(backend) else _jail.SAID["udp"]
    if no_doorman == sandbox.DOORMAN_ABOVE and not _udp_made_here():
        return None
    return send


def _failed(out: str) -> set[str]:
    """The names of the tests pytest's summary says failed."""
    return {line.split("::", 1)[1].split(" ", 1)[0] for line in out.splitlines()
            if line.startswith("FAILED ") and "::" in line}


SERVER = '''
import asyncio, http.server, socket, subprocess, sys, threading, urllib.request

class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from the project"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

def _get(port):
    with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=20) as r:
        return r.status, r.read()

def test_a_server_in_a_thread_answers():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert _get(srv.server_port) == (200, b"hello from the project")
    finally:
        srv.shutdown()
        srv.server_close()

CHILD = """
import http.server
class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from a program of its own"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), Hello)
print(srv.server_port, flush=True)
srv.serve_forever()
"""

def test_a_server_in_a_program_of_its_own_answers():
    p = subprocess.Popen([sys.executable, "-c", CHILD], stdout=subprocess.PIPE, text=True)
    try:
        port = int(p.stdout.readline() or 0)
        assert port, "the server did not start"
        assert _get(port) == (200, b"hello from a program of its own")
    finally:
        p.kill()
        p.wait()

def test_an_async_server_answers():
    async def main():
        async def handle(reader, writer):
            writer.write((await reader.readline()).upper())
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"ping\\n")
            await writer.drain()
            got = await asyncio.wait_for(reader.readline(), 20)
            writer.close()
            return got
    assert asyncio.run(main()) == b"PING\\n"

def test_a_server_on_every_address_of_this_computer_answers():
    with socket.create_server(("", 0)) as srv:
        with socket.create_connection(("127.0.0.1", srv.getsockname()[1]), timeout=20) as c:
            conn, _ = srv.accept()
            c.sendall(b"x")
            assert conn.recv(1) == b"x"
            conn.close()

def test_the_name_localhost_leads_to_the_server():
    with socket.create_server(("127.0.0.1", 0)) as srv:
        with socket.create_connection(("localhost", srv.getsockname()[1]), timeout=20) as c:
            conn, _ = srv.accept()
            c.sendall(b"x")
            assert conn.recv(1) == b"x"
            conn.close()

def test_a_datagram_reaches_its_own_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
        a.bind(("127.0.0.1", 0))
        a.settimeout(20)
        b.sendto(b"to myself", a.getsockname())
        assert a.recv(100) == b"to myself"
'''
SERVER_TESTS = {"test_a_server_in_a_thread_answers", "test_a_server_in_a_program_of_its_own_answers",
                "test_an_async_server_answers", "test_a_server_on_every_address_of_this_computer_answers",
                "test_the_name_localhost_leads_to_the_server", "test_a_datagram_reaches_its_own_listener"}


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_start_a_server_on_their_own_computer_run(backend, tmp_path):
    """The case that kept Lantern's own tests, and every project that tests its app over HTTP, from a firm answer."""
    lines = []
    r = sandbox.run(_tiny(tmp_path / "tiny", SERVER), PYTEST, log=lines.append, backend=backend, timeout=180)
    out = r["output_tail"]
    if not _own(backend):
        # nothing changed here: every one of them is refused, and the reasons are written down
        assert r["own_network"] is False and r["returncode"] == 1, out
        assert _failed(out) == SERVER_TESTS and {b["kind"] for b in r["blocked"]} == {"network"}, (out, r["blocked"])
        return
    assert r["returncode"] == 0, out
    assert r["blocked"] == [] and r["own_network"] is True, r["blocked"]
    assert "6 passed" in out, out
    if backend == "subprocess":      # said once in the run's log, in Lantern's words
        assert sum("a network of its own" in line for line in lines) == 1, lines


TWIN = '''
import socket

def test_it_talks_to_itself():
    with socket.create_server(("127.0.0.1", 0)) as srv:
        with socket.create_connection(srv.getsockname(), timeout=20) as c:
            conn, _ = srv.accept()
            c.sendall(b"x")
            assert conn.recv(1) == b"x"
            conn.close()

# 192.0.2.0/24 is kept for examples (RFC 5737): no computer has such an address

def test_it_calls_a_computer_outside():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(("192.0.2.1", 80))

def test_it_sends_a_datagram_outside():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("192.0.2.1", 53))

def test_it_asks_for_a_name_outside():
    socket.getaddrinfo("example.invalid", 80)
'''
OUTSIDE = {"test_it_calls_a_computer_outside", "test_it_sends_a_datagram_outside", "test_it_asks_for_a_name_outside"}


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_twin_that_reaches_outside_is_still_refused_and_written_down(backend, tmp_path):
    r = sandbox.run(_tiny(tmp_path / "tiny", TWIN), PYTEST, log=QUIET, backend=backend, timeout=180)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    assert _failed(out) == OUTSIDE | (set() if _own(backend) else {"test_it_talks_to_itself"}), out
    assert {b["kind"] for b in r["blocked"]} == {"network"}, r["blocked"]
    what = [b["what"] for b in r["blocked"]]
    datagram = _datagram_line(backend)
    for tried in ("network connect ('192.0.2.1', 80)", datagram, "network lookup 'example.invalid'"):
        assert tried is None or tried in what, what
    if _own(backend):                # and nothing else was refused: the test that talks to itself left no line
        assert len(what) == (2 if datagram is None else 3), what


# ------------------------------------------------------------------------------- the other programs of this computer
class _Others:
    """Other programs of this computer, each listening its own way: an address of the computer (TCP and
    datagrams), a socket file, and a socket name that is no file (Linux)."""

    def __init__(self):
        self.folder = Path(tempfile.mkdtemp(prefix="others-"))
        self.folder.chmod(0o755)                 # where the sandbox's own user can come, unlike a test's tmp_path
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.file = self.name = None
        if hasattr(socket, "AF_UNIX"):
            self.file = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.file.bind(str(self.folder / "other.sock"))
            self.file.listen()
            (self.folder / "other.sock").chmod(0o666)
        if sys.platform.startswith("linux"):
            self.name = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.name.bind("\0lantern-others-" + self.folder.name)
            self.name.listen()
        for s in (self.tcp, self.udp, self.file, self.name):
            if s is not None:
                s.setblocking(False)

    def where(self) -> dict:
        return {"tcp": self.tcp.getsockname()[1], "udp": self.udp.getsockname()[1],
                "file": str(self.folder / "other.sock") if self.file else "",
                "name": "lantern-others-" + self.folder.name if self.name else ""}

    def came(self) -> set[str]:
        """Which of them somebody reached."""
        got = set()
        for what, s in (("tcp", self.tcp), ("udp", self.udp), ("file", self.file), ("name", self.name)):
            if s is None:
                continue
            try:
                s.recv(100) if what == "udp" else s.accept()[0].close()
            except BlockingIOError:
                continue
            got.add(what)
        return got

    def close(self):
        for s in (self.tcp, self.udp, self.file, self.name):
            if s is not None:
                s.close()
        shutil.rmtree(self.folder, ignore_errors=True)


@pytest.fixture()
def others():
    o = _Others()
    try:
        yield o
    finally:
        o.close()


# Tries each of them and carries on whatever happens: what counts is whether anybody arrived.
REACH = '''
import json, socket
WHERE = json.loads(%r)

def _try(do):
    try:
        do()
    except OSError as e:
        print("not reached:", type(e).__name__)

def _tcp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(("127.0.0.1", WHERE["tcp"]))

def _udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("127.0.0.1", WHERE["udp"]))

def _local(address):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(address)

def reach():
    _try(_tcp)
    _try(_udp)
    if WHERE["file"]:
        _try(lambda: _local(WHERE["file"]))
    if WHERE["name"]:
        _try(lambda: _local(chr(0) + WHERE["name"]))
'''


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_other_programs_of_this_computer_are_out_of_reach(backend, tmp_path, others):
    """A listener of another program, at an address of this computer, at a socket file or at a socket name: the
    tests reach none of them. Until 2026-11-13 the last two were let through: a socket file is how a computer's
    own services are asked (the desktop's message bus, Docker), and the guard looked at network addresses only."""
    source = REACH % json.dumps(others.where()) + "\ndef test_reach():\n    reach()\n"
    r = sandbox.run(_tiny(tmp_path / "tiny", source), PYTEST, log=QUIET, backend=backend, timeout=180)
    assert r["returncode"] == 0, r["output_tail"]            # the test itself carries on after each refusal
    assert others.came() == set(), r["output_tail"]
    refused = [b["what"] for b in r["blocked"]]
    if others.file is not None and backend == "subprocess":  # written down, with the file it was (a container has no such file)
        assert any(str(others.folder / "other.sock") in what for what in refused), refused


def test_tests_may_use_a_socket_file_of_their_own(tmp_path):
    """The safe twin: a socket file in the tests' own temp folder is theirs (how a test database or a worker pool
    is reached), and is not refused."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("this system has no socket files")
    r = sandbox.run(_tiny(tmp_path / "tiny", '''
import socket

def test_a_socket_file_of_its_own(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)      # named from its own folder: a socket's name may be about a hundred letters long
    with socket.socket(socket.AF_UNIX) as srv, socket.socket(socket.AF_UNIX) as c:
        srv.bind("mine.sock")
        srv.listen()
        c.connect("mine.sock")
        conn, _ = srv.accept()
        c.sendall(b"x")
        assert conn.recv(1) == b"x"
        conn.close()

def test_a_pair_of_sockets():
    a, b = socket.socketpair()
    a.sendall(b"x")
    assert b.recv(1) == b"x"
    a.close()
    b.close()
'''), PYTEST, log=QUIET, backend="subprocess", timeout=180)
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []


def _below(where: dict) -> str:
    """A test module whose one test starts a Python without the guard (what any program that is not Python is to
    the sandbox: held by the kernel alone), which tries the other programs and then a listener of its own."""
    below = REACH % json.dumps({**where, "file": ""}) + textwrap.dedent('''
        reach()
        try:
            with socket.create_server(("127.0.0.1", 0)) as srv, socket.create_connection(srv.getsockname(), timeout=20):
                print("OWN LISTENER: reached")
        except OSError as e:
            print("OWN LISTENER: refused", type(e).__name__)
    ''')
    return ("import subprocess, sys\nBELOW = %r\n\ndef test_below_python():\n"
            "    r = subprocess.run([sys.executable, '-I', '-S', '-c', BELOW], capture_output=True, text=True)\n"
            "    print(r.stdout, r.stderr[-2000:])\n    assert r.returncode == 0\n") % below


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the kernel's walls are Linux's")
def test_below_python_the_tests_have_their_own_address_and_cannot_reach_another_program(tmp_path, others):
    """What holds a program that is not Python (a test in JavaScript, a C extension): the kernel alone. Until
    2026-11-13 such a program could not listen at all, and a datagram and a socket name of another program were
    let through (the kernel rule in place then is about TCP only)."""
    r = sandbox.run(_tiny(tmp_path / "tiny", _below(others.where())), PYTEST, log=QUIET, backend="subprocess", timeout=180)
    out = r["output_tail"]
    assert r["returncode"] == 0, out
    came = others.came()
    if _own():
        assert "OWN LISTENER: reached" in out, out
        assert came == set(), out
        return
    # no network of its own: the kernel's older rules, where it has them (none of them is about datagrams)
    if sandbox.landlock_abi() >= 4:
        assert "OWN LISTENER: refused" in out, out
    if not sandbox.held_below_python():
        # A run inside a run (these tests, run by Lantern): the doorman of the sandbox around it makes every
        # connection, and the kernel asks its rules of the one that connects. What is reached is that sandbox's
        # to decide (the other programs here are inside it), and the inner run's log says so.
        return
    if sandbox.landlock_abi() >= 4:
        assert "tcp" not in came, out
    if sandbox.landlock_abi() >= 6:
        assert "name" not in came, out


# ------------------------------------------------------------------------------------------------------ JavaScript
JS_SERVER = '''
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

test('a server on its own computer answers', async () => {
  const server = http.createServer((req, res) => res.end('hello from the project'));
  await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok); });
  try {
    const r = await fetch(`http://127.0.0.1:${server.address().port}/`);
    assert.strictEqual(await r.text(), 'hello from the project');
  } finally {
    if (server.closeAllConnections) server.closeAllConnections();
    server.close();
  }
});
'''
JS_OUTSIDE = '''
const test = require('node:test');
const net = require('node:net');
const dgram = require('node:dgram');
const WHERE = %s;

// 192.0.2.0/24 is kept for examples (RFC 5737): no computer has such an address
test('it calls a computer outside', async () => {
  await new Promise((ok, no) => {
    const s = net.connect({ host: '192.0.2.1', port: 80 });
    s.setTimeout(5000, () => { s.destroy(); no(new Error('no answer')); });
    s.once('connect', () => { s.destroy(); ok(); });
    s.once('error', no);
  });
});

test('it sends a datagram to another program of this computer', async () => {
  await new Promise((ok) => {
    const s = dgram.createSocket('udp4');
    s.once('error', () => { s.close(); ok(); });
    s.send('x', WHERE.udp, '127.0.0.1', () => { s.close(); ok(); });
  });
});
'''


def _js(folder: Path, source: str) -> Path:
    (folder / "test").mkdir(parents=True)
    (folder / "package.json").write_text(json.dumps({"name": "tiny-js", "version": "1.0.0", "private": True,
                                                     "scripts": {"test": "node --test"}}), encoding="utf-8")
    (folder / "test" / "tiny.test.js").write_text(source, encoding="utf-8")
    return folder


needs_node = pytest.mark.skipif(not (shutil.which("node") and shutil.which("npm")), reason="node and npm are not installed")


@needs_node
@pytest.mark.skipif(os.name != "posix", reason="npm is a script on Windows, which the sandbox starts another way")
def test_javascript_tests_that_start_a_server_on_their_own_computer_run(tmp_path):
    r = sandbox.run(_js(tmp_path / "tiny-js", JS_SERVER), ["npm", "test"], log=QUIET, backend="subprocess", timeout=180)
    out = r["output_tail"]
    if _own() or sandbox.landlock_abi() < 4:     # a network of its own, or a system with no rule for other languages
        assert r["returncode"] == 0, out
        assert r["blocked"] == [], r["blocked"]
        return
    assert r["returncode"] != 0, out             # the older wall, and now the reason is written down
    assert {b["kind"] for b in r["blocked"]} == {"network"}, (r["blocked"], out)


@needs_node
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the kernel's walls are Linux's")
@pytest.mark.tries_outside("connect", "192.0.2.1", 80, "the JavaScript twin calls a computer outside to see the kernel refuse it")
def test_the_javascript_twin_that_reaches_outside_is_refused_and_written_down(tmp_path, others):
    """Until 2026-11-13 the kernel refused the call, the tests failed, and Lantern did not say that the sandbox was
    the reason (it knew Python's words for it only); and the datagram arrived. The call is made below Python, so
    the operating system's record of a run holds it: the mark names it for the no-network runner (CI's first pass
    ended with every test passed and the runner's result 4 for this one call until it was named)."""
    if not (_own() or sandbox.landlock_abi() >= 4):
        pytest.skip("needs a network of the run's own or Landlock 4: this kernel has neither")
    source = JS_OUTSIDE % json.dumps(others.where())
    r = sandbox.run(_js(tmp_path / "tiny-js", source), ["npm", "test"], log=QUIET, backend="subprocess", timeout=180)
    out = r["output_tail"]
    assert r["returncode"] != 0, out
    assert {b["kind"] for b in r["blocked"]} == {"network"}, (r["blocked"], out)
    if _own():
        assert others.came() == set(), out


# ------------------------------------------------------------------------------------------- the guard, by itself
def _inode() -> str:
    return str(os.stat("/proc/self/ns/net").st_ino) if sys.platform.startswith("linux") else "0"


LISTEN_AND_CALL = '''
    import socket, sys
    assert sys.lantern_sandbox_guard == "on"
    def tried(what, do):
        try:
            do()
        except PermissionError:
            print("refused:", what)
        except OSError as e:
            print("allowed:", what)          # the guard let it through; what the system then said is another matter
        else:
            print("allowed:", what)
    def own():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
            srv.bind(("127.0.0.1", 0))
            srv.listen()
            c.settimeout(5)
            c.connect(srv.getsockname())
    def outside():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.01)
            s.connect(("192.0.2.1", 80))
    tried("a listener of its own", own)
    tried("a computer outside", outside)
'''


def test_the_guard_lets_this_computer_through_only_in_a_network_the_launcher_made(tmp_path):
    """The launcher names the network it made (its number in the kernel) and the guard looks for itself: a name
    that is not this process's network changes nothing, and neither does a word without a number, or no word."""
    for said in (None, "", "own", "own:1", "own:" + _inode() + "0", "yes", "container:" + _inode()):
        r = _guard_alone(tmp_path, LISTEN_AND_CALL, net=said)
        assert r.stdout.splitlines() == ["refused: a listener of its own", "refused: a computer outside"], (said, r.stdout, r.stderr[-800:])


ADDRESSES = '''
    import socket, sys
    SIX = sys.argv[1] == "True"
    def tried(what, do):
        if ":" in what and not SIX:
            return
        try:
            do()
        except PermissionError:
            print("refused:", what)
        except OSError:
            print("let through:", what)      # by the guard; what the system then said is another matter
        else:
            print("let through:", what)
    def connect(family, to):
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.01)
            s.connect(to)
    def send(to):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"x", to)
    four, six = socket.AF_INET, socket.AF_INET6
    for what, do in (
            ("127.0.0.1", lambda: connect(four, ("127.0.0.1", 9))), ("127.8.9.10", lambda: connect(four, ("127.8.9.10", 9))),
            ("::1", lambda: connect(six, ("::1", 9))), ("a datagram to itself", lambda: send(("127.0.0.1", 9))),
            ("192.0.2.1", lambda: connect(four, ("192.0.2.1", 80))), ("10.0.0.1", lambda: connect(four, ("10.0.0.1", 80))),
            ("169.254.169.254", lambda: connect(four, ("169.254.169.254", 80))),
            ("2001:db8::1", lambda: connect(six, ("2001:db8::1", 80))),
            ("a datagram outside", lambda: send(("192.0.2.1", 53))),
            ("a datagram to everybody", lambda: send(("255.255.255.255", 53))),
            ("a name outside", lambda: socket.getaddrinfo("example.invalid", 80))):
        tried(what, do)
'''
OWN_ADDRESSES = ["127.0.0.1", "127.8.9.10", "::1", "a datagram to itself"]
OTHER_ADDRESSES = ["192.0.2.1", "10.0.0.1", "169.254.169.254", "2001:db8::1", "a datagram outside",
                   "a datagram to everybody", "a name outside"]


def _six() -> bool:
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
    except OSError:
        return False
    return True


def _a_way_out() -> bool:
    """Is anything but this computer's own address switched on in the network these tests run in? (GitHub's
    Linux machines run them in a network that holds nothing else, `tools/netless.py`.)"""
    import fcntl
    import struct
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            flags = struct.unpack("16sH22s", fcntl.ioctl(s, 0x8913, struct.pack("16sH22s", name.encode()[:15], 0, b"")))[1]
            if name != "lo" and flags & 0x1:
                return True
    return False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a network of its own is made on Linux only")
def test_the_right_number_is_not_enough_where_the_network_has_a_way_out(tmp_path):
    """The guard looks at the network it is in: with anything but this computer's own address switched on there,
    it is not a network of the run's own, whatever the number says. (Without a way out, as on GitHub's Linux
    machines, the number of the tests' network is what a launcher would have said, and it is believed.)"""
    six = _six()
    r = _guard_alone(tmp_path, ADDRESSES, str(six), net="own:" + _inode())
    word = "refused: " if _a_way_out() else "let through: "
    want = [word + a for a in OWN_ADDRESSES] + ["refused: " + a for a in OTHER_ADDRESSES]
    assert r.stdout.splitlines() == [w for w in want if six or ":" not in w.split(": ", 1)[1]], r.stdout + r.stderr[-1500:]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a network of its own is made on Linux only")
def test_in_a_network_of_its_own_the_guard_still_refuses_every_address_that_is_not_this_computers(tmp_path):
    """The guard inside a network the launcher made: this computer's own addresses are let through, any other is
    refused before it is tried (the kernel would refuse it too; the guard's line is what the log shows)."""
    if sandbox.own_network():
        pytest.skip("this system cannot give a program a network of its own: " + sandbox.own_network())
    hook, room = tmp_path / "hook", tmp_path / "room"
    hook.mkdir()
    room.mkdir()
    (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
    for folder in (tmp_path, hook, room):
        folder.chmod(0o755)
    policy = {"writable": [str(room)], "nobody": False, "python": True, "net": True, "own_net": True, "must": True}
    launcher = ("import sys; sys.path.insert(0, %r); from lantern._jail import main; main(sys.argv[1:])"
                % str(Path(_jail.__file__).resolve().parent.parent))
    six = _six()
    r = subprocess.run([sys.executable, "-I", "-c", launcher, json.dumps(policy), "--", sys.executable, "-c",
                        textwrap.dedent(ADDRESSES), str(six)], cwd=room, capture_output=True, text=True,
                       encoding="utf-8", timeout=120,
                       env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(hook), "LANTERN_SANDBOX_WRITABLE": str(room)})
    want = ["let through: " + a for a in OWN_ADDRESSES] + ["refused: " + a for a in OTHER_ADDRESSES]
    assert r.stdout.splitlines() == [w for w in want if six or ":" not in w.split(": ", 1)[1]], r.stdout + r.stderr[-1500:]
    assert "sandbox: a network of its own" in r.stderr and sandbox.MARK + " network connect ('192.0.2.1', 80)" in r.stderr
    assert sandbox.MARK + " network connect ('127.0.0.1', 9)" not in r.stderr, r.stderr[-1500:]


def test_the_guard_refuses_a_socket_file_outside_the_temp_folder_and_a_socket_name(tmp_path, others):
    """On every system, with nothing else around it: another program's socket file, and (Linux) a socket name, which
    only a network of the run's own keeps apart from the other programs' names."""
    where = others.where()
    r = _guard_alone(tmp_path, '''
        import json, os, socket, sys
        where = json.loads(sys.argv[1])
        def tried(what, do):
            try:
                do()
            except PermissionError as e:
                print("refused:", what)
            else:
                print("allowed:", what)
        def connect(address):
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(address)
        def mine():
            with socket.socket(socket.AF_UNIX) as srv:
                srv.bind("mine.sock")
                srv.listen()
                connect(os.path.abspath("mine.sock"))
        def listen_outside():
            with socket.socket(socket.AF_UNIX) as srv:
                srv.bind(os.path.join(os.path.dirname(where["file"]), "planted.sock"))
        tried("another program's socket file", lambda: connect(where["file"]))
        tried("a socket file made outside the temp folder", listen_outside)
        tried("a socket file of its own", mine)
        if where["name"]:
            tried("another program's socket name", lambda: connect(chr(0) + where["name"]))
    ''', json.dumps(where)) if others.file is not None else None
    if r is None:
        pytest.skip("this system has no socket files")
    want = ["refused: another program's socket file", "refused: a socket file made outside the temp folder",
            "allowed: a socket file of its own"] + (["refused: another program's socket name"] if where["name"] else [])
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-1500:]
    assert others.came() == set() and not (others.folder / "planted.sock").exists()
    assert sandbox.MARK + " network connect" in r.stderr and str(others.folder / "other.sock") in r.stderr, r.stderr[-1500:]


# ------------------------------------------------------------------- where no network of its own can be made
def test_where_no_network_of_its_own_can_be_made_nothing_on_this_computer_is_let_through_and_the_log_says_why(
        tmp_path, monkeypatch, others):
    """The walls of before stay, every one: said in the log once, and on the sheet before the person clicks Run."""
    why = "this system refused the rights it takes (error 1)"
    monkeypatch.setattr(sandbox, "own_network", lambda: why)
    lines = []
    r = sandbox.run(_tiny(tmp_path / "tiny", SERVER), PYTEST, log=lines.append, backend="subprocess", timeout=180)
    assert r["own_network"] is False and r["returncode"] == 1, r["output_tail"]
    assert _failed(r["output_tail"]) == SERVER_TESTS, r["output_tail"]
    assert {b["kind"] for b in r["blocked"]} == {"network"}, r["blocked"]
    said = [line for line in lines if "network of their own" in line]
    assert len(said) == 1 and why in said[0] and "tests that start a server" in said[0], lines
    # the sheet of the same backend the run above was given: where Docker is there (GitHub's Linux machines), the
    # sheet would otherwise be the container's, which has a network of its own whatever this system allows
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    details = " ".join(sandbox.describe(tmp_path / "tiny", "python")["details"])
    assert why in details and "a network of its own:" not in details, details
    if sys.platform.startswith("linux") and sandbox.landlock_abi() >= 6:
        # below Python, a socket name of another program is refused by the kernel's own rule for it
        r = sandbox.run(_tiny(tmp_path / "below", _below(others.where())), PYTEST, log=QUIET, backend="subprocess",
                        timeout=180)
        assert r["returncode"] == 0, r["output_tail"]
        assert "OWN LISTENER: refused" in r["output_tail"], r["output_tail"]
        # (inside a sandbox that makes the connections, that sandbox decides what a connection reaches)
        assert others.came() <= {"udp"} or not sandbox.held_below_python(), r["output_tail"]


def test_the_sheet_says_what_the_tests_can_reach(tmp_path, monkeypatch):
    monkeypatch.delenv("LANTERN_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "docker_ok", lambda: False)
    monkeypatch.setattr(sandbox, "own_network", lambda: "")
    monkeypatch.setattr(sandbox, "_LINUX", True)
    for language in ("python", "node"):
        details = sandbox.describe(tmp_path, language)["details"]
        assert sum("a network of its own:" in d for d in details) == 1, details
        assert not any("network connections refused" in d or "opening network connections are refused" in d
                       for d in details), details
    monkeypatch.setattr(sandbox, "own_network", lambda: "this system is not Linux")
    details = sandbox.describe(tmp_path, "python")["details"]
    assert any("opening network connections are refused" in d for d in details), details
    assert any("this system is not Linux" in d and "tests that start a server" in d for d in details), details


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the launcher makes the network on Linux only")
def test_a_launcher_that_cannot_make_the_network_it_was_told_to_make_does_not_start_the_tests(tmp_path):
    """No sandbox, no tests: the walls are chosen for a run that has a network of its own (the rule that refuses
    every TCP connection is left off inside it), so a run without it must not start."""
    marker = tmp_path / "ran.txt"
    policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": True, "own_net": True, "must": True}
    code = ("import errno, sys\nimport lantern._jail as j\n"
            "def no(flags):\n    raise OSError(errno.EPERM, 'not permitted')\n"
            "j._unshare = no\nj.main(sys.argv[1:])\n")
    r = subprocess.run([sys.executable, "-c", code, json.dumps(policy), "--", sys.executable, "-c",
                        f"open({str(marker)!r}, 'w').close()"], capture_output=True, text=True, encoding="utf-8",
                       timeout=120, cwd=Path(_jail.__file__).resolve().parent.parent)
    assert r.returncode == _jail.UNAVAILABLE and not marker.exists(), (r.returncode, r.stderr)
    assert _jail.MARK + " own-network 1" in r.stderr, r.stderr
    assert "own-network" in _jail.REASONS
    assert sandbox._unavailable(r.returncode, r.stderr) == _jail.REASONS["own-network"] + " (error 1)"


def test_the_check_records_whether_the_tests_had_a_network_of_their_own(tmp_path):
    """run.json's `trace` says it, so a reviewer of the result can tell which walls the run had."""
    from lantern import pipeline
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=["python", "-m", "pytest", "-q"], sandbox=True, offline=True, log=QUIET)
    trace = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    assert trace["ran"] is True and trace["returncode"] == 0
    assert trace["own_network"] is (sandbox.backend_for("python") == "docker" or sandbox.own_network() == "")
