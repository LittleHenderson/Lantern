"""No way from the tests to another program of this computer below Python (2026-11-13).

The Python guard refuses a connection to a socket file outside the run's own folders, and a run's own network
keeps the addresses and socket names of the computer's other programs out of reach. A program the tests start
that is not Python under the guard (Node, a compiled test binary, `python -S`) asks the kernel itself, and the
kernel's rules for files say nothing about connecting to a socket file: so such a program could talk to whatever
listens at one, the desktop's message bus (which starts programs), a container daemon, an agent that holds keys,
the system's log. Where the run has no network of its own the kernel's rule against connections covers TCP only,
and a message over UDP went wherever it was sent, a name server included.

Now the launcher puts a doorman between the tests' programs and the kernel (`lantern._jail`, policy `sockets`):
every connection is made for them by the doorman, which looks where a socket file lies first, and the kinds of
socket whose messages carry their own address (which no doorman sees) are not made at all. Each dangerous example
here stands beside twins that honest tests are made of, which must keep working: a server of the tests' own
reached by its socket file in every way, by address in a network of their own, Python's own ways between
processes, many connections at once and under a storm of signals.

What reached the other program is read from that program's own record, never from what the tests say they got.
On the code before (with the names this change adds stood in), the three dangerous tests failed three of three:
the other program was reached 10 times by a program of the tests that is not Python; where a run has no
network of its own, 6 times (TCP by the two ways round the kernel's rule, UDP, its socket files); and its shared
memory of the older kind was read out."""
import ctypes
import errno
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import pytest

from lantern import _jail, sandbox

LINUX = sys.platform.startswith("linux")
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
UNITTEST = ["python", "-m", "unittest", "-v"]
NODE = shutil.which("node")
only_linux = pytest.mark.skipif(not LINUX, reason="the doorman is made on Linux only (a wall of the kernel's own)")


def QUIET(line):
    """A log nobody reads."""


def _can() -> bool:
    """Can a run be given a doorman of its own here? (Not where these tests run in a sandbox themselves: the
    outer run's doorman is the one, and it knows the outer run's folders.)"""
    return LINUX and not sandbox.own_sockets()


def _project(folder: Path, source: str, **more: str) -> Path:
    folder.mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "test_tiny.py").write_text(textwrap.dedent(source), encoding="utf-8")
    for name, text in more.items():
        (folder / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return folder


class Outside:
    """Another program of this computer, of the kind a person has running: it listens at a socket file every user
    may connect to (`bus`), at a socket file for single messages (`log`), at a socket name that is no file
    (`name`), and at an address of this computer over TCP and over UDP. Whatever reaches it is written down, and
    whoever connects is handed a secret."""

    def __init__(self):
        self.top = Path(tempfile.mkdtemp(prefix="lantern-test-outside-"))
        os.chmod(self.top, 0o755)
        self.secret = "SECRET-" + os.urandom(8).hex()
        self.reached: list[str] = []
        self.bus, self.log = self.top / "bus.sock", self.top / "log.sock"
        self.name = "lantern-test-" + os.urandom(6).hex()
        self._open, self._threads = [], []
        self._listen("the socket file", socket.AF_UNIX, str(self.bus))
        self._listen("the socket name", socket.AF_UNIX, "\0" + self.name)
        self.tcp = self._listen("the address, TCP", socket.AF_INET, ("127.0.0.1", 0)).getsockname()[1]
        log = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        log.bind(str(self.log))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        self.udp = udp.getsockname()[1]
        for path in (self.bus, self.log):
            os.chmod(path, 0o666)
        self._messages("the socket file for messages", log)
        self._messages("the address, UDP", udp)
        self.memory = self._memory()

    def _memory(self) -> int:
        """A piece of shared memory of the older kind (System V) that every user may read, holding the secret:
        the key another program finds it by, or 0 where this system hands none out."""
        libc = ctypes.CDLL(None, use_errno=True)
        libc.shmat.restype = ctypes.c_void_p
        self._piece = -1
        for _ in range(20):
            key = 0x10000 + int.from_bytes(os.urandom(3), "big")
            self._piece = libc.shmget(key, 4096, 0o1000 | 0o2000 | 0o666)      # IPC_CREAT | IPC_EXCL
            if self._piece >= 0:
                break
        else:
            return 0
        at = libc.shmat(self._piece, None, 0)
        if at in (None, ctypes.c_void_p(-1).value):
            return 0
        text = self.secret.encode() + b"\0"
        ctypes.memmove(at, text, len(text))
        libc.shmdt(ctypes.c_void_p(at))
        return key

    def _listen(self, what: str, family: int, at) -> socket.socket:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.bind(at)
        s.listen(16)
        s.settimeout(0.2)
        self._open.append(s)

        def serve():
            while True:
                try:
                    conn, _ = s.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                self.reached.append(what)
                try:
                    conn.settimeout(5)
                    conn.sendall(self.secret.encode())
                except OSError:
                    pass
                finally:
                    conn.close()
        self._start(serve)
        return s

    def _messages(self, what: str, s: socket.socket) -> None:
        s.settimeout(0.2)
        self._open.append(s)

        def serve():
            while True:
                try:
                    _data, sender = s.recvfrom(4096)
                except TimeoutError:
                    continue
                except OSError:
                    return
                self.reached.append(what)
                if isinstance(sender, tuple):
                    try:
                        s.sendto(self.secret.encode(), sender)
                    except OSError:
                        pass
        self._start(serve)

    def _start(self, serve) -> None:
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self._threads.append(t)

    def close(self) -> None:
        for s in self._open:
            s.close()
        for t in self._threads:
            t.join(5)
        if self._piece >= 0:
            ctypes.CDLL(None).shmctl(self._piece, 0, None)                     # IPC_RMID
        assert sandbox._rm(self.top) is True


@pytest.fixture()
def outside():
    # Every test that asks for this program is one of the doorman's, and says of itself that it is not run where a
    # run gets no doorman of its own. That is said here first: where this run is itself inside a sandbox that
    # makes the connections, that sandbox hands out no socket for single messages, so the program cannot even be
    # made there (2026-11-14, Lantern's own tests run by Lantern: five errors where five tests were not run).
    if LINUX and sandbox.own_sockets():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    program = Outside()
    try:
        yield program
    finally:
        program.close()


# One program below the guard, for both sides: `python -S` loads no guard (and no library of the project), so what
# it asks for it asks of the kernel. `reach.py WAY WHERE [PORT]` prints what it got, or ends with 1 and the error.
REACH = r'''
import ctypes
import os
import socket
import sys
import tempfile
import time

way, where = sys.argv[1], sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 0
TMP = tempfile.gettempdir()


def talk(s, to):
    s.settimeout(20)
    s.connect(to)
    s.sendall(b"hello")
    return s.recv(100).decode()


def answer(s):
    s.settimeout(3)
    try:
        return s.recv(100).decode()
    except TimeoutError:
        return "sent"


def link(target):
    name = os.path.join(TMP, "link-%d" % os.getpid())
    os.symlink(target, name)
    return name


try:
    if way == "file":
        got = talk(socket.socket(socket.AF_UNIX), where)
    elif way == "file, by a name from its folder":
        os.chdir(os.path.dirname(where))
        got = talk(socket.socket(socket.AF_UNIX), os.path.basename(where))
    elif way == "file, through a link":
        got = talk(socket.socket(socket.AF_UNIX), link(where))
    elif way == "file, through a link to its folder":
        got = talk(socket.socket(socket.AF_UNIX), os.path.join(link(os.path.dirname(where)), os.path.basename(where)))
    elif way == "file, under a second name":
        name = os.path.join(TMP, "second-%d" % os.getpid())
        os.link(where, name)
        got = talk(socket.socket(socket.AF_UNIX), name)
    elif way == "file, without waiting":
        s = socket.socket(socket.AF_UNIX)
        s.setblocking(False)
        s.connect_ex(where)
        s.setblocking(True)
        s.settimeout(20)
        s.sendall(b"hello")
        got = s.recv(100).decode()
    elif way == "file, from a program that left its parents":
        note = os.path.join(TMP, "left-%d" % os.getpid())
        if os.fork() == 0:
            os.setsid()
            if os.fork() == 0:                                       # nobody's child now: a daemon
                try:
                    said = "got " + talk(socket.socket(socket.AF_UNIX), where)
                except OSError as e:
                    said = "refused %s %s" % (type(e).__name__, e.errno)
                with open(note + ".part", "w") as f:
                    f.write(said)
                os.rename(note + ".part", note)
            os._exit(0)
        os.wait()
        for _ in range(600):
            if os.path.exists(note):
                break
            time.sleep(0.05)
        with open(note) as f:
            said = f.read()
        if not said.startswith("got "):
            print(said)
            sys.exit(1)
        got = said[4:]
    elif way == "message":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.sendto(b"hello", where)
        got = "sent"
    elif way == "message, from one of a pair":
        s, _other = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.sendto(b"hello", where)
        got = "sent"
    elif way == "message, connected first":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(where)
        s.send(b"hello")
        got = "sent"
    elif way == "name":
        got = talk(socket.socket(socket.AF_UNIX), "\0" + where)
    elif way == "tcp":
        got = talk(socket.socket(socket.AF_INET), (where, port))
    elif way == "tcp, the data sent with the opening":
        s = socket.socket(socket.AF_INET)
        s.sendto(b"hello", 0x20000000, (where, port))               # MSG_FASTOPEN: connects without `connect`
        s.settimeout(20)
        got = s.recv(100).decode()
    elif way == "tcp, over several paths":
        got = talk(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262), (where, port))    # IPPROTO_MPTCP
    elif way == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"hello", (where, port))
        got = answer(s)
    elif way == "udp, connected first":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((where, port))
        s.send(b"hello")
        got = answer(s)
    elif way == "the newer way to ask the kernel":
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.syscall(425, 4, ctypes.create_string_buffer(120))  # io_uring_setup: a queue of requests, connect among them
        if fd < 0:
            raise OSError(ctypes.get_errno(), "io_uring_setup")
        got = "a queue the wall does not see into"
    elif way == "shared memory of the older kind":
        libc = ctypes.CDLL(None, use_errno=True)
        libc.shmat.restype = ctypes.c_void_p
        piece = libc.shmget(int(where), 0, 0)
        if piece < 0:
            raise OSError(ctypes.get_errno(), "shmget")
        at = libc.shmat(piece, None, 0o10000)                        # SHM_RDONLY
        if at in (None, ctypes.c_void_p(-1).value):
            raise OSError(ctypes.get_errno(), "shmat")
        got = ctypes.string_at(at, 60).split(b"\0")[0].decode()
    elif way == "a look at the handles of another program":
        got = "%d handles" % len(os.listdir("/proc/%s/fd" % where))
    elif way == "a handle of another program":
        libc = ctypes.CDLL(None, use_errno=True)
        held, number = os.pidfd_open(int(where)), 0
        for fd in range(64):
            if libc.syscall(438, held, fd, 0) >= 0:                  # pidfd_getfd
                break
            number = number if ctypes.get_errno() == 9 else ctypes.get_errno()    # 9: it has no handle of that number
        else:
            raise OSError(number or 9, "pidfd_getfd")
        got = "its handle number %d" % fd
    else:
        raise SystemExit("unknown way " + way)
except OSError as e:
    print("refused %s %s" % (type(e).__name__, e.errno))
    sys.exit(1)
print("got " + got)
'''

NODE_REACH = r'''
const net = require('net');
const s = net.connect({path: process.argv[2]});
s.setTimeout(20000);
s.on('connect', () => s.write('hello'));
s.on('data', d => { console.log('got ' + d.toString()); process.exit(0); });
s.on('error', e => { console.log('refused ' + e.code); process.exit(1); });
s.on('timeout', () => { console.log('refused timeout'); process.exit(1); });
'''

# The hostile tests: each way is tried and what it gave is printed; nothing is asserted in there, because what
# counts is what the other program saw.
HOSTILE = '''
    import os
    import shutil
    import subprocess
    import sys
    import unittest

    WAYS = {ways!r}
    NODE = shutil.which("node")


    def run(*cmd):
        done = subprocess.run(list(cmd), capture_output=True, text=True, timeout=120)
        return (done.stdout.strip() or done.stderr.strip()[-300:])[:300]


    class T(unittest.TestCase):
        def test_reach_for_another_program(self):
            for way, where, port in WAYS:
                if where == "the doorman":      # the one that started the tests' first program
                    where = str(os.getppid())
                print("WAY", way, "->", run(sys.executable, "-S", "reach.py", way, where, str(port)), flush=True)
            if NODE:
                print("WAY node ->", run(NODE, "reach.js", WAYS[0][1]), flush=True)
'''

OWN_FILE_WAYS = ("file", "file, by a name from its folder", "file, through a link",
                 "file, through a link to its folder", "file, without waiting",
                 "file, from a program that left its parents")
FILE_WAYS = (*OWN_FILE_WAYS, "file, under a second name")
MESSAGE_WAYS = ("message", "message, from one of a pair", "message, connected first")
LOOKS = ("a look at the handles of another program", "a handle of another program")
HELLO = "hello from the tests' own server"


def _said(output: str) -> dict[str, str]:
    """What each way gave, as the tests printed it (the first stands on the line of the test's own name)."""
    out = {}
    for line in output.splitlines():
        i = line.find("WAY ")
        if i >= 0 and " -> " in line[i:]:
            way, what = line[i + 4:].split(" -> ", 1)
            out[way] = what
    return out


@only_linux
def test_a_program_of_the_tests_reaches_no_other_program_through_a_socket_file(tmp_path, outside):
    """The dangerous twin, in a run as it is on this system. The other program's socket files are outside the
    run's folders and open to every user; a program below the guard tries them by their full name, by a name
    from their folder, through links, under a second name, without waiting, as single messages, and by the
    socket name that is no file, from a program that left its parents. Nothing arrives, the secret is not in
    the output, and the run says what was refused (so it is not counted as tests that failed). The doorman
    itself, which holds the kernel's handle on the tests, is the tests' own user: they cannot look into it or
    take a handle of it."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    ways = [(w, str(outside.bus), 0) for w in FILE_WAYS] + [(w, str(outside.log), 0) for w in MESSAGE_WAYS]
    ways += [("name", outside.name, 0), ("the newer way to ask the kernel", "-", 0)]
    ways += [(w, "the doorman", 0) for w in LOOKS]
    repo = _project(tmp_path / "tiny", HOSTILE.format(ways=ways), **{"reach.py": REACH, "reach.js": NODE_REACH})
    lines: list[str] = []
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    said = _said(res["output_tail"])
    assert outside.reached == [], (outside.reached, said)
    assert outside.secret not in res["output_tail"]
    assert res["returncode"] == 0, res["output_tail"]
    assert set(said) >= {w for w, _, _ in ways}, said
    assert [w for w, what in said.items() if not what.startswith("refused ")] == [], said
    kinds = {b["kind"] for b in res["blocked"]}
    assert kinds == {"network"}, res["blocked"]
    assert any(str(outside.bus) in b["what"] for b in res["blocked"]), res["blocked"]
    assert any("single messages" in b["what"] for b in res["blocked"]), res["blocked"]
    assert res["own_sockets"] is True
    assert len([line for line in lines if "a doorman makes every connection" in line]) == 1, lines


@only_linux
def test_with_no_network_of_its_own_nothing_leaves_below_python_either(tmp_path, outside, monkeypatch):
    """The dangerous twin on a system that gives a run no network of its own (an ordinary user where new
    namespaces are refused): there the kernel's rule against connections is about TCP's own call, and what goes
    another way went through: a message over UDP (how a name is looked up), data sent with a TCP opening, TCP
    over several paths. The other program listens at this computer's own address, the nearest thing to reach."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
    ways = [("tcp", "127.0.0.1", outside.tcp), ("tcp, the data sent with the opening", "127.0.0.1", outside.tcp),
            ("tcp, over several paths", "127.0.0.1", outside.tcp), ("udp", "127.0.0.1", outside.udp),
            ("udp, connected first", "127.0.0.1", outside.udp), ("file", str(outside.bus), 0),
            ("message", str(outside.log), 0), ("name", outside.name, 0)]
    repo = _project(tmp_path / "tiny", HOSTILE.format(ways=ways), **{"reach.py": REACH, "reach.js": NODE_REACH})
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    said = _said(res["output_tail"])
    assert outside.reached == [], (outside.reached, said)
    assert outside.secret not in res["output_tail"]
    assert set(said) >= {w for w, _, _ in ways}, said
    assert [w for w, what in said.items() if not what.startswith("refused ")] == [], said
    assert {b["kind"] for b in res["blocked"]} == {"network"}, res["blocked"]
    assert any("UDP socket was not made" in b["what"] for b in res["blocked"]), res["blocked"]
    assert any("127.0.0.1:%d" % outside.tcp in b["what"] for b in res["blocked"]), res["blocked"]


@only_linux
def test_another_programs_shared_memory_of_the_older_kind_is_not_handed_out(tmp_path, outside, monkeypatch):
    """The dangerous twin on a system that gives a run no names of its own for shared memory (new namespaces are
    refused): the older kind of shared memory (System V) is found by a number, and the other program's piece,
    which every user may read, was handed to any program of the tests that asked. Now none is handed out there,
    and the run says so. Where the run has names of its own (the twin), the number names nothing."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    if not outside.memory:
        pytest.skip("this system hands out no shared memory of the older kind")
    ways = [("shared memory of the older kind", str(outside.memory), 0)]
    repo = _project(tmp_path / "own" / "tiny", HOSTILE.format(ways=ways), **{"reach.py": REACH, "reach.js": NODE_REACH})
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    if not sandbox.own_memory():
        assert _said(res["output_tail"])[ways[0][0]].startswith("refused "), res["output_tail"]
        assert outside.secret not in res["output_tail"]
        assert res["blocked"] == [], res["blocked"]
    monkeypatch.setattr(sandbox, "_OWN_MEMORY", ["this test takes the memory folder of its own away"])
    repo = _project(tmp_path / "none" / "tiny", HOSTILE.format(ways=ways), **{"reach.py": REACH, "reach.js": NODE_REACH})
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert outside.secret not in res["output_tail"]
    assert _said(res["output_tail"])[ways[0][0]].startswith("refused "), res["output_tail"]
    assert [b["kind"] for b in res["blocked"] if "older kind" in b["what"]] == ["write"], res["blocked"]


# ---------------------------------------------------------------------------- the twins honest tests are made of
# A server of the tests' own, below the guard like the programs that call it: `serve.py file=PATH name=NAME tcp udp`
# listens at each, prints `ready` and the ports it was given, and answers until its input is closed.
SERVE = r'''
import socket
import sys
import threading

HELLO = b"hello from the tests' own server"


def stream(s):
    s.listen(64)
    while True:
        conn, _ = s.accept()
        try:
            conn.settimeout(20)
            conn.recv(100)
            conn.sendall(HELLO)
        except OSError:
            pass
        conn.close()


def messages(s):
    while True:
        _data, sender = s.recvfrom(4096)
        s.sendto(HELLO, sender)


ports = []
for what in sys.argv[1:]:
    kind, _, where = what.partition("=")
    if kind == "file":
        s = socket.socket(socket.AF_UNIX)
        s.bind(where)
    elif kind == "name":
        s = socket.socket(socket.AF_UNIX)
        s.bind("\0" + where)
    elif kind == "tcp":
        s = socket.socket(socket.AF_INET)
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
    threading.Thread(target=messages if kind == "udp" else stream, args=(s,), daemon=True).start()
print("ready", *ports, flush=True)
sys.stdin.read()
'''

NODE_WEB = r'''
const http = require('http');
const server = http.createServer((req, res) => res.end("hello from the tests' own server"));
server.listen(0, '127.0.0.1', () => {
  http.get('http://localhost:' + server.address().port + '/', res => {
    let body = '';
    res.on('data', d => { body += d; });
    res.on('end', () => { console.log('got ' + body); process.exit(0); });
  }).on('error', e => { console.log('refused ' + e.code); process.exit(1); });
});
'''

HONEST = '''
    import os
    import shutil
    import socket
    import subprocess
    import sys
    import tempfile
    import unittest

    WAYS = {ways!r}
    SERVE = {serve!r}
    NODE = shutil.which("node")
    PLACES = {{"TMP": tempfile.gettempdir(), "COPY": os.getcwd()}}


    def run(*cmd):
        done = subprocess.run(list(cmd), capture_output=True, text=True, timeout=120)
        return (done.stdout.strip() or done.stderr.strip()[-300:])[:300]


    class T(unittest.TestCase):
        def test_the_tests_own_server_is_reached(self):
            serve = [what.format(**PLACES) for what in SERVE]
            server = subprocess.Popen([sys.executable, "-S", "serve.py", *serve], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True)
            try:
                ready = server.stdout.readline().split()
                self.assertEqual(ready[:1], ["ready"])
                ports = dict(zip([what for what in serve if what in ("tcp", "udp")], ready[1:]))
                for n, (way, where) in enumerate(WAYS):
                    port = ports.get(way.split(",")[0], "0")
                    print("WAY %d %s ->" % (n, way),
                          run(sys.executable, "-S", "reach.py", way, where.format(**PLACES), port), flush=True)
                files = [what[5:] for what in serve if what.startswith("file=")]
                if files:
                    with socket.socket(socket.AF_UNIX) as s:
                        s.settimeout(20)
                        s.connect(files[0])
                        s.sendall(b"hello")
                        print("WAY python under the guard ->", "got " + s.recv(100).decode(), flush=True)
                    if NODE:
                        print("WAY node ->", run(NODE, "reach.js", files[0]), flush=True)
                if NODE and os.path.exists("web.js"):
                    print("WAY node, a page of its own server ->", run(NODE, "web.js"), flush=True)
                print("WAY the tests look at their own runner ->", run(
                    sys.executable, "-S", "reach.py", "a look at the handles of another program", str(os.getpid())),
                    flush=True)
            finally:
                server.stdin.close()
                server.wait(20)
'''


def _honest(tmp_path, serve, ways, **more):
    """Run the honest twin: every way must have given the server's own words, and the sandbox refused nothing."""
    files = {"reach.py": REACH, "reach.js": NODE_REACH, "serve.py": SERVE, **more}
    repo = _project(tmp_path / "tiny", HONEST.format(ways=ways, serve=serve), **files)
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    said = _said(res["output_tail"])
    assert res["returncode"] == 0, res["output_tail"]
    look = said.pop("the tests look at their own runner", "")
    assert look.startswith("got ") and look.endswith(" handles"), res["output_tail"]
    assert [w for w, what in said.items() if what != "got " + HELLO] == [], said
    assert res["blocked"] == [], res["blocked"]
    return said


@only_linux
def test_a_server_of_the_tests_own_is_reached_by_its_socket_file_in_every_way(tmp_path):
    """The safe twin, in a run as it is on this system: the tests start a server of their own at a socket file in
    their temp folder and at one in their copy of the project, and their programs below the guard reach it by its
    full name, by a name from its folder, through links, without waiting and from a program that left its
    parents; Python under the guard and Node reach it too, and so does a socket name that is no file where the
    names are the run's own. The sandbox refuses nothing."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    serve = ["file={TMP}/own.sock", "file={COPY}/own.sock"]
    ways = [(w, place) for place in ("{TMP}/own.sock", "{COPY}/own.sock") for w in OWN_FILE_WAYS]
    if not sandbox.own_network():
        name = "lantern-test-" + os.urandom(6).hex()
        serve.append("name=" + name)
        ways.append(("name", name))
    said = _honest(tmp_path, serve, ways)
    assert len(said) == len(ways) + 1 + bool(NODE), said


@only_linux
def test_with_a_network_of_their_own_the_tests_programs_call_each_other_by_address(tmp_path):
    """The safe twin of the addresses: in a network of the run's own, TCP (also with the data sent with the
    opening) and UDP between two programs of the tests work below the guard, and Node gets a page from a server
    it started, found by the name `localhost`."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    if sandbox.own_network():
        pytest.skip("this system gives a run no network of its own (" + sandbox.own_network() + ")")
    ways = [(w, "127.0.0.1") for w in ("tcp", "tcp, the data sent with the opening", "udp", "udp, connected first")]
    said = _honest(tmp_path, ["tcp", "udp"], ways, **{"web.js": NODE_WEB})
    assert len(said) == len(ways) + bool(NODE), said


@only_linux
def test_with_no_network_of_its_own_the_tests_own_socket_file_is_still_reached(tmp_path, monkeypatch):
    """The safe twin on a system that gives a run no network of its own: a socket file in the run's own folders
    is a file of the run's, whatever the network."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    monkeypatch.setattr(sandbox, "_OWN_NETWORK", ["this test takes the network of its own away"])
    ways = [(w, "{TMP}/own.sock") for w in OWN_FILE_WAYS]
    said = _honest(tmp_path, ["file={TMP}/own.sock"], ways)
    assert len(said) == len(ways) + 1 + bool(NODE), said


PYTHONS_OWN = '''
    import asyncio
    import multiprocessing
    import os
    import tempfile
    import unittest


    class T(unittest.TestCase):
        def test_a_manager(self):
            with multiprocessing.Manager() as manager:       # a server process, reached through a socket file
                shared = manager.dict()
                p = multiprocessing.Process(target=shared.update, args=({{"a": 1}},))
                p.start()
                p.join(60)
                self.assertEqual(dict(shared), {{"a": 1}})

        def test_a_pool_started_by_a_server(self):
            with multiprocessing.get_context("forkserver").Pool(2) as pool:
                self.assertEqual(pool.map(abs, [-1, -2, -3]), [1, 2, 3])

        def test_an_event_loop_with_a_socket_file(self):
            where = os.path.join(tempfile.gettempdir(), "loop.sock")

            async def answer(reader, writer):
                writer.write((await reader.readline()).upper())
                await writer.drain()
                writer.close()

            async def main():
                server = await asyncio.start_unix_server(answer, where)
                async with server:
                    reader, writer = await asyncio.open_unix_connection(where)
                    writer.write(b"hello\\n")
                    await writer.drain()
                    got = await reader.readline()
                    writer.close()
                    return got

            self.assertEqual(asyncio.run(main()), b"HELLO\\n")
'''


@only_linux
def test_pythons_own_ways_between_processes_work_behind_the_doorman(tmp_path):
    """The safe twin in Python itself: a manager (a server process reached through a socket file in the temp
    folder), a pool whose processes are started by a server, and an event loop that serves and calls a socket
    file. Three tests pass and the sandbox refuses nothing."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    if sandbox.own_memory():
        pytest.skip("this system gives a run no memory folder of its own (" + sandbox.own_memory() + ")")
    repo = _project(tmp_path / "tiny", PYTHONS_OWN.format())
    res = sandbox.run(repo, UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
    assert "Ran 3 tests" in res["output_tail"] and "OK" in res["output_tail"], res["output_tail"]
    assert res["blocked"] == [], res["blocked"]


# ---------------------------------------------------------------------------- the launcher by itself
HERE = Path(_jail.__file__).resolve().parent.parent
LAUNCH = "import sys; from lantern import _jail; _jail.KILLABLE = {killable!r}; _jail.main(sys.argv[1:])"
BELOW = [sys.executable, "-S"]          # a Python with no guard: what it asks for it asks of the kernel


def _launch(policy: dict, cmd: list[str], killable: bool = True):
    return subprocess.run([sys.executable, "-c", LAUNCH.format(killable=killable), json.dumps(policy), "--", *cmd],
                          capture_output=True, text=True, encoding="utf-8", timeout=180, cwd=HERE)


@pytest.fixture()
def place():
    """A folder a launcher's command may write in, whoever it runs as."""
    folder = Path(tempfile.mkdtemp(prefix="lantern-test-own-"))
    os.chmod(folder, 0o777)
    try:
        yield folder
    finally:
        assert sandbox._rm(folder) is True


def _policy(folder: Path, **more) -> dict:
    return {"writable": [str(folder)], "nobody": ROOT, "python": False, "net": True, "must": True, "sockets": True,
            **more}


def _file(folder: Path, name: str, text: str) -> str:
    (folder / name).write_text(text, encoding="utf-8")
    os.chmod(folder / name, 0o644)
    return str(folder / name)


# A server and its callers in one program below the guard: 8 threads of 50 calls each, or calls one after the other
# while a timer interrupts the program a thousand times a second, until 1,000 calls and 500 interruptions are counted.
MANY = r'''
import signal
import socket
import sys
import threading

where, how = sys.argv[1], sys.argv[2]
server = socket.socket(socket.AF_UNIX)
server.bind(where)
server.listen(128)


def serve():
    while True:
        conn, _ = server.accept()
        threading.Thread(target=answer, args=(conn,), daemon=True).start()


def answer(conn):
    try:
        conn.sendall(conn.recv(1))
    except OSError:
        pass
    conn.close()


def call(n, out):
    for _ in range(n):
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(where)
            s.sendall(b"x")
            if s.recv(1) == b"x":
                out.append(1)


threading.Thread(target=serve, daemon=True).start()
done, fired, calls = [], [], 400
if how == "storm":
    signal.signal(signal.SIGALRM, lambda *_: fired.append(1))
    signal.siginterrupt(signal.SIGALRM, False)   # a request a signal interrupted is made again, as most programs have it
    signal.setitimer(signal.ITIMER_REAL, 0.001, 0.001)
    calls = 0
    while (calls < 1000 or len(fired) < 500) and calls < 200000:
        call(1, done)
        calls += 1
    signal.setitimer(signal.ITIMER_REAL, 0)
else:
    threads = [threading.Thread(target=call, args=(50, done)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
print("got %d answers to %d calls, %d signals" % (len(done), calls, len(fired)))
'''


@only_linux
@pytest.mark.parametrize("killable", [True, False], ids=["kernels from 5.19", "older kernels"])
@pytest.mark.parametrize("how", ["at once", "storm"])
def test_many_connections_at_once_and_under_a_storm_of_signals(place, how, killable):
    """The safe twin under load: 400 connections from 8 threads at once, and 1,000 or more while a timer
    interrupts the program a thousand times a second (until 500 interruptions are counted, so no clock decides
    what was tested). Every one is made and answered, both the way newer kernels hold a signal back until the
    doorman answered and the way older ones hand the request back to be made again (where the doorman may have
    made the connection already: the second answer is then the first one's; until the doorman kept every
    connection it made in mind, 4 of 5,000 such calls were told "is connected already")."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    done = _launch(_policy(place), [*BELOW, _file(place, "many.py", MANY), str(place / "own.sock"), how], killable)
    assert done.returncode == 0, done.stderr
    answers, calls, signals = (int(n) for n in re.findall(r"\d+", done.stdout))
    assert answers == calls and calls >= (1000 if how == "storm" else 400), done.stdout
    assert signals >= 500 if how == "storm" else signals == 0, done.stdout
    assert "a doorman makes every connection" in done.stderr
    assert _jail.BLOCKED_MARK not in done.stderr, done.stderr


@only_linux
def test_a_run_ends_the_way_its_command_did_behind_the_doorman(place):
    """The command's own result is what the launcher ends with: a number, or the signal that ended it. A signal
    the command sends its parent, which is the doorman now, ends nothing (the kernel refuses it where it can, as
    it refused one for the launcher before there was a doorman; elsewhere the doorman passes it over), and
    connections go on being made."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    assert _launch(_policy(place), [*BELOW, "-c", "import sys; print('ran'); sys.exit(7)"]).returncode == 7
    done = _launch(_policy(place), [*BELOW, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"])
    assert done.returncode == -signal.SIGKILL, (done.returncode, done.stderr)
    goes_on = textwrap.dedent('''
        import os, signal, socket, sys
        refused = 0
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGUSR1):
            try:
                os.kill(os.getppid(), number)
            except PermissionError:
                refused += 1
        server = socket.socket(socket.AF_UNIX)
        server.bind(sys.argv[1])
        server.listen(1)
        socket.socket(socket.AF_UNIX).connect(sys.argv[1])
        print("connected after the signals, %d refused" % refused)
    ''')
    done = _launch(_policy(place), [*BELOW, "-c", goes_on, str(place / "own.sock")])
    assert done.returncode == 0 and "connected after the signals" in done.stdout, (done.stdout, done.stderr)
    assert ("4 refused" if sandbox.landlock_abi() >= 6 else "0 refused") in done.stdout, done.stdout


# The tests try to end and to stop their doorman (it is their parent and their own user, and these are the two
# signals nothing can pass over), then go on as tests do: a server of their own, and the other program's socket file.
SIGNAL_THE_DOORMAN = r'''
import os
import signal
import socket
import sys

for number in (signal.SIGKILL, signal.SIGSTOP):
    try:
        os.kill(os.getppid(), number)
        print("sent", int(number))
    except PermissionError:
        print("refused", int(number))
server = socket.socket(socket.AF_UNIX)
server.bind(sys.argv[1])
server.listen(1)
socket.socket(socket.AF_UNIX).connect(sys.argv[1])
try:
    socket.socket(socket.AF_UNIX).connect(sys.argv[2])
    print("reached the other program")
except OSError as e:
    print("the other program:", type(e).__name__)
print("still here")
'''


@only_linux
def test_tests_cannot_end_or_stop_their_doorman_where_the_kernel_can_refuse_it(place, outside):
    '''The doorman is the tests' parent and of their user. Where the kernel can refuse a signal the tests are put
    one domain below it, so neither signal arrives, the run goes on, a server of the tests' own is reached and the
    other program is not. (Until this was done the tests could end their doorman here: nothing got through then,
    but an older test, that a test cannot signal the program that guards it, failed.)'''
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    if sandbox.landlock_abi() < 6:
        pytest.skip("needs a kernel whose Landlock can refuse signals (ABI 6, Linux 6.12)")
    done = _launch(_policy(place), [*BELOW, _file(place, "ask.py", SIGNAL_THE_DOORMAN), str(place / "own.sock"),
                                    str(outside.bus)])
    assert done.returncode == 0, (done.returncode, done.stdout, done.stderr)
    assert f"refused {int(signal.SIGKILL)}" in done.stdout and f"refused {int(signal.SIGSTOP)}" in done.stdout
    assert "sent" not in done.stdout and "still here" in done.stdout, done.stdout
    assert "the other program: PermissionError" in done.stdout, done.stdout
    assert outside.reached == []
    assert "a signal of the tests can reach their doorman" not in done.stderr, done.stderr


# The tests' first program says who its doorman is and waits, while a program of theirs that left its parents goes
# on asking for the other program's socket file.
AFTER_THE_DOORMAN = r'''
import os
import socket
import sys
import time

if os.fork() == 0:
    os.setsid()
    until = time.monotonic() + 3
    while time.monotonic() < until:
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(sys.argv[1])
        except OSError:
            pass
        time.sleep(0.001)
    os._exit(0)
time.sleep(0.3)
with open(sys.argv[2] + ".part", "w") as f:
    f.write(str(os.getppid()))
os.rename(sys.argv[2] + ".part", sys.argv[2])
time.sleep(8)
print("still here")
'''


@only_linux
def test_a_doorman_that_is_ended_lets_nothing_through_afterwards(place, outside):
    '''The dangerous twin against the doorman itself. Whatever ends it (the tests themselves on a kernel that
    cannot refuse their signal, the system when it is short of memory; here this test, from outside), the kernel
    refuses what would have been asked of it, the command is ended with it, and the launcher ends everything that
    is left: the other program hears nothing, before or after.'''
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    ready = place / "ready"
    cmd = [*BELOW, _file(place, "after.py", AFTER_THE_DOORMAN), str(outside.bus), str(ready)]
    run = subprocess.Popen([sys.executable, "-c", LAUNCH.format(killable=True), json.dumps(_policy(place)), "--", *cmd],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", cwd=HERE)
    try:
        until = time.monotonic() + 60
        while not ready.exists() and run.poll() is None and time.monotonic() < until:
            time.sleep(0.02)
        doorman = int(ready.read_text(encoding="utf-8"))
        status = Path(f"/proc/{doorman}/status").read_text(encoding="utf-8")
        assert f"PPid:\t{run.pid}\n" in status, status       # the launcher's own child, and nobody else
        os.kill(doorman, signal.SIGKILL)
        out, err = run.communicate(timeout=120)
    finally:
        if run.poll() is None:
            run.kill()
            run.communicate()
    assert outside.reached == []
    assert run.returncode == -signal.SIGKILL, (run.returncode, err)
    assert "still here" not in out
    assert str(outside.bus) in err and _jail.BLOCKED_MARK in err, err


@only_linux
def test_a_run_inside_a_run_keeps_the_outer_doorman_and_says_so(place):
    """The kernel hears one doorman for a program. A launcher that must have its own and is itself behind one
    starts nothing (so Lantern asks first, `own_sockets`, and then asks for none); one that need not carries on
    and says so, and what it starts is still behind the outer doorman, which judges by the outer run's folders."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    inner = [sys.executable, "-c", LAUNCH.format(killable=True)]
    tail = ["--", *BELOW, "-c", "print('ran')"]
    done = _launch(_policy(place), [*inner, json.dumps(_policy(place, nobody=False)), *tail])
    assert done.returncode == _jail.UNAVAILABLE, (done.returncode, done.stderr)
    assert f"{_jail.MARK} own-sockets {errno.EBUSY}" in done.stderr, done.stderr
    assert "ran" not in done.stdout
    done = _launch(_policy(place), [*inner, json.dumps(_policy(place, nobody=False, must=False)), *tail])
    assert done.returncode == 0 and "ran" in done.stdout, (done.returncode, done.stderr)
    assert "carrying on without it" in done.stderr, done.stderr


@only_linux
def test_a_socket_file_with_a_second_name_is_not_reached_and_the_run_says_why(place):
    """A socket file in the run's own folders that has a second name somewhere (a hard link) may be another
    program's, brought in under a name of the run's: where the kernel's rules for files are missing, nothing else
    stops such a link. It is refused, also when the tests made both names themselves, and that is said."""
    if not _can():
        pytest.skip("this system gives a run no doorman of its own (" + sandbox.own_sockets() + ")")
    twice = textwrap.dedent('''
        import os, socket, sys
        server = socket.socket(socket.AF_UNIX)
        server.bind(sys.argv[1])
        server.listen(1)
        os.link(sys.argv[1], sys.argv[1] + ".second")
        for name in (sys.argv[1], sys.argv[1] + ".second"):
            try:
                socket.socket(socket.AF_UNIX).connect(name)
                print("connected")
            except OSError as e:
                print("refused", e.errno)
    ''')
    done = _launch(_policy(place), [*BELOW, "-c", twice, str(place / "own.sock")])
    assert done.stdout.split() == ["refused", str(errno.EACCES)] * 2, (done.stdout, done.stderr)
    assert done.stderr.count(_jail.BLOCKED_MARK) == 2 and done.stderr.count("second name") == 2, done.stderr


def test_what_the_doorman_says_is_read_as_the_sandboxs_doing():
    """Each refusal is a line the run's result sorts under what was refused, so tests that failed for it are not
    counted as tests that failed."""
    assert _jail.BLOCKED_MARK == sandbox.MARK
    for word, text in _jail.SAID.items():
        line = f"{_jail.BLOCKED_MARK} {text.format(where='/run/user/1000/bus')}"
        (one,) = sandbox.blocked_reasons("the tests' own output\n" + line + "\n")
        assert one["kind"] == ("write" if word == "older" else "network"), (word, one)


@pytest.mark.parametrize("machine", sorted(_jail._CALLS))
def test_the_kernels_half_of_the_doorman_is_made_for_each_kind_of_processor(machine):
    for own_net in (True, False):
        for own_ipc in (True, False):
            program = _jail._filter(_jail._CALLS[machine], own_net, own_ipc)
            assert len(program) % 8 == 0 and 30 <= len(program) // 8 <= 255, (machine, own_net, own_ipc)


@only_linux
def test_the_sheet_and_the_log_say_whether_a_doorman_stands(tmp_path, monkeypatch):
    """Where this system lets Lantern make no doorman, the sheet a person reads before the run and the run's log
    say so in their words, the result records it, and the tests still run."""
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    monkeypatch.setattr(sandbox, "_OWN_SOCKETS", [""])
    sheet = " ".join(sandbox.describe(tmp_path, "python")["details"])
    assert "Lantern's doorman" in sheet and "can still connect" not in sheet
    monkeypatch.setattr(sandbox, "_OWN_SOCKETS", ["this test takes the doorman away"])
    sheet = " ".join(sandbox.describe(tmp_path, "python")["details"])
    assert "this test takes the doorman away, so a program the tests start that is not Python can still" in sheet
    repo = _project(tmp_path / "tiny", '''
        import unittest


        class T(unittest.TestCase):
            def test_it(self):
                self.assertTrue(True)
    ''')
    lines: list[str] = []
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    assert res["returncode"] == 0 and res["own_sockets"] is False, res["output_tail"]
    assert len([line for line in lines if "the tests have no doorman of their own" in line]) == 1, lines
    assert not [line for line in lines if "a doorman makes every connection" in line], lines
