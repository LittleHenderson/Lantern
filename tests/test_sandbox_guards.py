"""The sandbox's guard beside a project's own (2026-11-13).

Two things Lantern's own tests showed when Lantern ran them in its sandbox, where they met the sandbox's guard
before their own:

**An address written as a number is no question to the network.** `getaddrinfo("192.0.2.1", 443)` asks no name
server anything: the answer is the number itself. The guard refused it as a "lookup" all the same, so a test that
only wrote an address down failed, and so did every server a test starts at `0.0.0.0` through an event loop (the
loop asks `getaddrinfo` for the address it was given). A name is still refused, and so is whatever is not surely a
number, and so is asking who a number belongs to.

**A project that brings a guard of its own gets its say first.** Audit hooks run in the order they were added and
the sandbox's is added first, so until then a project's own hook (Lantern's `tools/netguard`) never saw what the
sandbox refused: its tests of its own refusals failed in the sandbox with the sandbox's words. Now the sandbox's
hook writes its line down and leaves the refusing to a hook of its own that stands after every hook the project
added: the project's guard may refuse its own way first, and whatever it lets through is refused as before.
Each case here stands beside the twin in which the project's hook lets the thing through, which must be refused."""
import os
import socket
import sys
from types import SimpleNamespace

import pytest
from test_sandbox import BACKENDS, _guard_alone

from lantern import sandbox

PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]


def QUIET(line):
    """A log nobody reads."""


def _failed(out: str) -> set[str]:
    """The names of the tests pytest's summary says failed."""
    return {line.split("::", 1)[1].split(" ", 1)[0] for line in out.splitlines()
            if line.startswith("FAILED ") and "::" in line}


def _project(folder, source: str, conftest: str = ""):
    (folder / "tests").mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "tests" / "test_tiny.py").write_text(source, encoding="utf-8")
    if conftest:
        (folder / "conftest.py").write_text(conftest, encoding="utf-8")
    return folder


def _six() -> bool:
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
    except OSError:
        return False
    return True


# ----------------------------------------------------------------------------- a number is no question
NUMBERS = '''
    import socket
    def tried(what, do):
        try:
            got = do()
        except PermissionError:
            print("refused:", what)
        except OSError:
            print("answered:", what)        # by the guard; what the system then said is another matter
        else:
            print("answered:", what, got if isinstance(got, str) else "")
    info = socket.getaddrinfo
    tried("192.0.2.1", lambda: info("192.0.2.1", 443)[0][4][0])
    tried("192.0.2.1 by name", lambda: socket.gethostbyname("192.0.2.1"))
    tried("192.0.2.1 with its other names", lambda: socket.gethostbyname_ex("192.0.2.1")[2][0])
    tried("192.0.2.1 as bytes", lambda: info(b"192.0.2.1", 80)[0][4][0])
    tried("0.0.0.0", lambda: info("0.0.0.0", 8000)[0][4][0])
    tried("255.255.255.255", lambda: info("255.255.255.255", 9)[0][4][0])
    tried("2001:db8::1", lambda: info("2001:db8::1", 80)[0][4][0])
    tried("::", lambda: info("::", 80)[0][4][0])
    tried("::ffff:192.0.2.1", lambda: info("::ffff:192.0.2.1", 80) and "")
    for name in ("example.invalid", "192.0.2.1.example.invalid", "192.0.2.256", "192.0.2", "1.2.3.4.5", "0x7f.0.0.1",
                 "0300.0.2.1", " 192.0.2.1", "192.0.2.1 ", "192.0.2.1\\n", "\\uff11\\uff19\\uff12.0.2.1", "1.2.3.-4",
                 "2001:db8::1%eth0", "::g", ":", "2001:db8::1.example.invalid"):
        tried("the name " + ascii(name), lambda: info(name, 80))
    tried("the name 'example.invalid' by name", lambda: socket.gethostbyname("example.invalid"))
    tried("the name '192.0.2.256' by name", lambda: socket.gethostbyname("192.0.2.256"))
    tried("who 192.0.2.1 is", lambda: socket.gethostbyaddr("192.0.2.1"))
'''
ANSWERED = ["answered: 192.0.2.1 192.0.2.1", "answered: 192.0.2.1 by name 192.0.2.1",
            "answered: 192.0.2.1 with its other names 192.0.2.1", "answered: 192.0.2.1 as bytes 192.0.2.1",
            "answered: 0.0.0.0 0.0.0.0", "answered: 255.255.255.255 255.255.255.255"]
NAMES = ["example.invalid", "192.0.2.1.example.invalid", "192.0.2.256", "192.0.2", "1.2.3.4.5", "0x7f.0.0.1",
         "0300.0.2.1", " 192.0.2.1", "192.0.2.1 ", "192.0.2.1\n", "１９２.0.2.1", "1.2.3.-4",
         "2001:db8::1%eth0", "::g", ":", "2001:db8::1.example.invalid"]


def test_an_address_written_as_a_number_is_answered_and_a_name_is_still_refused(tmp_path):
    """With the guard and nothing else around it. What is not surely a number counts as a name: a number with a
    part over 255 or a part missing, one written in another base, one with a space or a line end beside it, digits
    that are not the plain ones, an IPv6 address with a network card's name on it."""
    r = _guard_alone(tmp_path, NUMBERS)
    lines = r.stdout.splitlines()
    assert lines[:6] == ANSWERED, r.stdout + r.stderr[-1500:]
    assert [line.split(" ", 1)[0] for line in lines[6:9]] == ["answered:"] * 3, r.stdout     # the IPv6 ones: any answer
    assert lines[9:] == (["refused: the name " + ascii(n) for n in NAMES]
                         + ["refused: the name 'example.invalid' by name", "refused: the name '192.0.2.256' by name",
                            "refused: who 192.0.2.1 is"]), r.stdout + r.stderr[-1500:]
    written = [line for line in r.stderr.splitlines() if line.startswith(sandbox.MARK)]
    assert len(written) == len(NAMES) + 3, r.stderr[-3000:]            # one line for each refusal and for nothing else
    assert sandbox.MARK + " network lookup 'example.invalid'" in written
    assert sandbox.MARK + " network lookup '192.0.2.256'" in written
    # the one line about 192.0.2.1 is the last: who it is. Writing it down made none.
    assert [n for n, line in enumerate(written) if line == sandbox.MARK + " network lookup '192.0.2.1'"] == [len(written) - 1], written


def test_going_to_the_number_is_still_refused_and_the_line_says_where_to(tmp_path):
    """Writing the address down is let through; setting out for it is what the guard refuses, and its line now
    names the connection (until then it named the lookup the standard library makes first)."""
    r = _guard_alone(tmp_path, '''
        import socket
        for what, do in (("a connection", lambda: socket.create_connection(("192.0.2.1", 9), timeout=0.01)),
                         ("a datagram", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 53)))):
            try:
                do()
            except PermissionError as e:
                print("refused:", what, "|", e)
            except OSError as e:
                print("let through:", what, "|", e)
            else:
                print("let through:", what)
    ''')
    assert r.stdout.splitlines() == [
        "refused: a connection | " + sandbox.MARK + " network connect ('192.0.2.1', 9)",
        "refused: a datagram | " + sandbox.MARK + " network sendto ('192.0.2.1', 53)"], r.stdout + r.stderr[-1500:]
    assert "lookup" not in r.stderr, r.stderr[-1500:]


WRITES_NUMBERS = '''
import asyncio, socket

def test_an_address_written_down_is_answered():
    assert socket.getaddrinfo("192.0.2.1", 443)[0][4][0] == "192.0.2.1"
    assert socket.gethostbyname("192.0.2.1") == "192.0.2.1"
    assert socket.getaddrinfo("0.0.0.0", 8000)[0][4][0] == "0.0.0.0"

def test_a_server_of_the_tests_own_at_every_address_of_this_computer():
    if not OWN:
        return
    async def main():
        async def hello(reader, writer):
            writer.write(b"hello")
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(hello, "0.0.0.0", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        got = await reader.read(5)
        writer.close()
        server.close()
        await server.wait_closed()
        return got
    assert asyncio.run(main()) == b"hello"
'''
ASKS_A_NAME = '''
import socket

def test_a_name_is_asked_for():
    socket.getaddrinfo("example.invalid", 80)

def test_who_a_number_is():
    socket.gethostbyaddr("192.0.2.1")

def test_the_number_itself_is_gone_to():
    socket.create_connection(("192.0.2.1", 9), timeout=1)

def test_an_address_written_down_is_answered():
    assert socket.gethostbyname("192.0.2.1") == "192.0.2.1"
'''


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_that_write_an_address_down_pass_in_the_sandbox(backend, tmp_path):
    own = backend == "docker" or sandbox.own_network() == ""
    r = sandbox.run(_project(tmp_path / "tiny", f"OWN = {own}\n" + WRITES_NUMBERS), PYTEST, log=QUIET, backend=backend)
    assert r["returncode"] == 0, r["output_tail"]
    assert r["blocked"] == []


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_twin_that_asks_for_a_name_or_goes_to_the_number_is_refused_and_written_down(backend, tmp_path):
    r = sandbox.run(_project(tmp_path / "tiny", ASKS_A_NAME), PYTEST, log=QUIET, backend=backend)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    assert _failed(out) == {"test_a_name_is_asked_for", "test_who_a_number_is", "test_the_number_itself_is_gone_to"}, out
    assert {b["kind"] for b in r["blocked"]} == {"network"}, r["blocked"]
    said = [b["what"] for b in r["blocked"]]
    assert "network lookup 'example.invalid'" in said and "network lookup '192.0.2.1'" in said, said     # the second: who it is
    assert "network connect ('192.0.2.1', 9)" in said, said


# ----------------------------------------------------------------------------- a guard of the project's own
OWN_GUARD = '''
    import os, socket, sys, threading
    MODE, OUTSIDE = sys.argv[1], sys.argv[2]
    seen, inside = [], []
    def mine(event, args):
        if event == "socket.connect" and not inside:
            seen.append(args[1])
            if MODE == "refuses":
                raise OSError("MY-GUARD: no way out to %r" % (args[1],))
            if MODE == "busy":                      # a guard that does things of its own while it looks
                inside.append(1)
                with open(__file__ if "__file__" in globals() else os.devnull) as f:
                    f.read(1)
                socket.getaddrinfo("127.0.0.1", 80)
                compile("1 + 1", "<mine>", "eval")
                import json
                json.dumps(args[1])
                try:
                    open(os.path.join(OUTSIDE, "by-the-guard.txt"), "w")
                except OSError:
                    pass                            # refused, as it must be; the guard carries on
                try:
                    socket.socket().connect(("192.0.2.2", 9))     # refused too, in the middle of the first one
                except OSError:
                    pass
                inside.clear()
        if event == "open" and MODE == "refuses" and len(args) > 1 and isinstance(args[1], str) and "w" in args[1] \\
                and str(args[0]).startswith(OUTSIDE):
            raise OSError("MY-GUARD: not written: " + os.path.basename(str(args[0])))
    def tried(what, do):
        try:
            do()
        except OSError as e:
            print(what + ":", type(e).__name__, str(e).replace(OUTSIDE, "OUTSIDE").replace("\\\\", "/"))
        else:
            print(what + ": LET THROUGH")
    def call():
        with socket.socket() as s:
            s.settimeout(0.01)
            s.connect(("192.0.2.1", 9))
    def write():
        with open(os.path.join(OUTSIDE, "planted.txt"), "w") as f:
            f.write("x")
'''


def _with_own_guard(tmp_path, mode: str, rest: str):
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    r = _guard_alone(tmp_path, OWN_GUARD + rest, mode, str(outside))
    return r, outside


SIMPLY = '''
    sys.addaudithook(mine)
    import string                     # anything at all happens between the guard's arrival and the first try
    tried("a connection", call)
    tried("a file outside", write)
    print("the project's guard saw", [a for a in seen if a[0] == "192.0.2.1"])
'''
BOX_CONNECT = "PermissionError " + sandbox.MARK + " network connect ('192.0.2.1', 9)"
BOX_WRITE = "PermissionError " + sandbox.MARK + " write to OUTSIDE/planted.txt"


def test_a_guard_the_project_brings_refuses_its_own_way_first(tmp_path):
    r, outside = _with_own_guard(tmp_path, "refuses", SIMPLY)
    assert r.stdout.splitlines() == ["a connection: OSError MY-GUARD: no way out to ('192.0.2.1', 9)",
                                     "a file outside: OSError MY-GUARD: not written: planted.txt",
                                     "the project's guard saw [('192.0.2.1', 9)]"], r.stdout + r.stderr[-1500:]
    assert list(outside.iterdir()) == []
    # what the tests reached for is written down all the same, so the run's record names it
    assert sandbox.MARK + " network connect ('192.0.2.1', 9)" in r.stderr and sandbox.MARK + " write to " in r.stderr


@pytest.mark.parametrize("mode", ["watches", "busy"])
def test_the_twin_whose_guard_lets_it_through_is_refused_by_the_sandbox(mode, tmp_path):
    """The project's hook sees the event and says nothing (or does a good deal of its own while it looks, some of
    it refused in its turn): the sandbox's refusal comes after it, with the words it always had."""
    r, outside = _with_own_guard(tmp_path, mode, SIMPLY)
    assert r.stdout.splitlines() == ["a connection: " + BOX_CONNECT, "a file outside: " + BOX_WRITE,
                                     "the project's guard saw [('192.0.2.1', 9)]"], r.stdout + r.stderr[-1500:]
    assert list(outside.iterdir()) == []


def test_a_guard_that_arrives_just_before_the_try_changes_nothing(tmp_path):
    """Nothing happens between the hook's arrival and the connection: refused all the same (by the sandbox, which
    has not yet put its own last hook behind the newcomer and so refuses at once)."""
    r, outside = _with_own_guard(tmp_path, "watches", '''
    s = socket.socket()
    s.settimeout(0.01)
    w = lambda: os.mkdir(os.path.join(OUTSIDE, "planted"))
    sys.addaudithook(mine)
    tried("a connection", lambda: s.connect(("192.0.2.1", 9)))
    sys.addaudithook(lambda event, args: None)
    tried("a folder outside", w)
    ''')
    assert r.stdout.splitlines() == ["a connection: " + BOX_CONNECT,
                                     "a folder outside: PermissionError " + sandbox.MARK + " mkdir OUTSIDE/planted"], r.stdout + r.stderr[-1500:]
    assert list(outside.iterdir()) == []


def test_many_guards_one_after_another_and_one_added_by_another_change_nothing(tmp_path):
    r, outside = _with_own_guard(tmp_path, "watches", '''
    saw = []
    def adds_another(event, args):
        if event == "socket.connect" and not saw:
            saw.append(1)
            sys.addaudithook(mine)                 # a hook that arrives in the middle of the very event
    for i in range(40):
        sys.addaudithook(lambda event, args, i=i: None)
        if i % 3 == 0:
            import string
            compile("1", "<x>", "eval")
    sys.addaudithook(adds_another)
    for n in range(3):
        tried("a connection", call)
        tried("a file outside", write)
    ''')
    assert r.stdout.splitlines() == ["a connection: " + BOX_CONNECT, "a file outside: " + BOX_WRITE] * 3, r.stdout + r.stderr[-1500:]
    assert list(outside.iterdir()) == []


def test_a_refusal_the_projects_guard_made_is_not_carried_over_to_what_is_allowed(tmp_path):
    """2,000 times: the project's guard refuses a file outside, then the program writes a file of its own. No
    write of its own is refused for the one before it, and when the project's guard stops refusing the sandbox's
    refusal is there."""
    r, outside = _with_own_guard(tmp_path, "refuses", '''
    sys.addaudithook(mine)
    own = refused = 0
    for n in range(2000):
        try:
            write()
        except OSError as e:
            refused += "MY-GUARD" in str(e)
        try:
            with open("mine-%d.txt" % (n % 7), "w") as f:
                f.write("x")
            os.replace("mine-%d.txt" % (n % 7), "kept.txt")
            own += 1
        except OSError as e:
            print("a file of its own was refused:", e)
            break
    print("refused its own way", refused, "wrote its own", own)
    MODE = "watches"
    tried("a file outside", write)
    tried("a connection", call)
    ''')
    assert r.stdout.splitlines() == ["refused its own way 2000 wrote its own 2000", "a file outside: " + BOX_WRITE,
                                     "a connection: " + BOX_CONNECT], r.stdout[-2000:] + r.stderr[-1500:]
    assert list(outside.iterdir()) == []


def test_threads_that_bring_guards_while_others_try_are_all_refused(tmp_path):
    r, outside = _with_own_guard(tmp_path, "watches", '''
    through, tries, lock = [], [0], threading.Lock()
    def work(k):
        for n in range(60):
            if n % 10 == k % 10:
                sys.addaudithook(lambda event, args: None)
            for do in (call, write, lambda: os.mkdir(os.path.join(OUTSIDE, "d%d-%d" % (k, n)))):
                try:
                    do()
                except PermissionError:
                    with lock:
                        tries[0] += 1
                except OSError as e:
                    through.append(repr(e))
                else:
                    through.append("no error")
    threads = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    print("refused", tries[0], "let through", through[:3])
    ''')
    assert r.stdout.splitlines() == ["refused 1440 let through []"], r.stdout + r.stderr[-1500:]
    assert list(outside.iterdir()) == []


CONFTEST = '''
import sys

def guard(event, args):
    if event == "socket.connect" and MODE == "refuses" and isinstance(args[1], tuple) and not str(args[1][0]).startswith("127."):
        raise OSError("MY-GUARD: no way out to %s:%s" % args[1][:2])

sys.addaudithook(guard)
'''
ITS_OWN_REFUSALS = '''
import socket
import pytest

def test_my_guard_refuses_an_address_outside():
    with pytest.raises(OSError, match="MY-GUARD: no way out to 192.0.2.1:9"):
        socket.create_connection(("192.0.2.1", 9), timeout=1)

def test_and_tells_me_so_in_a_thread_too():
    import threading
    said = []
    def work():
        try:
            socket.create_connection(("192.0.2.1", 9), timeout=1)
        except OSError as e:
            said.append(str(e))
    t = threading.Thread(target=work)
    t.start()
    t.join(30)
    assert said == ["MY-GUARD: no way out to 192.0.2.1:9"]
'''
GOES_OUT = '''
import socket

def test_it_just_goes_there():
    socket.create_connection(("192.0.2.1", 9), timeout=1)
'''


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_projects_tests_of_its_own_guard_pass_in_the_sandbox(backend, tmp_path):
    """What Lantern's own tests do (`tests/test_netguard.py`): they reach for an outside address on purpose and
    look at their own guard's refusal. The run passes, and what was reached for is still on its record."""
    repo = _project(tmp_path / "tiny", ITS_OWN_REFUSALS, 'MODE = "refuses"\n' + CONFTEST)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend)
    assert r["returncode"] == 0, r["output_tail"]
    assert [b for b in r["blocked"] if b["kind"] == "network"] == [{"kind": "network", "what": "network connect ('192.0.2.1', 9)"}]


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_twin_whose_guard_refuses_nothing_is_refused_and_written_down(backend, tmp_path):
    repo = _project(tmp_path / "tiny", GOES_OUT, 'MODE = "sleeps"\n' + CONFTEST)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend)
    out = r["output_tail"]
    assert r["returncode"] == 1, out
    assert _failed(out) == {"test_it_just_goes_there"}, out
    assert "PermissionError" in out and sandbox.MARK + " network connect ('192.0.2.1', 9)" in out, out
    assert {"kind": "network", "what": "network connect ('192.0.2.1', 9)"} in r["blocked"], r["blocked"]


# ----------------------------------------------------------------------------- an open folder too deep to name
DEEP = '''
    import os, sys
    LEVELS, OUTSIDE, FAR, NAME = int(sys.argv[1]), sys.argv[2], sys.argv[3], "d" * 200
    def down(top, make):
        fd = os.open(top, os.O_RDONLY)
        for n in range(LEVELS):
            if make:
                os.mkdir(NAME, dir_fd=fd)
            below = os.open(NAME, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = below
        return fd
    def tried(what, do):
        try:
            do()
        except PermissionError:
            print("refused:", what)
        except OSError as e:
            print("let through:", what, "(the system said", type(e).__name__ + ")")
        else:
            print("let through:", what)
    try:
        mine = down(".", True)
    except PermissionError as e:
        sys.exit("the folders of its own could not be made: " + str(e)[:80])
    tried("a folder beside it", lambda: os.mkdir("made", dir_fd=mine))
    tried("that folder renamed", lambda: os.rename("made", "kept", src_dir_fd=mine, dst_dir_fd=mine))
    tried("that folder removed", lambda: os.rmdir("kept", dir_fd=mine))
    tried("a link out, made there", lambda: os.symlink(OUTSIDE, "link", dir_fd=mine))
    tried("a folder through the link", lambda: os.mkdir(os.path.join("link", "planted"), dir_fd=mine))
    tried("a change to what the link names", lambda: os.chmod("link", 0o777, dir_fd=mine))
    tried("the link removed, as the name it is", lambda: os.unlink("link", dir_fd=mine))
    tried("a folder named from there upwards and out", lambda: os.mkdir("../" * (LEVELS + 1) + "planted-up", dir_fd=mine))
    tried("a folder named by where it is, outside", lambda: os.mkdir(os.path.join(OUTSIDE, "planted-full"), dir_fd=mine))
    theirs = down(FAR, False)
    tried("a folder beside a deep folder outside", lambda: os.mkdir("planted", dir_fd=theirs))
    tried("a file removed from a deep folder outside", lambda: os.unlink("kept.txt", dir_fd=theirs))
'''


@pytest.mark.skipif(os.mkdir not in os.supports_dir_fd, reason="this system names nothing beside an open folder")
def test_a_name_beside_an_open_folder_too_deep_to_name_is_placed_by_going_up_from_it(tmp_path):
    """Forty folders with long names inside each other: the path of the last is longer than the system hands back,
    so until then the guard could not say where a name beside it lies and refused it (`tests/test_removal.py` builds
    such a nest, 2,500 deep, and failed in the sandbox for it). Now the guard goes up from the folder, one folder at
    a time, to one it can place. One plain name only: a name with a folder in it, what a link there names, a deep
    folder outside are refused. The link itself is removed like any name (the test's own tidying-up does that)."""
    from lantern import removal
    levels = 40
    outside, far = tmp_path / "outside", tmp_path / "far"
    outside.mkdir()
    far.mkdir()
    fd = os.open(far, os.O_RDONLY)
    try:
        for _ in range(levels):
            os.mkdir("d" * 200, dir_fd=fd)
            below = os.open("d" * 200, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = below
        with open(os.open("kept.txt", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
            f.write("kept")
        try:
            r = _guard_alone(tmp_path, DEEP, str(levels), str(outside), str(far))
            assert r.stdout.splitlines() == [
                "let through: a folder beside it", "let through: that folder renamed", "let through: that folder removed",
                "let through: a link out, made there", "refused: a folder through the link",
                "refused: a change to what the link names", "let through: the link removed, as the name it is",
                "refused: a folder named from there upwards and out",
                "refused: a folder named by where it is, outside", "refused: a folder beside a deep folder outside",
                "refused: a file removed from a deep folder outside"], r.stdout + r.stderr[-1500:]
            assert os.listdir(fd) == ["kept.txt"] and os.listdir(outside) == []
            assert sorted(os.listdir(tmp_path)) == ["far", "hook", "outside", "room"]
        finally:
            os.close(fd)
    finally:
        left = [removal.remove(tmp_path / name) for name in ("far", "room")]
    assert left == [None, None], left


# ----------------------------------------------------------------------------- a link is a name
LINKS = '''
    import os, shutil, sys, tempfile
    THEIRS, THEIR_FOLDER, THEIR_EMPTY = sys.argv[1:4]
    def tried(what, do):
        try:
            do()
        except PermissionError:
            print("refused:", what)
        except OSError as e:
            print("allowed:", what, "(the system said " + type(e).__name__ + ")")
        else:
            print("allowed:", what)
    def write(name, text="mine"):
        with open(name, "w") as f:
            f.write(text)
'''

AS_A_NAME = LINKS + '''
    os.symlink(THEIRS, "link")
    tried("a link out renamed", lambda: os.rename("link", "moved"))
    write("old")
    tried("a link out put in the place of a file", lambda: os.replace("moved", "old"))
    tried("a link out removed", lambda: os.remove("old"))
    os.mkdir("tree")
    os.symlink(THEIRS, os.path.join("tree", "a"))
    os.symlink(THEIR_FOLDER, os.path.join("tree", "b"))
    tried("a folder that holds links out removed with all in it", lambda: shutil.rmtree("tree"))
    def temp():
        with tempfile.TemporaryDirectory(dir=".") as t:
            os.symlink(sys.executable, os.path.join(t, "python"))
    tried("a temp folder with a link to the Python that runs, tidied away", temp)
    os.symlink(THEIR_FOLDER, "folder-link")
    tried("a link to a folder outside removed", lambda: os.remove("folder-link"))
    if os.unlink in os.supports_dir_fd:
        os.symlink(THEIRS, "again")
        fd = os.open(".", os.O_RDONLY)
        tried("a link out removed beside an open folder", lambda: os.unlink("again", dir_fd=fd))
    print("left:", sorted(os.listdir(".")))
'''

THROUGH_IT = LINKS + '''
    os.symlink(THEIRS, "link")
    os.symlink(THEIR_FOLDER, "folder")
    os.symlink(THEIR_EMPTY, "empty")
    write("mine.txt")
    tried("a write through a link out", lambda: write("link"))
    tried("what the link names cut short", lambda: os.truncate("link", 0))
    tried("the rights of what the link names changed", lambda: os.chmod("link", 0o600))
    tried("the dates of what the link names changed", lambda: os.utime("link"))
    tried("a file copied onto what the link names", lambda: shutil.copyfile("mine.txt", "link"))
    tried("a file removed through a link to a folder", lambda: os.remove(os.path.join("folder", "inner.txt")))
    tried("a folder made through a link to a folder", lambda: os.mkdir(os.path.join("folder", "planted")))
    tried("a file taken out through a link to a folder", lambda: os.rename(os.path.join("folder", "inner.txt"), "got.txt"))
    tried("a file put in through a link to a folder", lambda: os.rename("mine.txt", os.path.join("folder", "planted.txt")))
    tried("a link made through a link to a folder", lambda: os.symlink("x", os.path.join("folder", "planted-link")))
    tried("the folder a link names removed, named with a slash at its end", lambda: os.rmdir("empty" + os.sep))
    tried("the folder a link names renamed, named with a slash at its end", lambda: os.rename("empty" + os.sep, "taken"))
    tried("the folder a link names removed with all in it, named with a slash", lambda: shutil.rmtree("folder" + os.sep))
    print("left:", sorted(os.listdir(".")))
'''

SECOND_NAME = LINKS + '''
    tried("a second name here for a file outside", lambda: os.link(THEIRS, "second"))
    if os.path.exists("second"):
        tried("and a write under that name", lambda: write("second", "changed"))
    write("own.txt")
    tried("a second name for a file of its own", lambda: os.link("own.txt", "own-too.txt"))
    print("left:", sorted(os.listdir(".")))
'''


@pytest.fixture
def theirs(tmp_path):
    """What is somebody else's, outside the folder the guarded program may write in: a file, a folder with a file in
    it, and an empty folder. `intact()` says whether all of it is as it was."""
    file, folder, empty = tmp_path / "theirs.txt", tmp_path / "their-folder", tmp_path / "their-empty"
    file.write_text("theirs", encoding="utf-8")
    folder.mkdir()
    (folder / "inner.txt").write_text("theirs too", encoding="utf-8")
    empty.mkdir()

    def intact():
        return (file.read_text(encoding="utf-8") == "theirs" and os.listdir(folder) == ["inner.txt"]
                and (folder / "inner.txt").read_text(encoding="utf-8") == "theirs too" and os.listdir(empty) == [])
    return SimpleNamespace(args=(str(file), str(folder), str(empty)), intact=intact)


def _links_can_be_made(tmp_path) -> None:
    try:
        os.symlink("nowhere", tmp_path / "probe-link")
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("this system does not let this user make a link")
    os.remove(tmp_path / "probe-link")


def test_a_link_is_removed_renamed_and_tidied_away_as_the_name_it_is(tmp_path, theirs):
    """Removing a link, renaming it or putting it in another name's place does nothing to what it names, and the
    system does not follow it. Until 2026-11-13 the guard did, and judged the place the link names: a test that
    made a link to anything outside its own folders (a virtual environment's link to the Python that runs it, a
    link to a system file) could not tidy up after itself, and that read as a refused write."""
    _links_can_be_made(tmp_path)
    r = _guard_alone(tmp_path, AS_A_NAME, *theirs.args)
    want = ["allowed: a link out renamed", "allowed: a link out put in the place of a file", "allowed: a link out removed",
            "allowed: a folder that holds links out removed with all in it",
            "allowed: a temp folder with a link to the Python that runs, tidied away",
            "allowed: a link to a folder outside removed"]
    if os.unlink in os.supports_dir_fd:
        want.append("allowed: a link out removed beside an open folder")
    assert r.stdout.splitlines() == want + ["left: []"], r.stdout + r.stderr[-1500:]
    assert sandbox.MARK not in r.stderr, r.stderr[-1500:]
    assert theirs.intact()


def test_the_twin_that_goes_through_the_link_is_refused(tmp_path, theirs):
    """What must stay refused: everything that reaches what the link names. A name that ends in a slash is one of
    them: the system then follows a link to a folder, and `rmdir` would remove the folder outside."""
    _links_can_be_made(tmp_path)
    r = _guard_alone(tmp_path, THROUGH_IT, *theirs.args)
    assert r.stdout.splitlines() == [
        "refused: a write through a link out", "refused: what the link names cut short",
        "refused: the rights of what the link names changed", "refused: the dates of what the link names changed",
        "refused: a file copied onto what the link names", "refused: a file removed through a link to a folder",
        "refused: a folder made through a link to a folder", "refused: a file taken out through a link to a folder",
        "refused: a file put in through a link to a folder", "refused: a link made through a link to a folder",
        "refused: the folder a link names removed, named with a slash at its end",
        "refused: the folder a link names renamed, named with a slash at its end",
        "refused: the folder a link names removed with all in it, named with a slash",
        "left: ['empty', 'folder', 'link', 'mine.txt']"], r.stdout + r.stderr[-1500:]
    assert theirs.intact()


@pytest.mark.skipif(not hasattr(os, "link"), reason="this system gives a file no second name")
def test_a_file_outside_is_given_no_second_name_inside(tmp_path, theirs):
    """A second name for a file (a hard link) is the file itself: written under the new name, the file outside
    changes. Until 2026-11-13 the guard looked only at where the new name would be."""
    try:
        os.link(theirs.args[0], tmp_path / "probe-second")
    except (OSError, NotImplementedError):
        pytest.skip("this system or this disk gives a file no second name here")
    os.remove(tmp_path / "probe-second")
    r = _guard_alone(tmp_path, SECOND_NAME, *theirs.args)
    assert r.stdout.splitlines() == ["refused: a second name here for a file outside",
                                     "allowed: a second name for a file of its own",
                                     "left: ['own-too.txt', 'own.txt']"], r.stdout + r.stderr[-1500:]
    assert sandbox.MARK + " link " in r.stderr, r.stderr[-1500:]
    assert theirs.intact()


AT_HOME = '''
    import sys
    log, mood = [], [None]
    def first(event, args):
        if event == "probe":
            log.append(("first",) + args)
        if event == "sys.addaudithook" and mood[0]:
            raise mood[0]("no more hooks")
    def second(event, args):
        if event == "probe":
            log.append(("second",) + args)
        if event == "probe" and args == ("stop",):
            raise OSError("stopped by the second")
    def third(event, args):
        if event == "probe":
            log.append(("third",) + args)
    print(sys.addaudithook(first), sys.addaudithook(hook=second))
    sys.audit("probe", 1)
    for mood[0] in (RuntimeError, ValueError, OSError):       # Python's rule: a hook may keep a newcomer out, quietly
        print(sys.addaudithook(lambda event, args: log.append(("kept out",)) if event == "probe" else None))
    mood[0] = KeyboardInterrupt
    try:
        sys.addaudithook(lambda event, args: log.append(("kept out",)) if event == "probe" else None)
    except KeyboardInterrupt as e:
        print("not quietly:", e)
    mood[0] = None
    sys.addaudithook(third)
    try:
        sys.audit("probe", "stop")
    except OSError as e:
        print(e)
    sys.audit("probe", 2, "two")
    def arrives_in_the_middle(event, args):
        if event == "probe":
            log.append(("fourth",) + args)
    sys.addaudithook(lambda event, args: sys.addaudithook(arrives_in_the_middle) if event == "probe" and args == (3,) else None)
    sys.audit("probe", 3)
    sys.audit("probe", 4)
    for line in log:
        print(line)
    print(sys.addaudithook.__name__, sys.addaudithook.__module__, callable(sys.addaudithook))
'''


def test_adding_a_hook_works_as_it_does_at_home(tmp_path):
    """The same program with the guard and without it: the hooks are called in the order they came, a hook that
    raises ends the event for the ones after it, a hook already there can keep a newcomer out the way Python lets
    it, and a hook that arrives in the middle of an event is called for that event."""
    import subprocess
    import textwrap
    at_home = subprocess.run([sys.executable, "-I", "-c", textwrap.dedent(AT_HOME)], capture_output=True, text=True,
                             encoding="utf-8", timeout=120)
    assert at_home.returncode == 0 and "('third', 2, 'two')" in at_home.stdout, at_home.stdout + at_home.stderr[-1500:]
    r = _guard_alone(tmp_path, AT_HOME)
    assert r.returncode == 0, r.stderr[-1500:]
    assert r.stdout == at_home.stdout, r.stdout + r.stderr[-1500:]


def test_the_guards_mark_stays_when_a_program_adds_hooks_of_its_own(tmp_path):
    """`lantern.tracehook` looks for the guard's mark before it runs a test."""
    r = _guard_alone(tmp_path, '''
        import sys
        print(sys.lantern_sandbox_guard)
        for n in range(3):
            sys.addaudithook(lambda event, args: None)
            import string
        print(sys.lantern_sandbox_guard)
    ''')
    assert r.stdout.split() == ["on", "on"] and r.returncode == 0, r.stdout + r.stderr[-1500:]


@pytest.mark.skipif(sys.platform == "win32", reason="measured where the other speed checks are measured")
def test_the_guard_costs_no_more_than_a_little_for_what_it_lets_through(tmp_path):
    """200,000 opens for reading with the guard, with and without forty hooks of the program's own after it: the
    guard's own share stays small (a bound of 30 seconds for what takes about one)."""
    r = _guard_alone(tmp_path, '''
        import sys, time
        def many():
            t = time.perf_counter()
            for n in range(200000):
                sys.audit("open", "kept.txt", "r", 0)
            return time.perf_counter() - t
        a = many()
        for n in range(40):
            sys.addaudithook(lambda event, args: None)
            import string
        b = many()
        print("ok" if a < 30 and b < 60 else "slow", round(a, 2), round(b, 2))
    ''')
    assert r.stdout.split()[:1] == ["ok"], r.stdout + r.stderr[-1500:]
