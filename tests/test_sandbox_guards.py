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
import json
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


# ----------------------------------------------------------------------------- a name in an address
# (2026-11-14) A socket hands an address to the system in five calls: connect, connect_ex, bind, sendto and sendmsg.
# Where the address holds a host name, Python has the name looked up on the way down and tells its hooks of the call
# afterwards. The guard asks about such a name itself, first, with Python's own event for a lookup: a name is
# refused the way `getaddrinfo` refuses it, after the project's own hooks have seen it, and the system is not asked.
# A number, this computer's own names and the two words that are no names ("" and "<broadcast>") go down as they
# did and are judged where they always were. Each call stands beside those twins.
NAME = "lantern-guard.invalid"
NAMED = '''
    import socket, sys
    NAME, SIX = sys.argv[1], sys.argv[2] == "True"
    seen = []
    sys.addaudithook(lambda event, args: seen.append(event)
                     if event.startswith("socket.") and event != "socket.__new__" else None)
    def tried(what, do):
        del seen[:]
        try:
            got = do()
        except PermissionError as e:
            print("refused:", what, "|", str(e).split(": ", 1)[-1], "|", " ".join(seen))
        except TypeError:
            print("no address:", what, "|", " ".join(seen))
        except OSError as e:
            print("the system's answer:", what, "|", type(e).__name__, "|", " ".join(seen))
        else:
            print("answered:", what, "|", got if isinstance(got, (str, tuple)) else "", "|", " ".join(seen))
    class Mine(socket.socket):
        pass
    def tcp(cls=socket.socket, family=socket.AF_INET):
        s = cls(family, socket.SOCK_STREAM)
        s.settimeout(0.01)
        return s
    def udp(family=socket.AF_INET):
        return socket.socket(family, socket.SOCK_DGRAM)
    WAYS = [("connect", tcp, lambda s, to: s.connect(to)), ("connect_ex", tcp, lambda s, to: s.connect_ex(to)),
            ("bind", tcp, lambda s, to: s.bind(to)), ("sendto", udp, lambda s, to: s.sendto(b"x", to)),
            ("sendto with flags", udp, lambda s, to: s.sendto(b"x", 0, to))]
    if hasattr(socket.socket, "sendmsg"):
        WAYS.append(("sendmsg", udp, lambda s, to: s.sendmsg([b"x"], [], 0, to)))
    def each(to, note=""):
        for what, make, call in WAYS:
            with make() as s:
                tried(what + note, lambda: call(s, to))
'''
A_NAME = NAMED + '''
    each((NAME, 9))
    each((NAME.encode(), 9), " as bytes")
    with tcp(Mine) as s:
        tried("connect on a class made from socket", lambda: s.connect((NAME, 9)))
    with tcp() as s:
        tried("connect called on the class", lambda: socket.socket.connect(s, (NAME, 9)))
    import ssl
    with ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_socket(tcp(), server_hostname=NAME) as s:
        tried("connect on a TLS socket", lambda: s.connect((NAME, 443)))
    if SIX:
        with tcp(family=socket.AF_INET6) as s:
            tried("connect, IPv6", lambda: s.connect((NAME, 9, 0, 0)))
    for almost in ("localhost." + NAME, "127.0.0.1." + NAME, "0x7f.0.0.1", "192.0.2.256", "localhost."):
        with tcp() as s:
            tried("connect to " + ascii(almost), lambda: s.connect((almost, 9)))
'''
THE_TWINS = NAMED + '''
    each(("192.0.2.1", 9))
    each(("localhost", 9), " to localhost")
    with udp() as s:
        tried("sendto everybody", lambda: s.sendto(b"x", ("<broadcast>", 9)))
    with tcp() as s:
        tried("bind anywhere", lambda: s.bind(("", 0)))
    with tcp() as s:
        tried("a name that is no address", lambda: s.connect(NAME))
    with tcp() as s:
        tried("a number where the name goes", lambda: s.connect((9, NAME)))
    if hasattr(socket, "AF_UNIX") and sys.platform != "win32":
        with socket.socket(socket.AF_UNIX) as s:
            tried("a socket file of its own", lambda: s.bind("mine.sock"))
'''
WAYS = ["connect", "connect_ex", "bind", "sendto", "sendto with flags"] + (["sendmsg"] if hasattr(socket.socket, "sendmsg") else [])
EVENT = {"connect": "connect", "connect_ex": "connect", "bind": "bind", "sendto": "sendto", "sendto with flags": "sendto",
         "sendmsg": "sendmsg"}


def _marked(r) -> list[str]:
    return [line for line in r.stderr.splitlines() if line.startswith(sandbox.MARK)]


def test_a_name_in_an_address_is_refused_before_the_system_is_asked_for_it(tmp_path):
    """With the guard and nothing else around it. Each of the five calls, a name as text and as bytes, a class made
    from `socket.socket`, the call made on the class, a TLS socket, IPv6, and names that only look like this
    computer or like a number: every one is refused as a lookup, the only event anybody hears of is the lookup, and
    one line is written for each."""
    six = _six()
    r = _guard_alone(tmp_path, A_NAME, NAME, str(six))
    lookup = lambda what, name: f"refused: {what} | network lookup {name!r} | socket.getaddrinfo"      # noqa: E731
    want = ([lookup(way, NAME) for way in WAYS] + [lookup(way + " as bytes", NAME.encode()) for way in WAYS]
            + [lookup("connect on a class made from socket", NAME), lookup("connect called on the class", NAME),
               lookup("connect on a TLS socket", NAME)] + ([lookup("connect, IPv6", NAME)] if six else [])
            + [lookup("connect to " + ascii(n), n)
               for n in ("localhost." + NAME, "127.0.0.1." + NAME, "0x7f.0.0.1", "192.0.2.256", "localhost.")])
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    written = _marked(r)
    assert len(written) == len(want) and all(" network lookup " in line for line in written), r.stderr[-3000:]


def test_the_twins_a_number_this_computer_and_what_is_no_name_go_down_as_before(tmp_path):
    """The same calls with an address written as a number and with `localhost`: no lookup is heard of, the call
    itself is what the guard refuses (there is no network of the run's own here), and its line names the call as it
    always did. What is no address is the system's to refuse, and a socket file of the run's own is made. On Windows
    the guard's own rule (stage 4) writes `localhost` out as its number, and binds a datagram socket that sends to
    this computer to its own address first (`_written_out`, `_bound_first`): the line says so there."""
    r = _guard_alone(tmp_path, THE_TWINS, NAME, str(_six()))
    windows = sys.platform == "win32"

    def call(what, to, here=False):
        event = EVENT[what.split(" to ")[0]]
        if here and windows:
            to = ("127.0.0.1", to[1])
        first = "socket.bind " if here and windows and event == "sendto" else ""
        return f"refused: {what} | network {event} {to!r} | {first}socket.{event}"
    want = ([call(way, ("192.0.2.1", 9)) for way in WAYS]
            + [call(way + " to localhost", ("localhost", 9), here=True) for way in WAYS]
            + ["refused: sendto everybody | network sendto ('<broadcast>', 9) | socket.sendto",
               "refused: bind anywhere | network bind ('', 0) | socket.bind",
               "no address: a name that is no address | ", "no address: a number where the name goes | "]
            + (["answered: a socket file of its own |  | socket.bind"]
               if hasattr(socket, "AF_UNIX") and sys.platform != "win32" else []))
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    assert "lookup" not in r.stderr, r.stderr[-3000:]


# ----------------------------------------------------------------------------- who an address is
# `getnameinfo` asks who an address is, as `gethostbyaddr` does, unless it is told to answer with the number
# (NI_NUMERICHOST); Python's event for it does not say which. The guard reads the call itself. A number that is
# only written out is answered. Who an address belongs to is a lookup: a name in the address, a number, and here,
# where the run has no network of its own, this computer's own address too (the system may ask the network around
# it; in a network of the run's own that one is answered, tests/test_sandbox_own_network.py).
WHO = NAMED + '''
    import asyncio
    LOOP = sys.argv[3] == "True"
    NUMBERS = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
    who = socket.getnameinfo
    async def through_a_loop(flags):
        return await asyncio.get_running_loop().getnameinfo(("192.0.2.1", 80), flags)
    tried("a name", lambda: who((NAME, 80), 0))
    tried("a name, numbers asked for", lambda: who((NAME, 80), NUMBERS))
    tried("who 192.0.2.1 is", lambda: who(("192.0.2.1", 80), 0))
    tried("who 192.0.2.1 is, the port as a number", lambda: who(("192.0.2.1", 80), socket.NI_NUMERICSERV))
    tried("who this computer's own address is", lambda: who(("127.0.0.1", 80), socket.NI_NUMERICSERV))
    tried("192.0.2.1 written out", lambda: who(("192.0.2.1", 80), NUMBERS))
    tried("this computer's own address written out", lambda: who(("127.0.0.1", 80), NUMBERS))
    if LOOP:
        tried("who 192.0.2.1 is, asked through an event loop", lambda: asyncio.run(through_a_loop(0)))
        tried("192.0.2.1 written out, through an event loop", lambda: asyncio.run(through_a_loop(NUMBERS)))
    if SIX:
        tried("who 2001:db8::1 is", lambda: who(("2001:db8::1", 80, 0, 0), 0))
        tried("2001:db8::1 written out", lambda: who(("2001:db8::1", 80, 0, 0), NUMBERS))
'''


def test_who_an_address_is_is_a_lookup_and_writing_it_out_is_none(tmp_path):
    """With the guard and nothing else around it. The two questions put through an event loop are asked on every
    system: until stage 4 (2026-11-20) no event loop started under the guard on Windows, and they were left out
    there (CLAUDE.md, the sandbox's row)."""
    six, loop = _six(), True
    r = _guard_alone(tmp_path, WHO, NAME, str(six), str(loop))
    want = ([f"refused: a name | network lookup {NAME!r}", f"refused: a name, numbers asked for | network lookup {NAME!r}",
             "refused: who 192.0.2.1 is | network lookup '192.0.2.1'",
             "refused: who 192.0.2.1 is, the port as a number | network lookup '192.0.2.1'",
             "refused: who this computer's own address is | network lookup '127.0.0.1'",
             "answered: 192.0.2.1 written out | ('192.0.2.1', '80')",
             "answered: this computer's own address written out | ('127.0.0.1', '80')"]
            + (["refused: who 192.0.2.1 is, asked through an event loop | network lookup '192.0.2.1'",
                "answered: 192.0.2.1 written out, through an event loop | ('192.0.2.1', '80')"] if loop else [])
            + (["refused: who 2001:db8::1 is | network lookup '2001:db8::1'",
                "answered: 2001:db8::1 written out | ('2001:db8::1', '80')"] if six else []))
    assert [line.rsplit(" | ", 1)[0] for line in r.stdout.splitlines()] == want, r.stdout + r.stderr[-3000:]
    written = _marked(r)                                        # one line for each refusal and for nothing else
    assert len(written) == sum(line.startswith("refused: ") for line in want), r.stderr[-3000:]
    assert all(" network lookup " in line for line in written), written


# ----------------------------------------------------------------------------- this computer under its own name
# `socket.getfqdn()` asks who this computer is under its own name (a mail library does when it writes a message's
# id, an HTTP server when it starts). Where the run has no network of its own, the system may ask the network
# around it. The guard answers itself, with the name at this computer's own address: the system is not asked, no
# event is heard of, nothing is refused, so an honest test is not held up and no line is written. The question put
# to the system for this computer's own name is refused there like any other; whose a number is stays refused.
OWN_NAME = NAMED + '''
    mine = socket.gethostname()
    tried("getfqdn", lambda: "its name" if socket.getfqdn() == mine else socket.getfqdn())
    tried("who this computer is", lambda: "its name, at its own address"
          if socket.gethostbyaddr(mine) == (mine, [], ["127.0.0.1"]) else repr(socket.gethostbyaddr(mine)))
    tried("asked twice, the answers are two", lambda: str(socket.gethostbyaddr(mine)[1] is not socket.gethostbyaddr(mine)[1]))
    import _socket
    tried("asked of the module beneath", lambda: "the same" if _socket.gethostbyaddr(mine) == socket.gethostbyaddr(mine) else "another")
    tried("the question itself, put to the system", lambda: sys.audit("socket.gethostbyaddr", mine))
    tried("who 192.0.2.1 is", lambda: socket.gethostbyaddr("192.0.2.1"))
    tried("who a name is", lambda: socket.gethostbyaddr(NAME))
'''


def test_who_this_computer_is_is_answered_by_the_guard_and_the_system_is_not_asked(tmp_path):
    r = _guard_alone(tmp_path, OWN_NAME, NAME, "False")
    mine = socket.gethostname()
    plain = mine in ("localhost", "127.0.0.1", "::1")    # a computer named so: that question was never one to the network
    assert r.stdout.splitlines() == [
        "answered: getfqdn | its name | socket.gethostname",
        "answered: who this computer is | its name, at its own address | ",
        "answered: asked twice, the answers are two | True | ",
        "answered: asked of the module beneath | the same | ",
        ("answered: the question itself, put to the system |  | socket.gethostbyaddr" if plain else
         f"refused: the question itself, put to the system | network lookup {mine!r} | socket.gethostbyaddr"),
        "refused: who 192.0.2.1 is | network lookup '192.0.2.1' | socket.gethostbyaddr",
        f"refused: who a name is | network lookup {NAME!r} | socket.gethostbyaddr"], r.stdout + r.stderr[-3000:]
    assert len(_marked(r)) == 3 - plain, r.stderr[-3000:]


# ----------------------------------------------------------------------------- an address as the system reads it
# (2026-11-14) The system reads an address by what it holds: the entries of the pair, the letters of the host and
# the socket's own family, whatever class each is of and whatever that class says about itself. And it takes a
# host for a number only where every part is written the one way a number is written. The guard reads the same,
# and what it read is what goes down: a pair or a host of a class of its own is handed on as its plain value. So a
# name in such a value is asked about first like any other name, and a value of such a class that holds a number
# or this computer's name does what its plain twin does.
CLASSES = NAMED + '''
    import collections
    show = print
    def print(*parts):                        # letters outside ASCII written out, whatever this system's pipes take
        show(" ".join(str(p) for p in parts).encode("ascii", "backslashreplace").decode("ascii"))
    Pair = collections.namedtuple("Pair", "host port")
    class Made(tuple):
        pass
    class Name(str):
        pass
    class Raw(bytes):
        pass
    class First(tuple):                       # asked for its first entry, it says this computer
        def __getitem__(self, i):
            return "localhost" if i == 0 else tuple.__getitem__(self, i)
    class Small(str):                         # asked for its small letters, it says this computer
        def lower(self):
            return "localhost"
    class Parts(str):                         # asked for its parts, it says a number's
        def split(self, *how):
            return ["192", "0", "2", "1"]
    class Same(str):                          # asked whether it is the same as anything, it says yes
        def __eq__(self, other):
            return True
        def __hash__(self):
            return hash("localhost")
    class Other(str):                         # asked to write itself out, it writes another name
        def encode(self, *how):
            return NAME.encode()
    class Read(bytes):                        # asked for its bytes, it says a number's
        def __bytes__(self):
            return b"192.0.2.1"
    class Flags(int):                         # asked for any flag, it says the flag is set
        def __and__(self, other):
            return other
        __rand__ = __and__
    class Family(socket.socket):              # asked for its family, it says one that is no network's
        family = getattr(socket, "AF_UNIX", 1)
    NUMBERS = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
    who = socket.getnameinfo
    mine = socket.gethostname()
'''
OF_ANOTHER_CLASS = CLASSES + '''
    each(Pair(NAME, 9), ", a named pair")
    each(Made((NAME, 9)), ", a class made from tuple")
    for what, to in (("a pair that says this computer", First((NAME, 9))), ("a text that says this computer", (Small(NAME), 9)),
                     ("a text that says a number", (Parts(NAME), 9)), ("a text that says it is the same", (Same(NAME), 9)),
                     ("bytes that say a number", (Read(NAME.encode()), 9))):
        with tcp() as s:
            tried("connect, " + what, lambda: s.connect(to))
    with tcp() as s:
        tried("connect, a number that writes itself out as a name", lambda: s.connect((Other("192.0.2.1"), 9)))
    with Family(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.01)
        tried("connect, a socket that says another family", lambda: s.connect(("192.0.2.1", 9)))
    tried("getaddrinfo, a text that says it is the same", lambda: socket.getaddrinfo(Same(NAME), 80))
    import _socket
    tried("getaddrinfo of the module beneath, by its words", lambda: _socket.getaddrinfo(host=Same(NAME), port=80))
    tried("gethostbyname, a text that says it is the same", lambda: socket.gethostbyname(Same(NAME)))
    tried("gethostbyname_ex, a text that says it is the same", lambda: socket.gethostbyname_ex(Same(NAME)))
    tried("gethostbyaddr, a text that says it is the same", lambda: socket.gethostbyaddr(Same("192.0.2.1")))
    tried("getaddrinfo, a number that writes itself out as a name", lambda: len(socket.getaddrinfo(Other("127.0.0.1"), 80)) and "")
    tried("gethostbyname, a number that writes itself out as a name", lambda: socket.gethostbyname(Other("127.0.0.1")))
    tried("who 192.0.2.1 is, in a named pair", lambda: who(Pair("192.0.2.1", 80), 0))
    tried("who 192.0.2.1 is, in a pair that says this computer", lambda: who(First(("192.0.2.1", 80)), 0))
    tried("who 192.0.2.1 is, with flags that say numbers", lambda: who(("192.0.2.1", 80), Flags(0)))
    tried("who a name is, in a named pair", lambda: who(Pair(NAME, 80), 0))
    tried("who this computer is, its name in a text class", lambda: "its name, at its own address"
          if socket.gethostbyaddr(Name(mine)) == (mine, [], ["127.0.0.1"]) else repr(socket.gethostbyaddr(Name(mine))))
'''
HONEST_CLASSES = CLASSES + '''
    each(Pair("192.0.2.1", 9), ", a named pair")
    with tcp() as s:
        tried("connect, a number in a text class", lambda: s.connect((Name("192.0.2.1"), 9)))
    with tcp() as s:
        tried("connect, a number in a bytes class", lambda: s.connect((Raw(b"192.0.2.1"), 9)))
    with tcp() as s:
        tried("connect, localhost in a text class", lambda: s.connect((Name("localhost"), 9)))
    tried("getaddrinfo, a number in a text class", lambda: len(socket.getaddrinfo(Name("127.0.0.1"), 80)) and "")
    tried("gethostbyname, a number in a text class", lambda: socket.gethostbyname(Name("127.0.0.1")))
    tried("192.0.2.1 written out, in a named pair", lambda: who(Pair("192.0.2.1", 80), NUMBERS))
    tried("192.0.2.1 written out, the flags in a class", lambda: who(("192.0.2.1", 80), Flags(NUMBERS)))
'''


def test_a_value_of_another_class_is_read_as_the_system_reads_it(tmp_path):
    """With the guard and nothing else around it. A pair, a host, a set of flags and a socket of a class that
    answers for itself: the guard goes by what the value holds. A name in it is refused as a lookup before the
    system is asked, a number goes down as that number (and the call is refused where it always was), who an
    address is stays a lookup, and this computer's name in a text class is answered by the guard like its plain
    twin. One line is written for each refusal."""
    r = _guard_alone(tmp_path, OF_ANOTHER_CLASS, NAME, "False")
    lookup = lambda what, name, event="getaddrinfo": f"refused: {what} | network lookup {name!r} | socket.{event}"     # noqa: E731
    want = ([lookup(way + ", a named pair", NAME) for way in WAYS]
            + [lookup(way + ", a class made from tuple", NAME) for way in WAYS]
            + [lookup("connect, " + what, NAME) for what in (
                "a pair that says this computer", "a text that says this computer", "a text that says a number",
                "a text that says it is the same")]
            + [lookup("connect, bytes that say a number", NAME.encode()),
               "refused: connect, a number that writes itself out as a name | network connect ('192.0.2.1', 9) | socket.connect",
               "refused: connect, a socket that says another family | network connect ('192.0.2.1', 9) | socket.connect",
               lookup("getaddrinfo, a text that says it is the same", NAME),
               lookup("getaddrinfo of the module beneath, by its words", NAME),
               lookup("gethostbyname, a text that says it is the same", NAME, "gethostbyname"),
               lookup("gethostbyname_ex, a text that says it is the same", NAME, "gethostbyname"),
               lookup("gethostbyaddr, a text that says it is the same", "192.0.2.1", "gethostbyaddr"),
               "answered: getaddrinfo, a number that writes itself out as a name |  | socket.getaddrinfo",
               "answered: gethostbyname, a number that writes itself out as a name | 127.0.0.1 | socket.gethostbyname",
               lookup("who 192.0.2.1 is, in a named pair", "192.0.2.1", "gethostbyaddr"),
               lookup("who 192.0.2.1 is, in a pair that says this computer", "192.0.2.1", "gethostbyaddr"),
               lookup("who 192.0.2.1 is, with flags that say numbers", "192.0.2.1", "gethostbyaddr"),
               lookup("who a name is, in a named pair", NAME, "gethostbyaddr"),
               "answered: who this computer is, its name in a text class | its name, at its own address | "])
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    written = _marked(r)
    assert len(written) == sum(line.startswith("refused: ") for line in want), r.stderr[-3000:]
    assert sum(" network lookup " in line for line in written) == len(written) - 2, written


def test_the_twins_a_number_or_this_computer_in_a_value_of_another_class_does_what_its_plain_twin_does(tmp_path):
    """The same classes holding what is no question to anybody: a number in a named pair, in a text class and in
    a bytes class is refused as the connection it is (there is no network of the run's own here) with no lookup
    heard of, `localhost` too, a number looked up is answered, and an address that is only written out is
    answered, also where the flags are of a class of their own."""
    r = _guard_alone(tmp_path, HONEST_CLASSES, NAME, "False")
    got = [line.split(" | ") for line in r.stdout.splitlines()]
    calls = ([way + ", a named pair" for way in WAYS]
             + ["connect, a number in a text class", "connect, a number in a bytes class", "connect, localhost in a text class"])
    assert [g[0] for g in got[:len(calls)]] == ["refused: " + c for c in calls], r.stdout + r.stderr[-3000:]
    for (_, reason, events), what in zip(got[:len(calls)], calls):
        event = EVENT[what.split(",")[0]]
        assert reason.startswith(f"network {event} ") and events == "socket." + event, (what, reason, events)
    assert [" | ".join(g) for g in got[len(calls):]] == [
        "answered: getaddrinfo, a number in a text class |  | socket.getaddrinfo",
        "answered: gethostbyname, a number in a text class | 127.0.0.1 | socket.gethostbyname",
        "answered: 192.0.2.1 written out, in a named pair | ('192.0.2.1', '80') | socket.getnameinfo",
        "answered: 192.0.2.1 written out, the flags in a class | ('192.0.2.1', '80') | socket.getnameinfo"], r.stdout
    assert "lookup" not in r.stderr and len(_marked(r)) == len(calls), r.stderr[-3000:]


# ----------------------------------------------------------------------------- almost this computer's number
# This computer's own address is 127 and three more parts, each written the one way every system reads a number:
# plain digits, no zero in front. A host that only looks like it (a digit of another script, a part with a zero
# in front, a space or a dot more) may be a name to the system, which then asks for it; so it is a name to the
# guard and is asked about first.
ALMOST = ["127.0.0.\u0661", "127.0.0.\u00b2", "127.0.0.09", "127.0.0.010", "127.0.0.00", "127.00.0.1", "::ffff:127.0.0.09",
          "127.0.0.1 ", " 127.0.0.1", "127.0.0.1."]
ALMOST_HERE = CLASSES + '''
    import json
    for host in json.loads(sys.argv[3]):
        with tcp() as s:
            tried("connect to " + ascii(host), lambda: s.connect((host, 9)))
        with udp() as s:
            tried("sendto " + ascii(host), lambda: s.sendto(b"x", (host, 9)))
'''
HERE_AS_WRITTEN = CLASSES + '''
    for host in ("127.0.0.1", "127.9.8.7", "0.0.0.0"):
        with tcp() as s:
            tried("connect to " + host, lambda: s.connect((host, 9)))
    if SIX:
        for host in ("::1", "::ffff:127.0.0.1"):
            with tcp(family=socket.AF_INET6) as s:
                tried("connect to " + host, lambda: s.connect((host, 9, 0, 0)))
'''


def test_a_host_that_only_looks_like_this_computers_number_is_asked_about_first(tmp_path):
    r = _guard_alone(tmp_path, ALMOST_HERE, NAME, "False", json.dumps(ALMOST))
    want = [f"refused: {call} {ascii(host)} | network lookup {ascii(host)} | socket.getaddrinfo"
            for host in ALMOST for call in ("connect to", "sendto")]
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    written = _marked(r)
    assert len(written) == len(want) and all(" network lookup " in line for line in written), r.stderr[-3000:]


def test_the_twins_this_computers_number_as_it_is_written_is_no_lookup(tmp_path):
    """The numbers themselves go down, no lookup is heard of, and the call is refused where it always was (there
    is no network of the run's own here; in one they are let through, tests/test_sandbox_own_network.py)."""
    six = _six()
    r = _guard_alone(tmp_path, HERE_AS_WRITTEN, NAME, str(six))
    want = ([f"refused: connect to {host} | network connect ('{host}', 9) | socket.connect"
             for host in ("127.0.0.1", "127.9.8.7", "0.0.0.0")]
            + ([f"refused: connect to {host} | network connect ('{host}', 9, 0, 0) | socket.connect"
                for host in ("::1", "::ffff:127.0.0.1")] if six else []))
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    assert "lookup" not in r.stderr, r.stderr[-3000:]


# ----------------------------------------------------------------------------- a number on every system alike
# Which hosts are numbers must not depend on the system the guard runs on. A system may read more as an IPv6
# number than the others do: Windows takes a zero in front of a part of the IPv4 number at its end, a form Linux
# and macOS take for a name. The guard went by this system's reading alone, so on Windows it let such a host go
# down unasked (CI's Windows job, 2026-11-14: `::ffff:127.0.0.09` in the test above). In these programs this
# system's reading is replaced by one that takes anything, so the answer is the guard's own on every system: an
# IPv6 number is one only where it is written the one way all of them read it.
TAKES_ANYTHING = CLASSES + """
    import json
    socket.inet_pton = lambda family, text: bytes(16)     # from here on this system reads anything as a number
"""
SIX_ALMOST = ["::ffff:127.0.0.09", "::ffff:127.0.0.010", "::127.0.0.01", "::ffff:127.0.1", "::ffff:127.0.0.256",
              "::ffff:127.0.0.1.", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::1", "1:2:3:4:5:6:7", "1.2.3.4::", ":::1", "::1:"]
SIX_ALMOST_HERE = TAKES_ANYTHING + """
    for host in json.loads(sys.argv[3]):
        with tcp() as s:
            tried("connect to " + ascii(host), lambda: s.connect((host, 9)))
        with udp() as s:
            tried("sendto " + ascii(host), lambda: s.sendto(b"x", (host, 9)))
        tried("getaddrinfo of " + ascii(host), lambda: socket.getaddrinfo(host, 9) and "")
"""
SIX_AS_WRITTEN = ["::1", "::", "::ffff:127.0.0.1", "::ffff:192.0.2.1", "2001:db8::1", "1:2:3:4:5:6:7:8"]
SIX_WRITTEN_RARELY = ["2001:DB8:0:0:0:0:0:1", "fe80::1", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:192.0.2.1", "::192.0.2.1"]
SIX_WRITTEN_HERE = TAKES_ANYTHING + """
    for host in json.loads(sys.argv[3]):
        tried("getaddrinfo of " + host, lambda: socket.getaddrinfo(host, 9, 0, 0, 0, socket.AI_NUMERICHOST) and "")
"""


def test_what_only_one_system_reads_as_an_ipv6_number_is_asked_about_first(tmp_path):
    """A zero in front of a part of the IPv4 number at the end, a part too few or too large, a dot after it, a
    group too many or too long, two gaps: each is a name to some system, so each is asked about before any system
    sees it, through a socket and through a lookup, also where this system would read it as a number."""
    r = _guard_alone(tmp_path, SIX_ALMOST_HERE, NAME, "False", json.dumps(SIX_ALMOST))
    want = [f"refused: {call} {ascii(host)} | network lookup {ascii(host)} | socket.getaddrinfo"
            for host in SIX_ALMOST for call in ("connect to", "sendto", "getaddrinfo of")]
    assert r.stdout.splitlines() == want, r.stdout + r.stderr[-3000:]
    written = _marked(r)
    assert len(written) == len(want) and all(" network lookup " in line for line in written), r.stderr[-3000:]


def test_the_twins_an_ipv6_number_as_every_system_reads_it_is_no_lookup(tmp_path):
    """The same program with numbers written the one way: none is refused and no lookup is written down. The ones
    every system is sure to read are answered; of the rarer ways of writing one the test asks only that the guard
    let them down, and what the system then says is the system's."""
    r = _guard_alone(tmp_path, SIX_WRITTEN_HERE, NAME, "False", json.dumps(SIX_AS_WRITTEN + SIX_WRITTEN_RARELY))
    got = r.stdout.splitlines()
    assert got[:len(SIX_AS_WRITTEN)] == [f"answered: getaddrinfo of {host} |  | socket.getaddrinfo" for host in SIX_AS_WRITTEN], \
        r.stdout + r.stderr[-3000:]
    rarely = [line.split(" | ") for line in got[len(SIX_AS_WRITTEN):]]
    assert [(line[0].split(": ", 1)[1], line[-1]) for line in rarely] == [
        ("getaddrinfo of " + host, "socket.getaddrinfo") for host in SIX_WRITTEN_RARELY], r.stdout
    assert not any(line[0].startswith("refused") for line in rarely), r.stdout
    assert "lookup" not in r.stderr and _marked(r) == [], r.stderr[-3000:]
