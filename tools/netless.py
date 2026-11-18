"""Run a command with no network at all:  python tools/netless.py [--watch FILE [--deadline MINUTES]] -- COMMAND [ARGUMENT...]

Linux only. The command and every program it starts live in a network of their own that holds nothing but this
computer's loopback address (a new network namespace with only `lo`). No program in it can reach the outside, whatever
it is written in and whatever it does with proxy settings: this is the part the Python-level guard (tools/netguard)
cannot promise.

It needs the right to make that network: root (in CI: `sudo env "PATH=$PATH" "HOME=$HOME" python tools/netless.py
-- ...`; the command then runs as the user who called sudo, not as root), or a system that lets ordinary users create
user namespaces. sudo hands the command only the variables written after `env`: one it needs is written there too
(`"LANTERN_TESTS_NETLESS=required"`). `sudo -E` is no way round that: the sudo of newer systems (sudo-rs: GitHub's
Linux machines) ignores it.

--watch FILE also has the operating system write down every address any program of the run connects or sends to (the
`strace` program must be installed). FILE gets one JSON object: the addresses outside this computer, each with the
program that tried it. With --watch the result is 4 when the command succeeded and something tried the outside.

A try made on purpose. A test of Lantern's sandbox starts a program that is not Python and has it call an address
outside, to see the kernel refuse the call; nothing can refuse that before the operating system records it. Such a
test names the try before it makes it: --watch gives the command a file's place in LANTERN_NETLESS_ON_PURPOSE, and a
line `{"kind": "connect", "address": "192.0.2.1", "port": 80, "why": "..."}` there (tests/conftest.py writes it for
`@pytest.mark.tries_outside(...)`) keeps that try apart, under `on_purpose` in FILE and in what is printed. It is
kept apart only when the very try was named (kind, address and port), the address is one kept for examples (RFC 5737,
RFC 3849: no computer has one) and the kernel refused it; anything else that was tried still gives 4.

With --watch the end of the command is watched too. strace writes the end of every process it follows (`+++ exited
with N +++`), and the command's own end must be in that record: when strace stops before the command ends (twice in
CI it stopped with "ptrace(PTRACE_LISTEN, ...): Input/output error", telling the command to end and ending with 1 at
once), the command's result is not known and what it tried after that is not written down, so the result is 6 and the
runner says so, where until 2026-11-18 strace's 1 read like a failure of the command.

--deadline MINUTES (with --watch): the time the command is given. Past it the runner lists every process of the run
that is still there, with the state of each of its threads and what each waits in (the kernel's own word), asks the
command to end (SIGINT, so a test run says where it stood), gives it GRACE seconds, ends what is left, and the result
is 7. On 2026-11-17 a run of the tests printed 89% and then nothing for 2 h 39 min, until it was cancelled by hand,
and nothing said where it stood.

Result: the command's own; 2 when this was called wrongly; 3 when this system cannot do it; with --watch, 4 when
something tried the outside, 6 when the recorder stopped before the command ended, 7 when the command ran past its
deadline. FILE then says which (`command_end_recorded`, `past_deadline`, `still_running_at_deadline`).
"""
from __future__ import annotations

import collections
import io
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "netguard"))
import lantern_netguard as netguard  # noqa: E402

USAGE = "usage: python tools/netless.py [--watch FILE [--deadline MINUTES]] -- COMMAND [ARGUMENT...]\n"
CLONE_NEWUSER, CLONE_NEWNET = 0x10000000, 0x40000000
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
WITH_SUDO = 'sudo env "PATH=$PATH" "HOME=$HOME" python tools/netless.py -- COMMAND'


ON_PURPOSE = "LANTERN_NETLESS_ON_PURPOSE"       # for the command: the file its tests name their on-purpose tries in
KINDS = ("connect", "send", "lookup")          # what a test may name (a forwarding proxy is never tried on purpose)
REFUSED = ("EACCES", "EPERM", "ENETUNREACH", "EHOSTUNREACH")   # the kernel said no, there and then
EXAMPLES = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
RECORDER_STOPPED = 6                           # the recorder ended before the command did: no result of the command
LATE = 7                                       # the command ran past its deadline and was ended
GRACE = 60                                     # seconds a command past its deadline has to end once it is asked to
MOST_ROWS = 200                                # processes printed at a deadline (FILE keeps every one)
LEFT = 5                                       # seconds what the command left running has to end by itself
STATES = {"R": "running", "S": "waiting", "D": "waiting, and cannot be interrupted", "T": "stopped by a signal",
          "t": "held by its tracer (a ptrace stop)", "Z": "ended, not yet collected", "X": "ended", "x": "ended",
          "I": "idle", "K": "being ended", "W": "waking", "P": "parked"}     # proc(5): the state letter of a thread


class Cannot(Exception):
    """This system cannot give the command a network of its own."""


def _unshare(flags: int) -> None:
    if hasattr(os, "unshare"):                       # Python 3.12+
        os.unshare(flags)
        return
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(flags) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def own_network() -> None:
    """Move this process into a network that holds only its own loopback address, switched on."""
    try:
        _unshare(CLONE_NEWNET)
    except OSError:
        uid, gid = os.getuid(), os.getgid()          # not root: a user namespace gives the right inside it, if allowed
        try:
            _unshare(CLONE_NEWUSER | CLONE_NEWNET)
            for name, text in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
                with open(f"/proc/self/{name}", "w", encoding="ascii") as f:
                    f.write(text)
        except OSError as e:
            raise Cannot(f"no permission to create a network of its own ({e}). Run it as root: {WITH_SUDO}") from None
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        request = struct.pack("16sH22s", b"lo", 0, b"")
        flags = struct.unpack("16sH22s", fcntl.ioctl(s, SIOCGIFFLAGS, request))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH22s", b"lo", flags | IFF_UP, b""))
    except OSError as e:
        raise Cannot(f"the new network's loopback address could not be switched on ({e})") from None
    finally:
        s.close()
    if netguard.has_route_out():
        raise Cannot("the new network still has a route to the outside")


def back_to_the_caller() -> None:
    """Started through sudo: only making the network needed root. The command runs as the user who called sudo."""
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    if os.geteuid() != 0 or not uid.isdigit() or not gid.isdigit() or int(uid) == 0:
        return
    import pwd
    try:
        who = pwd.getpwuid(int(uid))
        os.initgroups(who.pw_name, int(gid))
    except KeyError:
        who = None
        os.setgroups([int(gid)])
    os.setgid(int(gid))
    os.setuid(int(uid))
    for name in ("SUDO_UID", "SUDO_GID", "SUDO_USER", "SUDO_COMMAND"):
        os.environ.pop(name, None)
    if who is not None:
        os.environ["USER"] = os.environ["LOGNAME"] = who.pw_name
        if os.environ.get("HOME") in (None, "", "/root"):
            os.environ["HOME"] = who.pw_dir


# ------------------------------------------------------------------------------------------------ --watch
TRACED = "connect,sendto,sendmsg,sendmmsg,execve,clone,clone3,fork,vfork"
_LINE = re.compile(r"^(\d+)\s+(?:\d+\.\d+\s+)?(.*)$")          # "PID [TIME] call(...) = result"
_V4 = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
_V6 = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
_UNIX = re.compile(r'sa_family=AF_UNIX, sun_path=@?"([^"]*)"')
_EXEC = re.compile(r'^execve\("([^"]*)", \[(.*)\]')
_ARGUMENT = re.compile(r'"((?:[^"\\]|\\.)*)"')
_RESULT = re.compile(r"\)\s+=\s+(-?\d+)(?:\s+([A-Z][A-Z0-9]+))?(?:\s+\(.*\))?\s*$")
_CALL = re.compile(r"^(?:<\.\.\. )?(\w+)")
_END = re.compile(r"^\+\+\+ (?:exited with -?\d+|killed by SIG\w+)")   # strace -q: "+++ exited with 0 +++"
SERVICES = ("docker.sock", "containerd", "podman", "nscd", "systemd/resolve", "dbus")   # they have their own way out


def summarize(trace_path: str, forwarder_ports=()) -> dict:
    """What a `strace -f -q -e trace=TRACED` record says about the network: every address outside this computer that a
    program connected or sent to (a name lookup counts: port 53 on any address), with the program. And whether the
    record holds the command's own end (`command_end_recorded`): the command is the process of its first line; None
    when it holds no line at all (nothing was started under the recorder)."""
    program: dict = {}
    waiting: dict = {}                    # pid -> (call, text so far) for a call another process interrupted
    outside: dict = collections.OrderedDict()
    services: collections.Counter = collections.Counter()
    local = checks = 0
    first, ended = None, False

    def note(pid, call, text, result):
        nonlocal local, checks
        if call in ("clone", "clone3", "fork", "vfork"):
            if result and result[0].isdigit() and int(result[0]) > 0:
                program[result[0]] = program.get(pid, "?")       # the new process is the same program until it execs
            return
        if call == "execve":
            m = _EXEC.match(text)
            if m and result and result[0] == "0":
                argv = [re.sub(r"\\[nrt]|\s+", " ", a).strip() for a in _ARGUMENT.findall(m.group(2))[:6]]
                program[pid] = (" ".join(a for a in argv if a) or m.group(1))[:160]
            return
        u = _UNIX.search(text)
        if u:
            if result and result[0] == "0" and any(s in u.group(1) for s in SERVICES):
                services[u.group(1)] += 1
            return
        m = _V4.search(text) or _V6.search(text)
        if not m:
            return
        port, address = int(m.group(1)), m.group(2)
        if (address, port) == netguard.PROBE:
            checks += 1                              # "is there a route?": the check itself, nothing is sent
            return
        lookup = port == 53
        forwarder = netguard.is_local(address) and port in forwarder_ports
        if netguard.is_local(address) and not lookup and not forwarder:
            local += 1
            return
        kind = "lookup" if lookup else "forwarding proxy" if forwarder else "send" if call != "connect" else "connect"
        key = (kind, address, port, program.get(pid, "?"))
        entry = outside.setdefault(key, {"kind": kind, "address": address, "port": port,
                                         "program": program.get(pid, "?"), "count": 0, "result": ""})
        entry["count"] += 1
        if result:
            entry["result"] = result[1] or ("ok" if not result[0].startswith("-") else result[0])

    try:
        f = open(trace_path, encoding="utf-8", errors="replace")
    except FileNotFoundError:                                  # the recorder stopped before it wrote anything
        f = io.StringIO()
    with f:
        for raw in f:
            m = _LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            pid, rest = m.group(1), m.group(2)
            if first is None:
                first = pid
            if rest.startswith("+++ "):                                   # a process ended
                ended = ended or (pid == first and bool(_END.match(rest)))
                continue
            if rest.startswith("<... "):                                   # "<... connect resumed>) = 0"
                call, text = waiting.pop(pid, (None, ""))
                if call:
                    r = _RESULT.search(rest)
                    note(pid, call, text, r.groups() if r else None)
                continue
            c = _CALL.match(rest)
            if not c:
                continue
            if rest.endswith("<unfinished ...>"):
                waiting[pid] = (c.group(1), rest)
                continue
            r = _RESULT.search(rest)
            note(pid, c.group(1), rest, r.groups() if r else None)
    for pid, (call, text) in waiting.items():                             # never came back: still an attempt
        note(pid, call, text, None)
    return {"outside": list(outside.values()), "connections_on_this_computer": local,
            "checks_that_there_is_no_route": checks,
            "services_on_this_computer_with_their_own_way_out": dict(services),
            "command_end_recorded": None if first is None else ended}


def for_examples(address: str) -> bool:
    """An address kept for examples (RFC 5737, RFC 3849): no computer has one."""
    try:
        a = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in EXAMPLES)


def named(path: str) -> list:
    """The tries the run's tests named as made on purpose: one JSON object a line, `kind` (one of KINDS), `address`,
    `port` and `why`. A line that is anything else names no try."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if (isinstance(d, dict) and d.get("kind") in KINDS and isinstance(d.get("address"), str)
                and type(d.get("port")) is int and isinstance(d.get("why"), str) and d["why"].strip()):
            out.append({"kind": d["kind"], "address": d["address"], "port": d["port"], "why": d["why"].strip()})
    return out


def sort_out(outside: list, names: list) -> tuple:
    """(what was tried and nobody named, what a test tried on purpose). A try is one made on purpose only when a
    test named that very try (kind, address and port), the address is one kept for examples, and the kernel refused
    it: a try that got through, or whose end the record does not show, counts like any other."""
    why = {(n["kind"], n["address"], n["port"]): n["why"] for n in names}
    left, meant = [], []
    for e in outside:
        key = (e["kind"], e["address"], e["port"])
        if key in why and for_examples(e["address"]) and e["result"] in REFUSED:
            meant.append({**e, "why": why[key]})
        else:
            left.append(e)
    return left, meant


# ------------------------------------------------------------------------------------------------ --deadline
def _stat(where: str):
    """(name, state, parent, started) from /proc/<where>/stat, or None where there is none any more. `started` is the
    clock tick the process started at: it tells a process from a later one that was given the same number."""
    try:
        with open(f"/proc/{where}/stat", "rb") as f:
            text = f.read(4096).decode("utf-8", "replace")
        rest = text[text.rindex(")") + 2:].split()
        return text[text.index("(") + 1:text.rindex(")")], rest[0], int(rest[1]), int(rest[19])
    except (OSError, ValueError, IndexError):
        return None


def _waits_in(where: str) -> str:
    """The kernel's own word for what a thread waits in (proc(5): wchan), or "" where it says none."""
    try:
        with open(f"/proc/{where}/wchan", "rb") as f:
            word = f.read(128).decode("ascii", "replace").strip()
    except OSError:
        return ""
    return word if re.fullmatch(r"[A-Za-z_][\w.]*", word) else ""


def _threads(pid: int) -> list:
    """The process's threads, counted by state and by what each waits in."""
    count: collections.Counter = collections.Counter()
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        tids = []
    for tid in tids:
        s = _stat(f"{pid}/task/{tid}")
        if s is not None:
            count[(s[1], _waits_in(f"{pid}/task/{tid}"))] += 1
    return [{"state": state, "waits_in": where, "count": n}
            for (state, where), n in sorted(count.items(), key=lambda kv: (-kv[1], kv[0]))]


_PYTHON = re.compile(r"^(?:python|pypy)[\d.]*$")
_PLAIN = re.compile(r"^[\w.+-]{1,80}$")
_VALUED = ("-W", "-X", "-r", "--require", "--import")      # options of Python and Node that take the next argument


def _what(pid: int, program: str) -> str:
    """A process's program in a few words: its name, and for Python or Node the module it runs or the name of its
    file. Never its arguments, which may hold anything (a key in a command line)."""
    if not (_PYTHON.match(program) or program == "node"):
        return program
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = [a.decode("utf-8", "replace") for a in f.read(65536).split(b"\0")[1:]]
    except OSError:
        return program
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
        elif a == "-m":
            module = args[i + 1] if i + 1 < len(args) else ""
            return f"{program} -m {module}" if _PLAIN.match(module) else program
        elif a in ("-c", "-e"):
            return f"{program} {a} ..."
        elif a in _VALUED:
            skip = True
        elif a and not a.startswith("-"):
            name = os.path.basename(a)
            return f"{program} {name}" if _PLAIN.match(name) else program
    return program


def _tracer(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "rb") as f:
            for line in f:
                if line.startswith(b"TracerPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def still_running(root: int) -> list:
    """Every process of the run that is still there, the recorder (`root`) first: what it started, each under its
    parent, and what the run left behind that another process took in (found by its tracer, the recorder). Each with
    its program in a few words, how long it has run, its state and its threads by state and by what each waits in."""
    procs = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        names = []
    for name in names:
        s = _stat(name) if name.isdigit() else None
        if s is not None:
            procs[int(name)] = s
    under = collections.defaultdict(list)
    for pid, s in procs.items():
        under[s[2]].append(pid)
    order: list = []
    seen: set = set()

    def take(start: int) -> None:
        stack = [start]
        while stack:
            pid = stack.pop()
            if pid in seen or pid not in procs:
                continue
            seen.add(pid)
            order.append(pid)
            stack.extend(sorted(under.get(pid, ()), reverse=True))

    take(root)
    for pid in sorted(procs):
        if pid not in seen and _tracer(pid) == root:
            take(pid)
    try:
        with open("/proc/uptime", encoding="ascii") as f:
            up = float(f.read().split()[0])
        tick = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        up, tick = None, 100
    rows = []
    for pid in order:
        name, state, parent, started = procs[pid]
        rows.append({"pid": pid, "parent": parent, "program": _what(pid, name), "state": state,
                     "seconds": None if up is None else round(max(0.0, up - started / tick), 1),
                     "started": started, "threads": _threads(pid)})
    return rows


def _span(seconds: float) -> str:
    value, unit = (seconds, "second") if seconds < 120 else (seconds / 60, "minute")
    value = round(value, 1)
    return f"{value:g} {unit}" + ("" if value == 1 else "s")


def _row_words(row: dict) -> str:
    threads = ", ".join(f"{t['count']} {'thread' if t['count'] == 1 else 'threads'} "
                        f"{STATES.get(t['state'], t['state'])}" + (f" in {t['waits_in']}" if t["waits_in"] else "")
                        for t in row["threads"])
    age = "" if row["seconds"] is None else f", running for {_span(row['seconds'])}"
    return f"  {row['pid']} (under {row['parent']}) {row['program']}{age}: {threads or 'no thread left'}\n"


def _send(row: dict, sig: int) -> bool:
    """Send `sig` to the process of `row`, only while it is still that process (the same started tick, looked at
    after it is held by a pidfd where the system has them) and has not ended."""
    try:
        fd = os.pidfd_open(row["pid"])
    except (AttributeError, OSError):
        fd = None
    try:
        now = _stat(str(row["pid"]))
        if now is None or now[3] != row["started"] or now[1] in "ZXx":
            return False
        if fd is not None:
            signal.pidfd_send_signal(fd, sig)
        else:
            os.kill(row["pid"], sig)
        return True
    except OSError:                                    # gone in between (ProcessLookupError), or not ours
        return False
    finally:
        if fd is not None:
            os.close(fd)


def _ended(row: dict) -> bool:
    now = _stat(str(row["pid"]))
    return now is None or now[3] != row["started"] or now[1] in "ZXx"


def _ends_within(child: subprocess.Popen, seconds: float, rows=()) -> bool:
    """Wait at most `seconds` for the recorder to end (True), or for every process of `rows` to have ended."""
    clock = time.monotonic() + seconds
    while True:
        try:
            child.wait(timeout=max(0.0, min(0.2, clock - time.monotonic())))
            return True
        except subprocess.TimeoutExpired:
            if time.monotonic() >= clock or (rows and all(_ended(r) for r in rows)):
                return False


def _end_late(child: subprocess.Popen, rows: list, grace: float) -> tuple:
    """The command ran past its deadline: ask it to end (SIGINT: a test run then says where it stood) and give it
    `grace` seconds; then end what is left of the run, the recorder last. Gives (how, ended by force): how is
    "asked" (everything ended when asked), "left" (the command did; what it had started and left running was ended)
    or "killed" (the command did not end when asked)."""
    recorder = child.pid
    command = [r for r in rows if r["parent"] == recorder] or [r for r in rows if r["pid"] != recorder]
    for r in command:
        _send(r, signal.SIGINT)
    if _ends_within(child, grace, command):
        return "asked", []
    how = "left" if all(_ended(r) for r in command) else "killed"
    if how == "left" and _ends_within(child, min(grace, LEFT)):
        return "asked", []
    forced: dict = {}
    for _ in range(5):
        left = [r for r in still_running(recorder) if r["pid"] != recorder and r["state"] not in "ZXx"]
        if not left:
            break
        for r in left:
            if _send(r, signal.SIGKILL):
                forced.setdefault(r["pid"], {"pid": r["pid"], "program": r["program"]})
        if _ends_within(child, 2):
            return how, list(forced.values())
    child.kill()                                       # a recorder that did not end once what it watched was gone
    child.wait()
    return how, list(forced.values())


def watched(command: list, out_path: str, forwarder_ports, deadline=None, grace=GRACE) -> int:
    strace = shutil.which("strace")
    if not strace:
        raise Cannot("--watch needs the strace program (Debian/Ubuntu: apt-get install strace)")
    folder = tempfile.mkdtemp(prefix="netless-")       # the raw record holds the first bytes of what programs sent each
    raw = os.path.join(folder, "trace")                # other on this computer: private, and removed below
    names = os.path.join(folder, "on-purpose")         # where the command's tests name the tries they make on purpose
    before: dict = {}
    asked: list = []
    child = late = how = None
    forced: list = []
    try:
        with open(names, "w", encoding="utf-8"):
            pass
        # -q, not -qq: the record then holds the end of every process (`+++ exited with N +++`), the command's too
        child = subprocess.Popen([strace, "-f", "-q", "--seccomp-bpf", "-s", "64", "-o", raw, "-e", f"trace={TRACED}",
                                  "--", *command], env={**os.environ, ON_PURPOSE: names})

        def forward(number, _frame):
            asked.append(signal.Signals(number).name)
            child.send_signal(number)

        for sig in (signal.SIGINT, signal.SIGTERM):
            before[sig] = signal.signal(sig, forward)
        try:
            code = child.wait(timeout=deadline)
        except subprocess.TimeoutExpired:
            late = still_running(child.pid)
            sys.stderr.write(f"netless: the command ran past its deadline ({_span(deadline)}). What of the run is "
                             "still there, thread by thread (its state, and what it waits in, in the kernel's words):\n")
            for r in late[:MOST_ROWS]:
                sys.stderr.write(_row_words(r))
            if len(late) > MOST_ROWS:
                sys.stderr.write(f"  and {len(late) - MOST_ROWS} more ({out_path} lists them)\n")
            sys.stderr.write(f"netless: asking the command to end (SIGINT, so that a test run says where it stood); "
                             f"it has {_span(grace)}\n")
            sys.stderr.flush()
            how, forced = _end_late(child, late, grace)
            code = child.wait()
            ended = ", ".join(f"{f['pid']} {f['program']}" for f in forced[:MOST_ROWS]) or "none was there any more"
            sys.stderr.write("netless: the command was asked to end (SIGINT) and did\n" if how == "asked" else
                             "netless: the command was asked to end (SIGINT) and did; what it had started and left "
                             f"running was ended (SIGKILL): {ended}\n" if how == "left" else
                             "netless: the command did not end when asked; what was left of the run was ended "
                             f"(SIGKILL): {ended}\n")
        summary = summarize(raw, forwarder_ports)
        summary["outside"], summary["on_purpose"] = sort_out(summary["outside"], named(names))
    finally:
        for sig, previous in before.items():
            if previous is not None:
                signal.signal(sig, previous)
        if child is not None and child.poll() is None:  # only when this went wrong itself: leave nothing running
            child.kill()
            child.wait()
        shutil.rmtree(folder, ignore_errors=True)
    summary["command"], summary["result"] = command[:8], code
    summary["past_deadline"], summary["deadline_seconds"] = late is not None, deadline
    if late is not None:
        summary["still_running_at_deadline"], summary["ended_at_deadline"] = late, how
        summary["ended_by_force"] = forced
    if asked:
        summary["asked_to_stop"] = asked
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
    outside, meant = summary["outside"], summary["on_purpose"]
    sys.stderr.write(f"netless: {summary['connections_on_this_computer']} connections stayed on this computer, "
                     f"{sum(e['count'] for e in outside)} attempts to reach outside it (none can succeed here), "
                     f"{summary['checks_that_there_is_no_route']} checks that there is no route"
                     + (f"; {sum(e['count'] for e in meant)} more that a test made on purpose, for an address no "
                        "computer has, and the kernel refused" if meant else "") + "\n")
    for e in outside:
        sys.stderr.write(f"  {e['count']}x {e['kind']} {e['address']}:{e['port']} ({e['result'] or '?'})   by: {e['program']}\n")
    for e in meant:
        sys.stderr.write(f"  on purpose: {e['count']}x {e['kind']} {e['address']}:{e['port']} ({e['result']})   "
                         f"by: {e['program']}   why: {e['why']}\n")
    if late is not None:
        return LATE
    if asked:
        sys.stderr.write(f"netless: the run was asked to stop ({', '.join(asked)})\n")
        return 128 + signal.Signals[asked[0]].value
    if summary["command_end_recorded"] is not True:
        sys.stderr.write("netless: " + ("the recorder (strace) stopped before the command ended" if summary[
            "command_end_recorded"] is False else "the recorder (strace) wrote nothing of the command")
            + f" (strace's result: {code}): the command's own result is not known, and what it tried after that is "
            "not written down\n")
        return RECORDER_STOPPED
    return code if code or not outside else 4


def main(argv: list) -> int:
    watch = minutes = None
    while len(argv) >= 2 and argv[0] in ("--watch", "--deadline") and argv[1] != "--":
        if argv[0] == "--watch":
            watch = argv[1]
        else:
            minutes = argv[1]
        argv = argv[2:]
    if len(argv) < 2 or argv[0] != "--":
        sys.stderr.write(USAGE)
        return 2
    if minutes is not None and not (minutes.isascii() and minutes.isdigit() and int(minutes) > 0):
        sys.stderr.write("netless: --deadline MINUTES is a whole number of minutes, 1 or more\n" + USAGE)
        return 2
    if minutes is not None and watch is None:
        sys.stderr.write("netless: --deadline needs --watch (the deadline is kept while the command is watched)\n"
                         + USAGE)
        return 2
    command = argv[1:]
    if not sys.platform.startswith("linux"):
        sys.stderr.write("netless: only Linux can give a command a network of its own\n")
        return 3
    forwarder_ports = {a[2] for a in netguard.proxy_variables().values() if netguard.is_local(a[1], loosely=True)}
    try:
        own_network()
        back_to_the_caller()
        if watch:
            return watched(command, watch, forwarder_ports, deadline=None if minutes is None else int(minutes) * 60)
    except Cannot as e:
        sys.stderr.write(f"netless: {e}\n")
        return 3
    try:
        os.execvp(command[0], command)
    except OSError as e:
        sys.stderr.write(f"netless: cannot start {command[0]}: {e}\n")
        return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
