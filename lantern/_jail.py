"""POSIX launcher for the test sandbox (`lantern.sandbox`) and the cloud worker's jailed steps: apply the limits,
run the command, and leave nothing it started behind.

    python -c "...main(argv)" POLICY_JSON -- command args...

POLICY_JSON: {"writable": [dirs], "nobody": bool, "python": bool, "net": bool, "own_net": bool, "net_told": bool,
              "must": bool, "parent": pid, "cpu": seconds, "memory": bytes, "readable": [paths], "runs": path}
* resource limits: processor time for each process (600 s, or `cpu`: the run's time limit on every processor it
  may use, so a test at work on several at once meets the clock first; until 2026-11-13 it was 600 s whatever
  the limit and however many processors), files up to 512 MB, no core dumps;
* `readable` and `runs` (2026-11-13, a project's own tests): what the command is made of (Lantern's own recorder,
  the libraries of the Python that runs it) and the program itself. Once the user is the one the command runs as,
  each is asked for: a folder must be one that user may enter, a file one it may read, the program one it may
  start. If not, nothing is started and the launcher ends with `UNAVAILABLE` and the word `unreadable`. Until then
  a Lantern installed in a folder that user may not enter (a home folder closed to others, a temp folder of
  root's) started Python, Python found no `lantern`, and that read as "the tests failed";
* `memory` (2026-11-13, a project's own tests): the memory the command and everything it started may have in use,
  counted together. On Linux the supervisor below looks at it from outside, a few times a second (`_in_use`: what
  the kernel says each process holds in memory and in swap, and, once that sum is over the limit, each process's
  own share of what it holds with others, so memory that five programs share is counted once). Over the limit it
  prints `LANTERN-SANDBOX-LIMIT: memory <bytes in use> <the limit>`, ends everything and ends itself with
  `OVER_MEMORY`. Until then a Python process had 2 GB of address space, which counts what a program reserved and
  not what it uses: tests that map a large file, start many threads or load a large library were refused memory
  they never asked to use, and that read as "the tests failed". Where the supervisor watches, no limit is set on
  address space; elsewhere (macOS, which has no supervisor) the address space is held to `memory`, and with no
  `memory` at all (the cloud service's steps, which read a project) a Python process keeps the 2 GB it always
  had. It is a watch and no wall: between two looks a program can take more, and what stops it then is the
  computer's own memory;
* `own_net` (Linux, 2026-11-13): a network of the command's own, made before anything else is taken away: a new
  network namespace, which holds this computer's own address (`lo`, switched on) and nothing else. The command
  can listen there and call what it started; no other computer can be reached from it, and neither can what the
  other programs of this one listen at by address or by socket name, which is in the network it left (a socket
  file is a file, and no network holds it). Root makes it directly; any
  other user through a user namespace, where the system allows one (the user and group stay what they were, and
  the rights the namespace gave end at the command's first exec). The command is told through
  LANTERN_SANDBOX_NET=own:<the namespace's number>, which the Python guard checks against its own process
  (`lantern.sandbox.SITECUSTOMIZE`), unless `net_told` is false: then the network is made and the guard goes on
  refusing every address and writing it down (`lantern.behave` reads what an app reached for from those lines);
* Linux Landlock (when the kernel has it): writes only beneath `writable`, (ABI 4+) no TCP connect or bind unless
  the command has a network of its own, and (ABI 6+) no signal to a process outside the sandbox and no
  connection to a socket name (an abstract Unix socket) of a process outside it;
* `nobody`: drop to uid/gid 65534 when started as root (root ignores file modes);
* no_new_privs, so nothing it runs can gain privileges.

`must` (set for a project's own tests, the one place Lantern runs untrusted code): when a restriction the sandbox
counts on cannot be put in place, the command is not started. The launcher prints `LANTERN-SANDBOX-UNAVAILABLE:
<word> [number]` (the words are `REASONS`) and ends with `UNAVAILABLE`. Until 2026-11-10 it printed `sandbox:
Landlock restrict error N` and ran the command all the same. Without `must` (the cloud worker's steps, which read a
project and never run it) it says so and carries on, as before. A system that has no Landlock at all is not a
failure either way: `lantern.sandbox.describe` promises Landlock only where the kernel has it.

On Linux the launcher stays as the command's supervisor instead of becoming it:
* orphans of the run are handed to it (PR_SET_CHILD_SUBREAPER), so every process the command started, however
  deep and whatever session or process group it moved to, stays findable beneath it in /proc;
* when the command ends, when Lantern asks (SIGTERM, at the wall clock or a cancel), and when Lantern itself ends
  (`parent`, PR_SET_PDEATHSIG), it ends every one of them, collects them, then ends itself the way the command did
  (same exit code, or the same signal);
* the restrictions are put on the command's side of the fork only, so the supervisor keeps the right to end it.
Before, the launcher became the command; a process that had left the process group (`setsid`, a daemon) outlived
the wall clock, and anything left running outlived a normal end.

Standard library only; it must run before anything from the project is imported.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import sys
import time

UNAVAILABLE = 119          # the launcher's own result when it did not start the command
OVER_MEMORY = 118          # ... and when it stopped the command because of the memory in use
LIMIT_MARK = "LANTERN-SANDBOX-LIMIT:"
# Processor time for each process of a run: at least, and at most (the longest time limit on 4,096 processors). A
# run is given its time limit on every processor it may use, so that a test working on several at once is stopped
# by the clock, which reads as a run that did not finish, and not by this limit, which would read as a failure.
CPU_SECONDS, CPU_MOST = 600, 240 * 60 * 4096
MARK = "LANTERN-SANDBOX-UNAVAILABLE:"
# Why the command was not started: the word printed after MARK, and the words `lantern.sandbox` shows for it. The
# words shown to a person are always these, never text read from a run's output.
REASONS = {
    "landlock-ruleset": "the kernel refused the rules that keep writes inside the sandbox's temp folder",
    "landlock-restrict": "the kernel refused to put the tests under the rules that keep writes inside the sandbox's temp folder",
    "no-new-privileges": "the kernel refused to stop the tests from gaining privileges",
    "user": "the tests could not be handed to the unprivileged user they must run as",
    "parent-gone": "Lantern ended while the sandbox was starting",
    "guard": "the guard that refuses writes and network connections did not load into the tests' Python",
    "own-network": "the tests could not be given a network of their own, which is where they may listen and "
                   "call what they started",
    "unreadable": "the user the sandbox runs the tests as cannot read Lantern's own files, the Python that runs "
                  "them or its libraries: they lie in a folder that user may not enter (install Lantern where "
                  "every user of this computer can read it, or start it as an ordinary user)",
}
ASK = 6.0                  # seconds `lantern.sandbox` waits after asking (SIGTERM) before it kills the process group
_SWEEP = 3.0               # seconds the supervisor spends ending what the command started

# Landlock filesystem rights that change things (reads are not restricted)
_FS_WRITE = {1: (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)}
_FS_WRITE[2] = _FS_WRITE[1] | (1 << 13)          # REFER
_FS_WRITE[3] = _FS_WRITE[2] | (1 << 14)          # TRUNCATE
_NET_TCP = (1 << 0) | (1 << 1)                   # BIND_TCP | CONNECT_TCP (ABI 4)
_SCOPE_SIGNAL = 1 << 1                           # LANDLOCK_SCOPE_SIGNAL (ABI 6): no signal to a process outside
_SCOPE_NAME = 1 << 0                             # LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (ABI 6): no socket name outside
_CLONE_NEWUSER, _CLONE_NEWNET = 0x10000000, 0x40000000
_SIOCGIFFLAGS, _SIOCSIFFLAGS, _IFF_UP = 0x8913, 0x8914, 0x1
NET_VARIABLE = "LANTERN_SANDBOX_NET"             # how the command is told that its network is its own


class _Refused(Exception):
    """A restriction the sandbox counts on could not be put in place; the reason has been printed."""


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _refuse(word: str, number: int | None = None) -> None:
    _say(f"{MARK} {word}" + (f" {number}" if number else ""))
    raise _Refused(word)


def _reads(path, run: bool = False) -> bool:
    """Can the user this process now is read `path` (a folder: also enter it), or, with `run`, start it?"""
    try:
        path = os.fspath(path)
        folder = os.path.isdir(path)
        if run:
            return not folder and os.access(path, os.R_OK | os.X_OK)
        return os.access(path, os.R_OK | (os.X_OK if folder else 0))
    except (OSError, TypeError, ValueError):
        return False


def _landlock(writable: list[str], net: bool) -> tuple[str, str | None, int]:
    """Put this process under Landlock. Returns (what to print after "sandbox: Landlock", None or the word in
    REASONS for what failed, the system's error number)."""
    if not sys.platform.startswith("linux"):
        return "not Linux", None, 0
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        return "kernel has no Landlock", None, 0
    fs = _FS_WRITE[min(abi, 3)]
    if abi >= 6:
        attr = (ctypes.c_uint64 * 3)(fs, _NET_TCP if net else 0, _SCOPE_SIGNAL | _SCOPE_NAME)
    elif abi >= 4 and net:
        attr = (ctypes.c_uint64 * 2)(fs, _NET_TCP)
    else:
        attr = (ctypes.c_uint64 * 1)(fs)
    rfd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0:
        number = ctypes.get_errno()
        return f"ruleset error {number}", "landlock-ruleset", number

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
    O_PATH = 0o10000000
    allowed = [(p, fs) for p in writable] + [("/dev", 1 << 1)]   # /dev/null, /dev/tty: write to existing files only
    for path, rights in allowed:
        # a folder that cannot be allowed leaves the command with less than it was meant to have, never more
        try:
            fd = os.open(path, O_PATH | os.O_CLOEXEC)
        except OSError as e:
            _say(f"sandbox: Landlock could not allow writes beneath {path} (error {e.errno})")
            continue
        rule = Beneath(rights & fs, fd)
        if libc.syscall(445, rfd, 1, ctypes.byref(rule), 0) != 0:   # LANDLOCK_RULE_PATH_BENEATH
            _say(f"sandbox: Landlock could not allow writes beneath {path} (error {ctypes.get_errno()})")
        os.close(fd)
    if libc.prctl(38, 1, 0, 0, 0) != 0:                      # PR_SET_NO_NEW_PRIVS
        number = ctypes.get_errno()
        os.close(rfd)
        return f"no_new_privs error {number}", "no-new-privileges", number
    if libc.syscall(446, rfd, 0) != 0:
        number = ctypes.get_errno()
        os.close(rfd)
        return f"restrict error {number}", "landlock-restrict", number
    os.close(rfd)
    return (f"on (ABI {abi}{', no TCP' if abi >= 4 and net else ''}"
            f"{', no signals or socket names outside' if abi >= 6 else ''})"), None, 0


def _unshare(flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(flags) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _own_network(user: bool) -> int:
    """Move this process into a network of its own: a new network namespace, which starts with a loopback address
    and nothing else, switched on here. `user`: through a new user namespace, the way a process that is not root
    gets the right (where the system allows it). The user and group stay the ones they were (each mapped to
    itself), so the command gains nothing: it is not root in there, and the rights the new namespace gives this
    process end at its first exec. Returns 0, or the system's error number."""
    if not sys.platform.startswith("linux"):
        return errno.ENOSYS
    uid, gid = os.geteuid(), os.getegid()
    try:
        _unshare((_CLONE_NEWUSER if user else 0) | _CLONE_NEWNET)
        if user:
            for name, text in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
                with open(f"/proc/self/{name}", "w", encoding="ascii") as f:
                    f.write(text)
        import fcntl
        import socket
        import struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            asked = fcntl.ioctl(s, _SIOCGIFFLAGS, struct.pack("16sH22s", b"lo", 0, b""))
            flags = struct.unpack("16sH22s", asked)[1]
            fcntl.ioctl(s, _SIOCSIFFLAGS, struct.pack("16sH22s", b"lo", flags | _IFF_UP, b""))
    except OSError as e:
        return e.errno or errno.EPERM
    return 0


def _become_nobody() -> None:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def try_own_network(nobody: bool) -> int:
    """For a throwaway process (`lantern.sandbox.own_network` starts one): can the command of a run be given a
    network of its own on this system? Does what `_restrict` does for it, in the same order. 0, or the error
    number of the step that was refused."""
    if os.geteuid() == 0:
        if _own_network(False) == 0:
            return 0
        if nobody:
            try:
                _become_nobody()
            except OSError as e:
                return e.errno or errno.EPERM
    return _own_network(True)


def _restrict(policy: dict) -> None:
    """Limits, the unprivileged user, Landlock and no new privileges, in the process that is about to become the
    command. Raises `_Refused`, the reason printed, when the command must not be started."""
    must = bool(policy.get("must"))
    import resource
    cpu = policy.get("cpu")       # never under the 600 seconds a run always had; more when its time limit is longer
    cpu = cpu if type(cpu) is int and CPU_SECONDS < cpu <= CPU_MOST else CPU_SECONDS
    limits = [("CPU", cpu), ("FSIZE", 512 << 20), ("CORE", 0)]
    memory = _memory(policy)
    if memory and not _watches():           # no supervisor to count memory in use: the address space, as before
        limits.append(("AS", memory))
    elif not memory and policy.get("python"):
        limits.append(("AS", 2 << 30))
    for name, want in limits:
        which = getattr(resource, "RLIMIT_" + name, None)
        if which is None:
            continue
        try:
            hard = resource.getrlimit(which)[1]
            value = want if hard == resource.RLIM_INFINITY else min(want, hard)   # never above what is already set
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError) as e:
            _say(f"sandbox: the limit {name} was not set ({e})")
    own, made, number = bool(policy.get("own_net")), False, 0
    os.environ.pop(NET_VARIABLE, None)      # said by this launcher alone, after it made the network
    if own and os.geteuid() == 0:           # root makes it before the change of user takes the right away
        number = _own_network(False)
        made = number == 0
    if policy.get("nobody") and os.geteuid() == 0:
        try:
            _become_nobody()
        except OSError as e:
            _refuse("user", e.errno)        # never as root what was to run as nobody
        if os.getuid() != 65534 or os.geteuid() != 65534 or os.getgid() != 65534:
            _refuse("user")
    # What the command is made of (`readable`: files and folders, `runs`: the program) is looked at by the user
    # the command will run as: root's own home folder is closed to `nobody`, and a Python that finds no Lantern
    # and no test runner there would end with an error that reads as tests that failed.
    named, runs = policy.get("readable"), policy.get("runs")
    for path, run in [(p, False) for p in (named if isinstance(named, list) else [])] + ([(runs, True)] if runs else []):
        if not _reads(path, run):
            _say(f"sandbox: the user the tests run as cannot {'start' if run else 'read'} {str(path)[:300]}")
            _refuse("unreadable")
    if own and not made:                    # any other user: through a user namespace, where the system allows one
        number = _own_network(True)
        made = number == 0
    told = made and policy.get("net_told", True)
    if told:
        try:
            os.environ[NET_VARIABLE] = "own:%d" % os.stat("/proc/self/ns/net").st_ino
        except OSError as e:
            made, number = False, e.errno or errno.EPERM
    if own and not made:
        # The walls of a run with `own_net` are chosen for a network of its own (the caller asked this system
        # first, `try_own_network`): without it the command is not started, rather than started with other walls.
        _say("sandbox: a network of its own could not be made")
        if must:
            _refuse("own-network", number)
    elif made:
        _say("sandbox: a network of its own (this computer's own address and nothing else)" if told else
             "sandbox: a network of its own, which nothing outside can be reached from")
    state, failed, number = _landlock(policy.get("writable", []), bool(policy.get("net")) and not made)
    if failed is None and not state.startswith("on") and sys.platform.startswith("linux"):
        try:   # no Landlock on this kernel: still no new privileges
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(38, 1, 0, 0, 0) != 0:
                failed, number = "no-new-privileges", ctypes.get_errno()
        except (OSError, AttributeError):
            failed, number = "no-new-privileges", 0
    _say(f"sandbox: Landlock {state}")
    if failed and must:
        _refuse(failed, number)
    if failed:
        _say(f"sandbox: carrying on without it ({REASONS[failed]})")


def _memory(policy: dict) -> int:
    """The bytes of memory the policy gives the command and what it starts, or 0 when it names no such limit."""
    n = policy.get("memory")
    return n if type(n) is int and n > 0 else 0


def _watches() -> bool:
    """Whether a supervisor stays with the command and can look at the memory it uses."""
    return sys.platform.startswith("linux")


GUARD_MISSING = ("sandbox: the guard that refuses writes and network connections did not load into this step's "
                 "Python; the step carries on, because it reads the project's files and runs none of them")


def say_if_guard_missing() -> None:
    """First line of the programs the cloud service starts on a project's files with the network off (`lantern.cli`,
    `lantern.archive`). Their guard is a sitecustomize on PYTHONPATH (`lantern.sandbox.SITECUSTOMIZE`), and Python
    leaves a folder it cannot read out of its path without a word: where the guard was expected
    (LANTERN_SANDBOX_GUARD=expected) and is not in this Python, the run's log says so. A project's own tests are
    another matter: they do not run without it (`required`, checked by `lantern.tracehook`)."""
    if os.environ.get("LANTERN_SANDBOX_GUARD") == "expected" and getattr(sys, "lantern_sandbox_guard", None) != "on":
        _say(GUARD_MISSING)


# ---------------------------------------------------------------------------- Linux: the supervisor
def _stat(pid) -> tuple[bytes, int, int] | None:
    """One process as /proc shows it: (state, its parent, its session). None when it is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            text = f.read()
        # the program's name is in brackets and may hold brackets and spaces: read after the last ")"
        fields = text[text.rindex(b")") + 2:].split()
        return fields[0], int(fields[1]), int(fields[3])
    except (OSError, ValueError, IndexError):
        return None


def _all() -> dict[int, tuple[bytes, int, int]]:
    """Every process of this computer that /proc shows."""
    out = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            row = _stat(name)
            if row:
                out[int(name)] = row
    return out


def _kb(text: bytes, names: tuple) -> int | None:
    """The sum, in bytes, of the lines of a /proc file that begin with one of `names` ("VmRSS:      1234 kB"). Read
    line by line from each line's start: the first line of such a file may be the program's own name, which the
    program chooses. None when no such line is there."""
    total, seen = 0, False
    for line in text.split(b"\n"):
        if line.startswith(names):
            try:
                total += int(line.split(b":", 1)[1].split()[0]) << 10
                seen = True
            except (ValueError, IndexError):
                pass
    return total if seen else None


def _holds(pid: int) -> int:
    """Bytes of memory one process holds, by the kernel's quick count: what is in memory and what was moved to
    swap. Memory it shares with other processes is counted here for each of them. 0 for one that is gone."""
    try:
        with open(f"/proc/{pid}/status", "rb") as f:
            return _kb(f.read(), (b"VmRSS:", b"VmSwap:")) or 0
    except OSError:
        return 0


def _share(pid: int) -> int:
    """Bytes of memory that are one process's own share: what it holds alone, and of what it holds with others its
    part (the kernel's Pss). Costs the kernel a walk through the process's memory, so it is asked only when the
    quick count is over the limit. Where the kernel does not say (before 4.14, or not to this user), the quick
    count stands, which errs on the side of stopping."""
    try:
        with open(f"/proc/{pid}/smaps_rollup", "rb") as f:
            own = _kb(f.read(), (b"Pss:", b"SwapPss:"))
    except (FileNotFoundError, ProcessLookupError):
        return 0 if _stat(pid) is None else _holds(pid)
    except OSError:
        return _holds(pid)
    return _holds(pid) if own is None else own


def _in_use(me: int, limit: int) -> int:
    """Bytes of memory in use by every process beneath `me`, counted together. Under `limit` the answer is the
    quick count (never too low); over it, each process's own share is asked, and that sum is the answer."""
    try:
        pids = _beneath(me)
    except OSError:
        return 0
    quick = sum(_holds(pid) for pid in pids)
    return quick if quick <= limit else sum(_share(pid) for pid in pids)


def _beneath(me: int, table: dict | None = None) -> list[int]:
    """Every process whose chain of parents leads to `me` (`table`: what `_all` returned, to read it once)."""
    kids: dict[int, list[int]] = {}
    for pid, (_state, parent, _session) in (_all() if table is None else table).items():
        kids.setdefault(parent, []).append(pid)
    out, todo = [], [me]
    while todo:
        for k in kids.get(todo.pop(), []):
            out.append(k)
            todo.append(k)
    return out


def in_session(sid: int) -> list[int]:
    """Linux: every process still running in the session `sid` (a launcher starts one, and the command's own
    process group lives in it). Ended processes that nobody has collected yet are not counted."""
    try:
        return [pid for pid, (state, _parent, session) in _all().items() if session == sid and state != b"Z"]
    except OSError:
        return []


def end_session(sid: int) -> None:
    """Linux: end every process in the session `sid`. For `lantern.sandbox`, when a launcher did not do it."""
    for pid in in_session(sid):
        _kill(pid, lambda row: row is not None and row[2] == sid)


def end_beneath(top: int, seconds: float = 2.0) -> int:
    """Linux: end every process whose chain of parents leads to `top`. For `lantern.sandbox`, when a launcher is
    still there but has not ended what its command started (it was stopped, or is too slow): while the launcher
    lives, every process of the run is beneath it, also one that left its session. Returns how many still run."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            table = _all()
        except OSError:
            return 0
        family = _beneath(top, table)
        running = [pid for pid in family if table[pid][0] != b"Z"]   # ended ones wait there for the launcher
        if not running or time.monotonic() > deadline:
            return len(running)
        ours = set(family) | {top}
        for pid in running:
            _kill(pid, lambda row, ours=ours: row is not None and row[1] in ours)
        time.sleep(0.01)


def _kill(pid: int, still_ours) -> None:
    """End one process that was found in /proc. Its number may, by the time the signal goes, belong to another
    program: where the kernel can hold the process itself (a pidfd), it is held first, looked at again
    (`still_ours`, given what /proc says of it now), and only then ended through what is held."""
    opener, sender = getattr(os, "pidfd_open", None), getattr(signal, "pidfd_send_signal", None)
    if opener and sender:
        try:
            fd = opener(pid)
        except ProcessLookupError:
            return
        except OSError:
            fd = None                      # an older kernel, or a filter that does not let the call through
        if fd is not None:
            try:
                if still_ours(_stat(pid)):
                    sender(fd, signal.SIGKILL)
            except OSError:
                pass
            finally:
                os.close(fd)
            return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _end_all(me: int, seconds: float = _SWEEP) -> int:
    """End every process beneath this one and collect them. Returns how many are still there (0 when none)."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            pids = _beneath(me)
        except OSError:
            _say("sandbox: /proc cannot be read here, so what the command started was not looked for")
            return 0
        if not pids:
            return 0
        ours = set(pids) | {me}
        for pid in pids:
            _kill(pid, lambda row, ours=ours: row is not None and row[1] in ours)
        while True:                        # collect the ones that ended; orphans were handed to this process
            try:
                got, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if got == 0:
                break
        if time.monotonic() > deadline:
            return len(_beneath(me))
        time.sleep(0.01)


def _supervise(policy: dict, cmd: list[str]) -> None:
    """Linux: run the command as a child, and end everything it started when it ends, when asked, and when the
    program that started this launcher ends. Does not return."""
    asks = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(36, 1, 0, 0, 0)                           # PR_SET_CHILD_SUBREAPER
    libc.prctl(1, int(signal.SIGTERM), 0, 0, 0)          # PR_SET_PDEATHSIG: told when the one that started it ends
    parent = policy.get("parent")
    if parent and os.getppid() != parent:                # it ended before the line above
        _say(f"{MARK} parent-gone")
        os._exit(UNAVAILABLE)
    # The signals that ask this launcher to stop, and the news that a child ended, wait in the kernel's queue from
    # here on and are read below one at a time. Nothing interrupts this code: a handler that fired between two
    # lines of the clean-up would have cut the clean-up short. Whatever the starting program left set is put right
    # first: an ignored SIGCHLD would have the kernel collect the command and keep its result from this launcher.
    watched = {*asks, signal.SIGCHLD}
    before = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # ending the way the command did must not write a core file
    except (ImportError, ValueError, OSError):
        pass
    me = os.getpid()
    sys.stdout.flush()
    sys.stderr.flush()
    child = os.fork()
    if child == 0:
        code = 127
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)   # the command hears what any program hears
            os.setpgid(0, 0)            # its own process group: a signal a test sends "to its group" stays in it
            _restrict(policy)
            libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)   # after the change of user, which clears it
            if os.getppid() != me:
                os._exit(code)
            os.execvp(cmd[0], cmd)
        except _Refused:
            code = UNAVAILABLE
        except BaseException as e:  # noqa: BLE001 - whatever it is, this side of the fork must end here
            _say(f"sandbox: could not start {cmd[0]}: {e}")
        finally:
            os._exit(code)
    status, memory, over, look = None, _memory(policy), 0, 0.0
    while True:
        try:
            got, st = os.waitpid(-1, os.WNOHANG)         # also collects orphans handed to this process
        except ChildProcessError:
            break
        if got == child:
            status = st
            break
        if got == 0:                                     # nothing has ended: wait for news (the second is a net)
            wait = 1.0
            if memory:
                now = time.monotonic()
                if now >= look:                          # how much memory everything beneath this process has in use
                    used = _in_use(me, memory)
                    if used > memory:
                        over = used
                        break
                    took = time.monotonic() - now
                    # looked at more often near the limit, and never so often that the looking is the work: a
                    # look costs a read of /proc for every process of this computer
                    look = now + took + (max(0.5, 20 * took) if used < memory // 2 else max(0.1, 10 * took))
                wait = min(1.0, max(0.01, look - time.monotonic()))
            news = signal.sigtimedwait(watched, wait)
            if news is not None and news.si_signo != signal.SIGCHLD:
                break                                    # asked to stop, or the starting program ended
    if over:
        _say(f"{LIMIT_MARK} memory {over} {memory}")
    left = _end_all(me)
    if left:
        _say(f"sandbox: {left} process(es) the command started could not be ended")
    sys.stdout.flush()
    sys.stderr.flush()
    if over:                                             # stopped for the memory in use: neither a pass nor a failure
        os._exit(OVER_MEMORY)
    if status is None:                                   # asked to stop
        os._exit(128 + int(signal.SIGTERM))
    if os.WIFSIGNALED(status):                           # end the way the command did, so the caller reads the same
        number = os.WTERMSIG(status)
        try:
            signal.signal(number, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {number})
        except (OSError, ValueError):
            pass
        os.kill(me, number)
        time.sleep(1)
        os._exit(128 + number)
    os._exit(os.WEXITSTATUS(status))


def main(argv: list[str]) -> None:
    policy = json.loads(argv[0])
    cmd = argv[argv.index("--") + 1:]
    if sys.platform.startswith("linux"):
        _supervise(policy, cmd)
    try:
        _restrict(policy)
    except _Refused:
        sys.exit(UNAVAILABLE)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
