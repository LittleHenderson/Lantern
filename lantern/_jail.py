"""POSIX launcher for the test sandbox (`lantern.sandbox`) and the cloud worker's jailed steps: apply the limits,
run the command, and leave nothing it started behind.

    python -c "...main(argv)" POLICY_JSON -- command args...

POLICY_JSON: {"writable": [dirs], "nobody": bool, "python": bool, "net": bool, "own_net": bool, "net_told": bool,
              "must": bool, "parent": pid, "cpu": seconds, "memory": bytes, "readable": [paths], "runs": path,
              "read": {"closed": [dirs], "open": [paths], "list": [dirs]}, "shm": bytes, "sockets": bool}
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
* `read` (2026-11-13, a project's own tests; Landlock): the folders named in `closed` cannot be read, listed or
  run from, by the command or by anything it starts. The kernel's rules can only open folders, so what is open
  is named one by one (`_beside`): every entry that lies beside the way from `/` to a closed folder, links left
  out (a link is open or not by where it leads); then `open`, files and folders inside a closed one that the
  command is made of (the run's own folder, the Python or Node that runs it), and `list`, folders whose names
  may be read and whose files may not. A folder on the way to a closed one can be passed through and not
  listed, `/` included. Until then the rules were about writes alone: a library the tests load could read a key
  file of the person's by its full path. Afterwards `readable` and `runs` are opened once more, under the rules:
  what the command is made of has to be among what is open, or nothing is started (the word `closed`);
* `shm` (Linux, 2026-11-13, a project's own tests): a memory folder of the command's own (`_own_memory`). Linux
  keeps named semaphores and shared memory as files in `/dev/shm`, one folder for every program of the computer,
  which the command may not write in; Python makes every process lock, pool and queue from such a semaphore, so
  tests that start a pool of processes failed with "Permission denied" from below Python and read as "the tests
  failed". Now an empty folder of at most `shm` bytes (64 MB to 1 GB) stands in its place for the command, in a
  mount namespace of its own in which nothing else is changed, and is gone with the last process of the run; the
  rules for writes and reads open it. The names of the older kind of shared memory, semaphores and queues
  (System V; POSIX message queues) are the command's own as well (an IPC namespace): it finds none of another
  program's, and what it makes does not outlive it. Root makes both directly, any other user in the user
  namespace of its network or in one of its own. The command is told through LANTERN_SANDBOX_SHM=own:<the
  folder's device number>, which the Python guard checks against the folder it sees. The caller asks this
  system first (`try_own_memory`) and names `shm` only where it can: a launcher that then cannot make it does
  not start the command (`must`). Where the system cannot (it refuses new namespaces; a run inside a run, since
  no mount can be made under the outer run's rules) none is asked for, and `lantern.sandbox` reads a refused
  lock in the output as the sandbox's doing;
* `sockets` (Linux, 2026-11-13, a project's own tests): a doorman between the command and the kernel
  (`_doorman`). The kernel's rules for files say nothing about connecting to a socket file, its rule against
  connections is about TCP's own request, and the Python guard is in Python only: a program the tests start
  that is not Python (Node, a compiled test, `python -S`) could talk to whatever listens at a socket file of the
  person's (the desktop's message bus, a container service, an agent that holds keys) and, where the run has no
  network of its own, send UDP anywhere and open TCP in two ways that rule does not see. Now a list of
  comparisons the kernel makes on every request (`_filter`, a seccomp filter) hands every `connect` to the
  doorman, a process of Lantern's that stays between the supervisor and the command. The doorman reads the
  address once, judges it and makes the connection itself, on the socket of the program that asked; the kernel
  is never told to carry on with the program's own request, which could have been changed after the look. A
  socket file is reached only when it lies in one of the command's own folders (`writable`), is found again
  from a handle on that folder held since before the command started, through no link, and has no second
  name; a socket name that is no file only where the names are the command's own (a network of its own, or
  Landlock's rule about names); an address only in a network of its own. A kind of socket whose messages each
  carry their own receiver is not made where that matters (a Unix socket for single messages; UDP where the
  run has no network of its own), nor is the newer way to hand the kernel a queue of requests (io_uring), nor,
  without names of the command's own (`shm`), shared memory of the older kind. Each refusal is said once in the
  run's output (`BLOCKED_MARK`, `SAID`), where `lantern.sandbox` reads it as the sandbox's doing. The caller
  asks this system first (`try_own_sockets`) and names `sockets` only where it can: a launcher that then cannot
  make the doorman does not start the command (`must`). The doorman is the command's parent and of its user:
  where the kernel can refuse a signal (Landlock ABI 6, Linux 6.12) the command is put one domain below it
  (`_below`), so the tests can neither end nor stop their doorman, as they could not signal the launcher
  before there was one; on an older kernel they can, and then nothing more is let through (the kernel answers
  "no such call" for a doorman that is gone) and the run ends with it. None can be made on a kernel before 5.6, on a
  processor that is neither x86-64 nor ARM64, where a system lets no program look into another, or beneath
  another doorman (a run inside a run: the kernel hears one, and the outer one judges by the outer run's
  folders). What it costs honest programs: a server that asks who connected is told the doorman (the same
  user); a 32-bit program is ended at its first request; a program that closed itself to the others of its user
  gets no connection; and a signal that arrives in the instant before the doorman has heard a request reads as
  "under way" to a program whose handlers do not have the request made again, which Python's own do not
  (measured here, 5,000 connections under about a thousand signals a second: 50 failed afterwards with "not
  connected"; the way kernels before 5.19 work, which hand a request back at any signal, 1,037; with handlers
  that restart, as Node, Go and most C programs have them, 0 either way);
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
import itertools
import json
import os
import signal
import stat
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
    "libraries": "the tests' Python could not be limited to the libraries fetched for them (the ones installed "
                 "on this computer could not be taken off its path)",
    "own-network": "the tests could not be given a network of their own, which is where they may listen and "
                   "call what they started",
    "own-memory": "the tests could not be given a memory folder of their own, which is where process pools and "
                  "locks are kept and what keeps the shared memory of your other programs out of their reach",
    "unreadable": "the user the sandbox runs the tests as cannot read Lantern's own files, the Python that runs "
                  "them or its libraries: they lie in a folder that user may not enter (install Lantern where "
                  "every user of this computer can read it, or start it as an ordinary user)",
    "landlock-read": "the kernel's rules that close your own folders to the tests could not be made",
    "own-sockets": "the tests' programs could not be put behind Lantern's doorman, which makes their connections "
                   "for them and keeps the socket files of your other programs out of their reach",
    "closed": "what the tests are made of (Lantern's recorder, the program that runs them or its libraries) lies "
              "where the rules that close your own folders to the tests leave it unreadable",
}
ASK = 6.0                  # seconds `lantern.sandbox` waits after asking (SIGTERM) before it kills the process group
_SWEEP = 3.0               # seconds the supervisor spends ending what the command started

# Landlock filesystem rights that change things (reads are not restricted)
_FS_WRITE = {1: (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)}
_FS_WRITE[2] = _FS_WRITE[1] | (1 << 13)          # REFER
_FS_WRITE[3] = _FS_WRITE[2] | (1 << 14)          # TRUNCATE
_FS_LIST = 1 << 3                                # READ_DIR
_FS_READ_FILE = (1 << 0) | (1 << 2)              # EXECUTE | READ_FILE: what a file can be opened to
_FS_READ = _FS_READ_FILE | _FS_LIST              # ... and a folder: what a closed folder is closed to (`read`)
MOST_BESIDE = 50_000                             # the entries of one folder that are opened one by one
# What a Linux system has in the folders that lie on the way to a person's own, for where such a folder cannot be
# listed: a run started inside another run (Lantern's own tests start runs, and may themselves run in one) is under
# rules that let it pass through `/` and not list it. The names are tried one by one; what is not there, or is
# closed by the rules around, is not opened by trying.
USUAL = {
    "/": ("bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "libx32", "nix", "opt", "proc", "run",
          "sbin", "snap", "sys", "usr", "var"),
    "/dev": ("null", "zero", "full", "random", "urandom", "tty", "ptmx", "pts", "console"),
    "/var": ("lib", "cache", "log", "local", "opt", "backups"),
    "/run": ("lock",),
}
_NET_TCP = (1 << 0) | (1 << 1)                   # BIND_TCP | CONNECT_TCP (ABI 4)
_SCOPE_SIGNAL = 1 << 1                           # LANDLOCK_SCOPE_SIGNAL (ABI 6): no signal to a process outside
_SCOPE_NAME = 1 << 0                             # LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (ABI 6): no socket name outside
_CLONE_NEWUSER, _CLONE_NEWNET = 0x10000000, 0x40000000
_CLONE_NEWNS, _CLONE_NEWIPC = 0x00020000, 0x08000000
_MS_NOSUID, _MS_NODEV, _MS_REC, _MS_PRIVATE = 0x2, 0x4, 0x4000, 0x40000
# Where Linux keeps named semaphores and shared memory, as files. An empty folder of the run's own is put over it.
MEMORY_FOLDER = "/dev/shm"   # nosec B108: the system's own name for that folder; Lantern makes no file in it by name
MEMORY_VARIABLE = "LANTERN_SANDBOX_SHM"          # how the command is told that this folder is its run's own
MEMORY_LEAST, MEMORY_MOST = 64 << 20, 1 << 30    # the bytes a run's memory folder holds: never less, never more
_SIOCGIFFLAGS, _SIOCSIFFLAGS, _IFF_UP = 0x8913, 0x8914, 0x1
NET_VARIABLE = "LANTERN_SANDBOX_NET"             # how the command is told that its network is its own


class _Refused(Exception):
    """A restriction the sandbox counts on could not be put in place; the reason has been printed."""

    def __init__(self, word: str, number: int | None = None):
        super().__init__(word)
        self.number = number


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _refuse(word: str, number: int | None = None) -> None:
    _say(f"{MARK} {word}" + (f" {number}" if number else ""))
    raise _Refused(word, number)


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


def _beside(closed, top: str = "/") -> list[str]:
    """Every entry that lies beside the way from `top` down to a folder of `closed`, as full paths: what is open
    when those folders are closed. A closed folder, the folders on the way to it and every link are not named;
    of a folder that cannot be listed, or holds more than `MOST_BESIDE` entries, only the names every system has
    in it are named (`USUAL`; for most folders none), and the way goes on through it (less is open then, never
    more). `closed`: full paths with no link in them (the caller resolved them)."""
    top = os.path.normpath(top)
    tree: dict = {}
    for path in closed if isinstance(closed, (list, tuple)) else []:
        if not isinstance(path, str) or not os.path.isabs(path):
            continue
        path = os.path.normpath(path)
        if path == top:
            return []                                   # everything is closed
        if os.path.commonpath([path, top]) != top:
            continue
        parts = os.path.relpath(path, top).split(os.sep)
        node = tree
        for part in parts[:-1]:
            if node.get(part, 0) is None:               # a folder above it is closed already
                node = None
                break
            node = node.setdefault(part, {})
        if node is not None:
            node[parts[-1]] = None
    found: list[str] = []

    def walk(folder: str, node: dict) -> None:
        try:
            with os.scandir(folder) as entries:
                names = [(e.name, e.is_symlink()) for e in itertools.islice(entries, MOST_BESIDE + 1)]
        except OSError:
            names = None
        if names is None or len(names) > MOST_BESIDE:
            names = [(name, os.path.islink(os.path.join(folder, name)))
                     for name in dict.fromkeys((*USUAL.get(folder, ()), *node))
                     if os.path.lexists(os.path.join(folder, name))]
        for name, link in names:
            below = node.get(name, 0)
            if link or below is None:
                continue
            if below == 0:
                found.append(os.path.join(folder, name))
            else:
                walk(os.path.join(folder, name), below)
    walk(top, tree)
    return found


def _texts(x) -> list[str]:
    return [p for p in x if isinstance(p, str) and os.path.isabs(p)] if isinstance(x, list) else []


def _landlock(writable: list[str], net: bool, ports=(), read=None) -> tuple[str, str | None, int]:
    """Put this process under Landlock. Returns (what to print after "sandbox: Landlock", None or the word in
    REASONS for what failed, the system's error number). `ports`: where TCP is refused (`net`), the ports this
    process may still connect to (the fetching step's one way out: the doorkeeper, `lantern._stores`). `read`:
    the policy's rule for reads (this module's opening text); None leaves reads as they are."""
    if not sys.platform.startswith("linux"):
        return "not Linux", None, 0
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        return "kernel has no Landlock", None, 0
    reads = isinstance(read, dict)
    write = _FS_WRITE[min(abi, 3)]
    fs = write | (_FS_READ if reads else 0)
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

    def opens(path: str, rights: int) -> bool | None:
        """One entry opened to reads, as itself: never through a link, a file to what a file can be opened to.
        None: this user cannot come to it, or it is not there, so nothing was lost by not opening it."""
        try:
            fd = os.open(path, O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as e:
            return None if e.errno in (errno.EACCES, errno.ENOENT, errno.ENOTDIR) else False
        try:
            mode = os.fstat(fd).st_mode
            if stat.S_ISLNK(mode):
                return False
            if not stat.S_ISDIR(mode):
                rights &= _FS_READ_FILE
            return bool(rights) and libc.syscall(445, rfd, 1, ctypes.byref(Beneath(rights, fd)), 0) == 0
        except OSError:
            return False
        finally:
            os.close(fd)
    missed = 0
    if reads:
        beside = _beside(_texts(read.get("closed")))
        if not sum(1 for path in beside if opens(path, _FS_READ)):
            os.close(rfd)           # not even the system's own folders: no program could be started under that
            return "could not name what stays open to reads", "landlock-read", 0
        named = [(p, _FS_READ) for p in _texts(read.get("open"))] + [(p, _FS_LIST) for p in _texts(read.get("list"))]
        missed = sum(1 for path, rights in named if opens(path, rights) is False)
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
    opened = []
    if abi >= 4 and net:
        class Port(ctypes.Structure):
            _pack_ = 1
            _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]
        for port in ports:
            if type(port) is int and 0 < port < 65536:
                rule = Port(1 << 1, port)                    # CONNECT_TCP to this port
                if libc.syscall(445, rfd, 2, ctypes.byref(rule), 0) == 0:   # LANDLOCK_RULE_NET_PORT
                    opened.append(port)
                else:
                    _say(f"sandbox: Landlock could not allow the way to port {port} (error {ctypes.get_errno()})")
    if libc.prctl(38, 1, 0, 0, 0) != 0:                      # PR_SET_NO_NEW_PRIVS
        number = ctypes.get_errno()
        os.close(rfd)
        return f"no_new_privs error {number}", "no-new-privileges", number
    if libc.syscall(446, rfd, 0) != 0:
        number = ctypes.get_errno()
        os.close(rfd)
        return f"restrict error {number}", "landlock-restrict", number
    os.close(rfd)
    closed = ""
    if reads:
        closed = ", the person's own folders closed to reads" + (f" ({missed} of the places named to stay open "
                                                                 "could not be opened)" if missed else "")
    return (f"on (ABI {abi}{', no TCP' if abi >= 4 and net else ''}{' but to its doorkeeper' if opened else ''}"
            f"{', no signals or socket names outside' if abi >= 6 else ''}{closed})"), None, 0


def _unshare(flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(flags) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _as_itself(uid: int, gid: int) -> None:
    """In a user namespace this process just made: the user and the group stay the ones they were."""
    for name, text in (("setgroups", "deny"), ("uid_map", f"{uid} {uid} 1"), ("gid_map", f"{gid} {gid} 1")):
        with open(f"/proc/self/{name}", "w", encoding="ascii") as f:
            f.write(text)


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
            _as_itself(uid, gid)
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


def _memory_folder(policy: dict) -> int:
    """The bytes the policy gives the run's memory folder, or 0 when it asks for none."""
    n = policy.get("shm")
    return max(MEMORY_LEAST, min(n, MEMORY_MOST)) if type(n) is int and n > 0 else 0


def _own_memory(size: int, user: bool = False) -> int:
    """Give this process a memory folder of its own: `MEMORY_FOLDER` is where Linux keeps named semaphores and
    shared memory as files (every lock, pool and queue of Python's `multiprocessing` is made from one), and it is
    one folder for every program of the computer. In a new mount namespace an empty one is put in its place,
    which holds `size` bytes at most and is gone when the last process of the run is; nothing is mounted anywhere
    else, and no mount of this namespace reaches the computer's own. With it, the names of the older kind of
    shared memory, semaphores and message queues (System V, and POSIX queues) are the run's own too: a new IPC
    namespace, so the run finds none of another program's and leaves none behind. `user`: through a new user
    namespace, as for the network. Returns 0, or the system's error number."""
    if not sys.platform.startswith("linux"):
        return errno.ENOSYS
    uid, gid = os.geteuid(), os.getegid()
    try:
        before = os.lstat(MEMORY_FOLDER)
        if not stat.S_ISDIR(before.st_mode):
            return errno.ENOTDIR
        _unshare((_CLONE_NEWUSER if user else 0) | _CLONE_NEWNS | _CLONE_NEWIPC)
        if user:
            _as_itself(uid, gid)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
        for what in ((None, b"/", None, _MS_REC | _MS_PRIVATE, None),
                     (b"tmpfs", MEMORY_FOLDER.encode(), b"tmpfs", _MS_NOSUID | _MS_NODEV,
                      f"mode=1777,size={int(size)},nr_inodes=65536".encode("ascii"))):
            if libc.mount(*what) != 0:
                number = ctypes.get_errno()
                raise OSError(number, os.strerror(number))
        after = os.lstat(MEMORY_FOLDER)
        if not stat.S_ISDIR(after.st_mode) or after.st_dev == before.st_dev or os.listdir(MEMORY_FOLDER):
            return errno.EXDEV          # not a new, empty folder: nothing is said to be the run's own
    except OSError as e:
        return e.errno or errno.EPERM
    return 0


def try_own_memory(nobody: bool) -> int:
    """For a throwaway process: can the command of a run be given a memory folder of its own on this system? Does
    what `_restrict` does for it, in the same order. 0, or the error number of the step that was refused."""
    size = MEMORY_LEAST
    if os.geteuid() == 0:
        if _own_memory(size) == 0:
            return 0
        if nobody:
            try:
                _become_nobody()
            except OSError as e:
                return e.errno or errno.EPERM
    return _own_memory(size, True)


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


def _door(policy: dict) -> dict | None:
    """The doorkeeper a fetching step asked for (`lantern._stores`), when the policy names one in full."""
    door = policy.get("door")
    if isinstance(door, dict) and type(door.get("port")) is int and isinstance(door.get("allowed"), list):
        return door
    return None


def _restrict(policy: dict, hand=None) -> dict:
    """Limits, the unprivileged user, Landlock and no new privileges, in the process that is about to become the
    command. Raises `_Refused`, the reason printed, when the command must not be started. `hand`: this side of a
    socket pair whose other side the launcher keeps: a fetching step's listener goes over it (`_door`). Returns
    the walls that stand, for the doorman (`_doorman`): `net` a network of the command's own, `ipc` names of its
    own for shared memory of the older kind, `scope` no socket name of a program outside, `folders` the folders
    that are the command's own."""
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
    shm, kept, shm_number = _memory_folder(policy), False, 0
    os.environ.pop(MEMORY_VARIABLE, None)   # said by this launcher alone, after it made the folder
    if own and os.geteuid() == 0:           # root makes it before the change of user takes the right away
        number = _own_network(False)
        made = number == 0
    if shm and os.geteuid() == 0:
        shm_number = _own_memory(shm)
        kept = shm_number == 0
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
    in_new = False
    if own and not made:                    # any other user: through a user namespace, where the system allows one
        number = _own_network(True)
        made = in_new = number == 0
    if shm and not kept:                    # ... in the one the network was made in, or in one of its own
        shm_number = _own_memory(shm, not in_new)
        kept = shm_number == 0
    if kept:
        try:
            os.environ[MEMORY_VARIABLE] = "own:%d" % os.lstat(MEMORY_FOLDER).st_dev
            _say("sandbox: a memory folder of its own (process locks, pools and queues work; it is gone with the run)")
        except OSError as e:
            kept, shm_number = False, e.errno or errno.EPERM
    if shm and not kept:
        # Asked for only where the caller tried this system first (`try_own_memory`), and promised with it: what
        # the other programs of this computer keep in shared memory is out of the command's reach.
        _say("sandbox: a memory folder of its own could not be made")
        if must:
            _refuse("own-memory", shm_number)
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
    door = _door(policy)
    if door and hand is not None:
        # A fetching step: the one thing that listens in this network is made here and handed to the launcher,
        # which stays outside and answers it (the doorkeeper). No listener, no command: it would fetch nothing.
        try:
            if not made:
                raise OSError(errno.ENETUNREACH, "no network of its own")
            import socket
            from . import _stores
            with _stores.listen(door["port"]) as listener:
                socket.send_fds(hand, [b"door"], [listener.fileno()])
            _say("sandbox: the only way out of that network is Lantern's doorkeeper, which reaches the store "
                 "and nothing else")
        except OSError as e:
            _say("sandbox: the doorkeeper's listener could not be made")
            _refuse("own-network", e.errno)
        finally:
            hand.close()
    ports = policy.get("tcp_ports")     # only a fetching step names any (`lantern.libraries`)
    read = policy.get("read") if isinstance(policy.get("read"), dict) else None
    writable = [*policy.get("writable", []), *([MEMORY_FOLDER] if kept else [])]
    state, failed, number = _landlock(writable, bool(policy.get("net")) and not made,
                                      ports if isinstance(ports, list) else (), read)
    if failed is None and read is not None and state.startswith("on"):
        # Under the rules now: what the command is made of has to be among what stayed open. A Python that cannot
        # read its own library, or a recorder nobody can open, would end with an error that reads as tests that
        # failed.
        for path in [p for p in (named if isinstance(named, list) else [])] + ([runs] if runs else []):
            try:
                folder = os.path.isdir(path)
                os.close(os.open(path, os.O_RDONLY | os.O_CLOEXEC | (os.O_DIRECTORY if folder else 0)))
            except (OSError, TypeError, ValueError):
                _say(f"sandbox: with your own folders closed to them, the tests cannot read {str(path)[:300]}")
                failed, number = "closed", 0
                break
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
    return {"net": made, "ipc": kept, "scope": "no signals or socket names outside" in state, "folders": writable}


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


# ---------------------------------------------------------------------------- Linux: the doorman
BLOCKED_MARK = "LANTERN-SANDBOX-BLOCKED:"    # how a refusal is said in a run's output (`lantern.sandbox.MARK`)
KILLABLE = True       # the kernel (5.19+) is asked to hold a signal that is not fatal back until the doorman answered
MOST_TOLD = 20        # the refusals a doorman writes into a run's output, each place once
MOST_AT_ONCE = 128    # the requests a doorman works on at the same time
MOST_REMEMBERED = 4096   # the sockets whose last connection a doorman keeps in mind
_O_PATH = 0o10000000
_AF_UNIX, _AF_INET, _AF_INET6, _AF_NETLINK = 1, 2, 10, 16
_RET_ASK, _RET_ALLOW, _RET_ERRNO = 0x7FC00000, 0x7FFF0000, 0x00050000
_NOTIF_RECV, _NOTIF_SEND, _NOTIF_VALID, _NOTIF_VALID_OLD = 0xC0502100, 0xC0182101, 0x40082102, 0x80082102
_NEW_LISTENER, _WAIT_KILLABLE = 1 << 3, 1 << 5
_MSG_FASTOPEN = 0x20000000
_PIDFD_THREAD = 0x80
_KNOCK_SAYS = getattr(errno, "ENOANO", 55)       # what only a doorman answers a connection with ("no anode")
# The requests the doorman is about, by their numbers on the two kinds of processor it is made for. `older`: shared
# memory, semaphores and message queues of the older kind (System V) and POSIX message queues, whose names every
# program of the computer shares unless the run was given names of its own (`shm`).
_CALLS = {
    "x86_64": {"arch": 0xC000003E, "x32": 0x40000000, "connect": 42, "socket": 41, "socketpair": 53, "sendto": 44,
               "sendmsg": 46, "sendmmsg": 307, "io_uring_setup": 425, "seccomp": 317, "pidfd_getfd": 438,
               "process_vm_readv": 310, "older": (29, 30, 31, 64, 65, 66, 68, 69, 70, 71, 220, 240)},
    "aarch64": {"arch": 0xC00000B7, "x32": 0, "connect": 203, "socket": 198, "socketpair": 199, "sendto": 206,
                "sendmsg": 211, "sendmmsg": 269, "io_uring_setup": 425, "seccomp": 277, "pidfd_getfd": 438,
                "process_vm_readv": 270, "older": (186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 180)},
}
# What the doorman writes into the run's output when it refuses (after BLOCKED_MARK). Each starts with the kind
# `lantern.sandbox.blocked_reasons` sorts it under.
SAID = {
    "file": "network connect to the socket file {where} (a program of the tests asked for it; only a socket file "
            "in the tests' own folders is reached)",
    "second": "network connect to the socket file {where} (it has a second name somewhere, so it may be another "
              "program's)",
    "name": "network connect to the socket name {where} (on this system the tests' network is the computer's own, "
            "so such a name may be another program's)",
    "address": "network connect to {where} (on this system the tests' network is the computer's own, so nothing "
               "is let through)",
    "messages": "network: a socket for single messages between programs (a Unix datagram socket) was not made: "
                "each message names its own receiver, which the sandbox cannot look at",
    "udp": "network: a UDP socket was not made (on this system the tests' network is the computer's own, and a "
           "UDP message goes wherever it is sent, a name server included)",
    "older": "write to shared memory, a semaphore or a message queue of the older kind (System V, POSIX message "
             "queues): this system gave the tests no names of their own for them, so another program's could be "
             "reached",
    "foreign": "network and every other request of a program built for another kind of processor (a 32-bit "
               "program): the sandbox cannot read what it asks for, so it was ended",
    "closed": "network connect by a program the sandbox cannot look into (it closed itself to the other programs "
              "of its user)",
    "more": "network and other requests: the sandbox refused more than is listed here",
}
# The C library's own cache of names, which it tries before it looks a user or a host up by itself and does
# without: refused like any socket file outside the run's folders, and not said (nothing the tests did failed).
_NOT_SAID = ("/run/nscd/socket", "/var/run/nscd/socket")


def _plain(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:300]


def _numbers(asked: bytes) -> str:
    """An address of the internet kind as a person writes it."""
    import socket
    try:
        kind, port = int.from_bytes(asked[:2], sys.byteorder), int.from_bytes(asked[2:4], "big")
        if kind == _AF_INET and len(asked) >= 8:
            return "%s:%d" % (socket.inet_ntop(socket.AF_INET, asked[4:8]), port)
        if kind == _AF_INET6 and len(asked) >= 24:
            return "[%s]:%d" % (socket.inet_ntop(socket.AF_INET6, asked[8:24]), port)
    except (OSError, ValueError):
        pass
    return "an address"


def _filter(table: dict, own_net: bool, own_ipc: bool) -> bytes:
    """The half of the doorman the kernel runs: a list of comparisons (classic BPF, a seccomp filter) made on every
    request of the command and of everything it starts, before the kernel does what was asked. It reads the
    request's number and its plain arguments, never memory, so nothing in it can be changed after it looked.

    * a connection (`connect`) is never made by the kernel for the one that asked: the doorman is asked;
    * a socket is made only of a kind whose every way to another program goes through `connect`: a Unix socket for
      a stream or for packets in sequence; TCP; UDP where the run has a network of its own (where it has none, a
      UDP message would go wherever it is sent); a socket that asks the kernel about the computer's own network
      (netlink: routes, sockets, devices). A Unix socket for single messages names the receiver in each message,
      which no filter and no doorman can see in time, so none is made, alone or as a pair (the doorman says so);
      TCP over several paths, SCTP, raw sockets and every other family (to the machine around a virtual one,
      Bluetooth, the kernel's own services) get the answer a kernel without them gives;
    * the newer way to hand the kernel a queue of requests (io_uring), which would carry a connection past this
      list, gets the answer of a kernel without it;
    * with no network of the run's own: data sent together with a TCP opening (which connects without `connect`)
      is refused;
    * with no names of the run's own for them (`own_ipc`): shared memory, semaphores and queues of the older kind
      are not handed out (the doorman says so);
    * a request made the way another kind of processor makes it (a 32-bit program) cannot be read: the doorman is
      asked, and ends that program."""
    import struct
    LD, JEQ, JGE, JSET, AND, RET = 0x20, 0x15, 0x35, 0x45, 0x54, 0x06
    rows: list = []

    def no(number: int) -> int:
        return _RET_ERRNO | number

    def arg(i: int) -> None:
        rows.append((LD, None, None, 16 + 8 * i))    # the low half, which is all the kernel reads of an int

    def jump(k: int, yes: str | None = None, otherwise: str | None = None, how: int = JEQ) -> None:
        rows.append((how, yes, otherwise, k))

    def kind_of() -> None:
        arg(1)
        rows.append((AND, None, None, 0xF))          # the kind of socket, without the flags written beside it

    rows.append((LD, None, None, 4))
    jump(table["arch"], None, "ask")
    rows.append((LD, None, None, 0))
    if table.get("x32"):
        jump(table["x32"], "none", None, JGE)
    jump(table["connect"], "ask")
    jump(table["io_uring_setup"], "none")
    jump(table["socket"], "socket")
    jump(table["socketpair"], "pair")
    if not own_net:
        jump(table["sendto"], "flags3")
        jump(table["sendmmsg"], "flags3")
        jump(table["sendmsg"], "flags2")
    if not own_ipc:
        for number in table["older"]:
            jump(number, "ask")
    rows.append((RET, None, None, _RET_ALLOW))
    rows.append("socket")
    arg(0)
    jump(_AF_UNIX, "unix")
    jump(_AF_INET, "inet")
    jump(_AF_INET6, "inet")
    jump(_AF_NETLINK, "netlink")
    rows.append((RET, None, None, no(errno.EAFNOSUPPORT)))
    rows.append("pair")
    arg(0)
    jump(_AF_UNIX, None, "allow")
    rows.append("unix")
    kind_of()
    jump(1, "allow")                                 # SOCK_STREAM
    jump(5, "allow")                                 # SOCK_SEQPACKET
    rows.append((RET, None, None, _RET_ASK))
    rows.append("inet")
    kind_of()
    jump(1, "stream")
    jump(2, "datagram")
    jump(3, "raw")
    rows.append((RET, None, None, no(errno.ESOCKTNOSUPPORT)))
    rows.append("raw")
    rows.append((RET, None, None, no(errno.EPERM)))
    rows.append("stream")
    arg(2)
    jump(0, "allow")
    jump(6, "allow")                                 # IPPROTO_TCP
    rows.append((RET, None, None, no(errno.EPROTONOSUPPORT)))
    rows.append("datagram")
    if own_net:
        arg(2)
        jump(0, "allow")
        jump(17, "allow")                            # IPPROTO_UDP
        rows.append((RET, None, None, no(errno.EPROTONOSUPPORT)))
    else:
        rows.append((RET, None, None, _RET_ASK))
    rows.append("netlink")
    arg(2)
    jump(0, "allow")                                 # NETLINK_ROUTE
    jump(4, "allow")                                 # NETLINK_SOCK_DIAG
    jump(15, "allow")                                # NETLINK_KOBJECT_UEVENT
    rows.append((RET, None, None, no(errno.EPROTONOSUPPORT)))
    rows.append("flags3")
    arg(3)
    jump(_MSG_FASTOPEN, "unsupported", "allow", JSET)
    rows.append("flags2")
    arg(2)
    jump(_MSG_FASTOPEN, "unsupported", "allow", JSET)
    rows.append("unsupported")
    rows.append((RET, None, None, no(errno.EOPNOTSUPP)))
    rows.append("none")
    rows.append((RET, None, None, no(errno.ENOSYS)))
    rows.append("ask")
    rows.append((RET, None, None, _RET_ASK))
    rows.append("allow")
    rows.append((RET, None, None, _RET_ALLOW))
    where, n = {}, 0
    for row in rows:
        if isinstance(row, str):
            where[row] = n
        else:
            n += 1
    out, n = [], 0
    for row in rows:
        if isinstance(row, str):
            continue
        code, yes, otherwise, k = row
        jt = where[yes] - n - 1 if yes else 0
        jf = where[otherwise] - n - 1 if otherwise else 0
        if not (0 <= jt < 256 and 0 <= jf < 256):
            raise ValueError("a jump of the filter is out of reach")
        out.append(struct.pack("=HBBI", code, jt, jf, k))
        n += 1
    return b"".join(out)


def _listen(table: dict, program: bytes) -> int:
    """Put this process, what it becomes and everything it starts under the filter. Returns the kernel's handle
    through which the doorman hears their requests and answers them. OSError when the kernel refuses."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    raw = ctypes.create_string_buffer(program, len(program))

    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    prog = Program(len(program) // 8, ctypes.cast(raw, ctypes.c_void_p))
    number = errno.EINVAL
    for flags in dict.fromkeys(((_NEW_LISTENER | _WAIT_KILLABLE) if KILLABLE else _NEW_LISTENER, _NEW_LISTENER)):
        fd = libc.syscall(ctypes.c_long(table["seccomp"]), ctypes.c_ulong(1), ctypes.c_ulong(flags), ctypes.byref(prog))
        if fd >= 0:
            return int(fd)
        number = ctypes.get_errno()
        if number != errno.EINVAL:      # an older kernel does not know the second flag: once more without it
            break
    raise OSError(number, os.strerror(number))


def _knock(libc, knock: bytes) -> None:
    """The command's side, once, before the command is started: ask for a connection to a name nobody listens at.
    Only a doorman that heard the request, found the process, took its socket and read the address out of its
    memory, all of which it does for every later request, answers it the way `_KNOCK_SAYS` says. Anything else
    is an OSError, and the command is not started."""
    import socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        buffer = ctypes.create_string_buffer(knock, len(knock))
        done = libc.connect(s.fileno(), buffer, len(knock))
        number = ctypes.get_errno() if done != 0 else 0
    if number != _KNOCK_SAYS:
        raise OSError(number or errno.EPROTO, "the doorman did not answer")


class _Doorman:
    """The half of the doorman that runs beside the command: it holds the kernel's handle (`listener`) and
    answers every request the filter sent its way. A connection is made by the doorman itself, on the socket of
    the program that asked, to an address the doorman read once and judged: the kernel is never told to carry
    on with the program's own request, because the program could have put another address, or another socket,
    in its place between the look and the act."""

    def __init__(self, listener: int, table: dict, walls: dict, knock: bytes):
        import threading
        self.listener, self.table = listener, table
        self.own_net, self.scoped = bool(walls.get("net")), bool(walls.get("scope"))
        self.knock: bytes | None = knock
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.roots: list[tuple[str, int]] = []       # the run's own folders: the real name, and the folder held open
        for folder in walls.get("folders") or []:
            try:
                real = os.path.realpath(folder)
                self.roots.append((real, os.open(real, _O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)))
            except (OSError, TypeError, ValueError):
                continue
        self.lock = threading.Lock()
        self.told: set[str] = set()
        self.made: dict = {}                         # the connections the doorman made, by socket (`_connect`)
        self.gates: dict = {}                        # one socket, one connection at a time: [a lock, who waits]
        self.room = threading.BoundedSemaphore(MOST_AT_ONCE)

    def serve(self) -> None:
        """Hear requests until the last program under the filter is gone. One that cannot be answered is never
        left waiting: a doorman that fails ends itself, and the kernel then refuses what was asked of it."""
        import fcntl
        import select
        import threading
        try:
            poll = select.poll()
            poll.register(self.listener, select.POLLIN)
            while True:
                for _fd, event in poll.poll(1000):
                    if not event & select.POLLIN:
                        return                       # nobody is left to ask
                    heard = bytearray(80)
                    try:
                        fcntl.ioctl(self.listener, _NOTIF_RECV, heard)
                    except OSError as e:
                        if e.errno in (errno.ENOENT, errno.EINTR, errno.EAGAIN):
                            continue                 # whoever asked is gone already
                        raise
                    self.room.acquire()
                    try:
                        threading.Thread(target=self._one, args=(bytes(heard),), daemon=True).start()
                    except RuntimeError:             # no thread to be had: answered here, in turn
                        self._one(bytes(heard))
        except BaseException as e:  # noqa: BLE001 - whatever it is, no request may wait on a doorman that is gone
            _say(f"sandbox: the doorman stopped ({type(e).__name__}); the kernel refuses what is asked of it now")
            os.kill(os.getpid(), signal.SIGKILL)

    def _one(self, heard: bytes) -> None:
        import struct
        try:
            ident, tid, _flags, nr, arch, _ip, *args = struct.unpack("=QIIiIQ6Q", heard)
            try:
                number = self._decide(ident, tid, nr, arch, args)
            except OSError as e:
                number = e.errno or errno.EPERM
            except Exception:  # noqa: BLE001 - a request the doorman cannot work out is refused
                number = errno.EPERM
            if number is not None:
                self._send(ident, number)
        finally:
            self.room.release()

    def _decide(self, ident: int, tid: int, nr: int, arch: int, args: list) -> int | None:
        """The error number one request is answered with, or None when it was answered here."""
        table = self.table
        if arch != table["arch"]:
            self._tell(SAID["foreign"])
            self._end(ident, tid)
            return errno.ENOSYS
        if nr == table["connect"]:
            fd, size = args[0] & 0xFFFFFFFF, args[2] & 0xFFFFFFFF
            self._connect(ident, tid, fd - (1 << 32) if fd >> 31 else fd, args[1], size)
            return None
        if nr in (table["socket"], table["socketpair"]):
            self._tell(SAID["messages" if args[0] & 0xFFFFFFFF == _AF_UNIX else "udp"])
            return errno.EACCES
        if nr in table["older"]:
            self._tell(SAID["older"])
        return errno.ENOSYS

    def _send(self, ident: int, number: int = 0) -> bool:
        """Answer one request: done (0), or the error number the program gets. False when nobody waits for the
        answer any more."""
        import fcntl
        import struct
        try:
            fcntl.ioctl(self.listener, _NOTIF_SEND, struct.pack("=QqiI", ident, 0, -number, 0))
            return True
        except OSError:
            return False

    def _valid(self, ident: int) -> bool:
        """Is the one that asked still waiting for this answer? Asked after the doorman took hold of the process
        by its number: a number is given to a new process when the old one is gone."""
        import fcntl
        import struct
        for request in (_NOTIF_VALID, _NOTIF_VALID_OLD):     # the second: how kernels before 5.17 named it
            try:
                fcntl.ioctl(self.listener, request, struct.pack("=Q", ident))
                return True
            except OSError as e:
                if e.errno != errno.EINVAL:
                    return False
        return False

    def _hold(self, tid: int) -> int:
        """The process a request came from, held (a pidfd): the very thread that asked where the kernel hands
        one out (6.9+), else its process."""
        try:
            return os.pidfd_open(tid, _PIDFD_THREAD)
        except OSError as e:
            if e.errno != errno.EINVAL:
                raise
        with open(f"/proc/{tid}/status", "rb") as f:
            for line in f:
                if line.startswith(b"Tgid:"):
                    return os.pidfd_open(int(line.split()[1]), 0)
        raise OSError(errno.ESRCH, os.strerror(errno.ESRCH))

    def _read(self, tid: int, pointer: int, size: int) -> bytes:
        """`size` bytes of the memory of the one that asked: the address it named, read once."""
        class Piece(ctypes.Structure):
            _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
        mine = ctypes.create_string_buffer(size)
        here, there = Piece(ctypes.cast(mine, ctypes.c_void_p), size), Piece(ctypes.c_void_p(pointer), size)
        got = self.libc.syscall(ctypes.c_long(self.table["process_vm_readv"]), ctypes.c_long(tid),
                                ctypes.byref(here), ctypes.c_ulong(1), ctypes.byref(there), ctypes.c_ulong(1),
                                ctypes.c_ulong(0))
        if got < 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
        if got != size:
            raise OSError(errno.EFAULT, os.strerror(errno.EFAULT))
        return mine.raw

    def _take(self, held: int, fd: int) -> int:
        """The socket the one that asked named by its number, as a handle of the doorman's own on the same
        socket: what the doorman connects is what the program goes on to use."""
        got = self.libc.syscall(ctypes.c_long(self.table["pidfd_getfd"]), ctypes.c_int(held), ctypes.c_int(fd),
                                ctypes.c_uint(0))
        if got < 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
        return int(got)

    def _family(self, fd: int) -> int:
        value, size = ctypes.c_int(0), ctypes.c_uint(ctypes.sizeof(ctypes.c_int))
        if self.libc.getsockopt(fd, 1, 39, ctypes.byref(value), ctypes.byref(size)) != 0:   # SOL_SOCKET, SO_DOMAIN
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))                                     # no socket: said as such
        return value.value

    def _end(self, ident: int, tid: int) -> None:
        try:
            held = self._hold(tid)
        except OSError:
            return
        try:
            if self._valid(ident):
                signal.pidfd_send_signal(held, signal.SIGKILL)
        except OSError:
            pass
        finally:
            os.close(held)

    def _tell(self, text: str) -> None:
        """One refusal into the run's output, where `lantern.sandbox` reads it: each once, and not without end."""
        with self.lock:
            if text in self.told or len(self.told) > MOST_TOLD:
                return
            self.told.add(text)
            if len(self.told) > MOST_TOLD:
                text = SAID["more"]
        try:
            os.write(2, f"{BLOCKED_MARK} {text}\n".encode("utf-8", "replace"))
        except OSError:
            pass

    def _connect(self, ident: int, tid: int, fd: int, pointer: int, size: int) -> None:
        """Make, refuse or pass on to the kernel's own judgement one connection, and answer the one that asked."""
        import threading
        if size > 128:                               # longer than any address: what the kernel says to that
            self._send(ident, errno.EINVAL)
            return
        keep: list[int] = []
        try:
            try:
                held = self._hold(tid)
                keep.append(held)
                asked = self._read(tid, pointer, size) if size else b""
                mine = self._take(held, fd)
                keep.append(mine)
            except OSError as e:
                if e.errno in (errno.EPERM, errno.EACCES):
                    self._tell(SAID["closed"])
                    self._send(ident, errno.EACCES)
                elif e.errno != errno.ESRCH:
                    self._send(ident, e.errno or errno.EPERM)
                return
            if not self._valid(ident):
                return                               # whoever asked is gone, or was interrupted: nothing is done
            with self.lock:
                first = self.knock is not None and asked == self.knock
                if first:
                    self.knock = None
            if first:
                self._send(ident, _KNOCK_SAYS)       # the command's side, before the command (`_knock`)
                return
            family = self._family(mine)
            kind = int.from_bytes(asked[:2], sys.byteorder) if len(asked) >= 2 else -1
            address = asked
            if family == _AF_UNIX and kind == _AF_UNIX and len(asked) > 2:
                if asked[2] == 0:
                    # A socket name that is no file. In a network of the run's own the names are the run's own;
                    # under Landlock's rule the kernel refuses the doorman, which is under the same rule, a name
                    # of a program outside. With neither, nothing tells whose name it is.
                    if not (self.own_net or self.scoped):
                        self._tell(SAID["name"].format(where=_plain(repr(asked[3:].decode("utf-8", "replace")))))
                        self._send(ident, errno.EACCES)
                        return
                else:
                    address = self._file(tid, asked[2:].split(b"\0", 1)[0], keep)
                    if address is None:
                        self._send(ident, errno.EACCES)
                        return
            elif family in (_AF_INET, _AF_INET6) and kind in (_AF_INET, _AF_INET6) and not self.own_net:
                self._tell(SAID["address"].format(where=_numbers(asked)))
                self._send(ident, errno.EACCES)
                return
            # A request that a signal interrupted is made again by the program, or by the kernel for it, and the
            # connection the doorman made the first time is then there already. The doorman cannot tell whether
            # its first answer was taken (where the kernel does not hold signals back, `KILLABLE`, an answer
            # that arrived together with the signal is dropped though it was accepted): so a request for the
            # same socket and the same address that finds the connection made, or under way, is answered as the
            # first one was. A program that asks twice on purpose reads "done" where the kernel says "is
            # connected already", which every program that asks twice takes for the same. The requests for one
            # socket are worked out one after the other (its gate), so the second finds what the first left.
            status = os.fstat(mine)
            which = (status.st_dev, status.st_ino)
            with self.lock:
                gate = self.gates.setdefault(which, [threading.Lock(), 0])
                gate[1] += 1
            try:
                with gate[0]:
                    buffer = ctypes.create_string_buffer(address, max(1, len(address)))
                    done = self.libc.connect(mine, buffer, len(address))
                    number = ctypes.get_errno() if done != 0 else 0
                    with self.lock:
                        before = self.made.get(which)
                        if before is not None and before[0] == asked:
                            if number == errno.EISCONN and before[1] == 0:
                                number = 0
                            elif number == errno.EALREADY and before[1] == errno.EINPROGRESS:
                                number = errno.EINPROGRESS
                        if number in (0, errno.EINPROGRESS):
                            if len(self.made) >= MOST_REMEMBERED:
                                self.made.clear()
                            self.made[which] = (asked, number)
                        elif before is not None:
                            del self.made[which]
                    self._send(ident, number)
            finally:
                with self.lock:
                    gate[1] -= 1
                    if not gate[1]:
                        self.gates.pop(which, None)
        except OSError as e:
            self._send(ident, e.errno or errno.EPERM)
        finally:
            for one in keep:
                try:
                    os.close(one)
                except OSError:
                    pass

    def _file(self, tid: int, path: bytes, keep: list) -> bytes | None:
        """The address the doorman connects to for a socket file a program named, or None when the file is not
        the run's own (said, unless it is the C library's cache). The name is followed the way the kernel would
        follow it for that program, links and all, and what it leads to is held. That is the run's own only when
        the same file is found again from one of the run's folders, held open since before the command started,
        going down name by name through no link and no `..`: a link, a second name (hard link) or a folder
        attached in a namespace of the tests' making then leads nowhere but to what the folder really holds. The
        connection is made to the file that is held, not to a name, which could be changed in between."""
        top = os.open(f"/proc/{tid}/{'root' if path.startswith(b'/') else 'cwd'}",
                      _O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        keep.append(top)
        named = os.open(path.lstrip(b"/") or b".", _O_PATH | os.O_CLOEXEC, dir_fd=top)
        keep.append(named)
        it = os.fstat(named)
        if not stat.S_ISSOCK(it.st_mode):            # nothing listens at a file that is no socket
            raise OSError(errno.ECONNREFUSED, os.strerror(errno.ECONNREFUSED))
        real = os.readlink(f"/proc/self/fd/{named}")
        for root, folder in self.roots:
            if not real.startswith(root + "/"):
                continue
            at, opened, found = folder, [], None
            try:
                parts = real[len(root) + 1:].split("/")
                for i, part in enumerate(parts):
                    if part in ("", ".", ".."):
                        raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
                    at = os.open(part, _O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
                                 | (os.O_DIRECTORY if i < len(parts) - 1 else 0), dir_fd=at)
                    opened.append(at)
                found = os.fstat(at)
            except OSError:
                found = None
            finally:
                for one in opened:
                    os.close(one)
            if found is None or not os.path.samestat(found, it):
                continue
            if it.st_nlink != 1:
                self._tell(SAID["second"].format(where=_plain(real)))
                return None
            return _AF_UNIX.to_bytes(2, sys.byteorder) + f"/proc/self/fd/{named}".encode("ascii") + b"\0"
        if real not in _NOT_SAID:
            self._tell(SAID["file"].format(where=_plain(real)))
        return None


def _below(libc) -> int:
    """Put this process, the command's side of the doorman's fork, one Landlock domain below the doorman's, whose
    one rule is "no signal to a process outside" (ABI 6). The doorman is the command's own user and its parent, so
    without this the tests could end it (nothing is let through then, and the run ends) or stop it (every
    connection then waits for the wall clock); before there was a doorman a test could send its parent, the
    launcher, no signal where the kernel can refuse one, and that stays so. The doorman, one domain above, may
    still look into the programs it answers for. 0 when it stands, else the system's error number (38: this
    kernel's Landlock has no such rule; 7: sixteen rule sets are on this process already)."""
    if libc.syscall(444, None, 0, 1) < 6:
        return errno.ENOSYS
    attr = (ctypes.c_uint64 * 3)(0, 0, _SCOPE_SIGNAL)
    rfd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0:
        return ctypes.get_errno() or errno.EPERM
    try:
        return 0 if libc.syscall(446, rfd, 0) == 0 else (ctypes.get_errno() or errno.EPERM)
    finally:
        os.close(rfd)


def _doorman(policy: dict, cmd: list[str] | None, walls: dict) -> None:
    """Put a doorman between the command and the kernel (this module's opening text, `sockets`), in the process
    that was about to become the command: that process stays as the doorman, and a child of it, under the
    filter, becomes the command (`cmd` None: nothing is started; for `try_own_sockets`). Does not come back when
    the doorman stands: it ends when the command does, and the way the command did. When no doorman can be made
    it says so and comes back, or, where the policy says `must`, raises `_Refused` and nothing is started."""
    import socket
    import struct
    import threading
    must = bool(policy.get("must"))

    def failed(number: int) -> None:
        _say("sandbox: the doorman that makes the connections of the tests' programs could not be made")
        if must:
            _refuse("own-sockets", number)
        _say(f"sandbox: carrying on without it ({REASONS['own-sockets']})")

    table = _CALLS.get(os.uname().machine) if sys.byteorder == "little" else None
    if table is None or not hasattr(os, "pidfd_open"):
        return failed(errno.ENOSYS)
    libc = ctypes.CDLL(None, use_errno=True)
    me = os.getpid()
    knock = _AF_UNIX.to_bytes(2, sys.byteorder) + b"\0" + os.urandom(16)
    try:
        program = _filter(table, bool(walls.get("net")), bool(walls.get("ipc")))
        mine, theirs = socket.socketpair()
        # The tests cannot look into the doorman or take what it holds (the kernel's handle): a process that is
        # closed this way is nobody's to trace but an administrator's. What the tests' programs leave behind
        # when their parent ends is handed to the doorman, so it stays something the doorman may look into where
        # a system lets a program look only into what it started (Yama).
        libc.prctl(4, 0, 0, 0, 0)                    # PR_SET_DUMPABLE: off
        libc.prctl(36, 1, 0, 0, 0)                   # PR_SET_CHILD_SUBREAPER
        sys.stdout.flush()
        sys.stderr.flush()
        kid = os.fork()
    except (OSError, ValueError) as e:
        return failed(getattr(e, "errno", None) or errno.EPERM)
    if kid == 0:
        code = 127
        try:
            mine.close()
            os.setpgid(0, 0)                         # a signal a test sends "to its group" does not reach the doorman
            libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)       # no doorman, no command
            if os.getppid() != me:
                os._exit(code)
            libc.prctl(4, 1, 0, 0, 0)                # open to the doorman's look, as a started program is
            try:
                if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS: what lets a user set a filter
                    raise OSError(ctypes.get_errno(), "no new privileges")
                listener = _listen(table, program)
                apart = _below(libc)                 # the doorman stands: from here no signal of this side reaches it
                socket.send_fds(theirs, [b"L"], [listener])
                os.close(listener)
                if theirs.recv(16) != b"G":
                    os._exit(code)                   # the doorman's side gave up, and has said why
                _knock(libc, knock)
                theirs.sendall(b"K" + struct.pack("=i", apart))
            except OSError as e:
                theirs.sendall(b"E" + struct.pack("=i", e.errno or errno.EPERM))
                os._exit(code)
            theirs.close()
            if cmd is None:
                code = 0
            else:
                os.execvp(cmd[0], cmd)
        except BaseException as e:  # noqa: BLE001 - whatever it is, this side of the fork must end here
            _say(f"sandbox: could not start {cmd[0] if cmd else 'behind the doorman'}: {e}")
        finally:
            os._exit(code)
    theirs.close()
    faults = {signal.SIGCHLD, signal.SIGSEGV, signal.SIGBUS, signal.SIGFPE, signal.SIGILL, signal.SIGABRT,
              signal.SIGSYS, signal.SIGTRAP, signal.SIGXCPU}
    for number in range(1, signal.NSIG):             # a signal the tests send their parent does not end the doorman
        if number not in faults:
            try:
                signal.signal(number, signal.SIG_IGN)
            except (OSError, ValueError, RuntimeError):
                pass
    number, apart = errno.EPROTO, 0
    try:
        mine.settimeout(30)
        word, fds, _flags, _from = socket.recv_fds(mine, 16, 1)
        if word[:1] == b"L" and fds:
            threading.Thread(target=_Doorman(fds[0], table, walls, knock).serve, daemon=True).start()
            mine.sendall(b"G")
            word = mine.recv(16)
            if word[:1] == b"K" and len(word) >= 5:
                number, apart = 0, struct.unpack("=i", word[1:5])[0]
        if word[:1] == b"E" and len(word) >= 5:
            number = struct.unpack("=i", word[1:5])[0] or errno.EPERM
    except (OSError, ValueError, RuntimeError) as e:
        number = getattr(e, "errno", None) or errno.ETIMEDOUT
    finally:
        mine.close()
    if number:
        try:
            os.kill(kid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(kid, 0)
        except OSError:
            pass
        for one in range(1, signal.NSIG):            # what the command is started with, should it be started here
            if one not in faults:
                try:
                    signal.signal(one, signal.SIG_DFL)
                except (OSError, ValueError, RuntimeError):
                    pass
        libc.prctl(4, 1, 0, 0, 0)
        return failed(number)
    if cmd is not None:
        _say("sandbox: a doorman makes every connection of the tests' programs for them (a socket file outside "
             "the tests' own folders is not reached, by Python or by any other program)")
        if apart:
            _say("sandbox: on this system a signal of the tests can reach their doorman "
                 f"({'this kernel refuses none' if apart == errno.ENOSYS else f'error {apart}'}): tests that end it "
                 "reach nothing afterwards and are ended with it")
    status = None
    while True:
        try:
            got, ended = os.waitpid(-1, 0)           # also collects what was handed to this process
        except ChildProcessError:
            break
        if got == kid:
            status = ended
            break
    if status is None:
        os._exit(127)
    if os.WIFSIGNALED(status):                       # end the way the command did, so the launcher reads the same
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


def try_own_sockets(nobody: bool) -> int:
    """For a throwaway process (`lantern.sandbox.own_sockets` starts one): can a run's command be put behind a
    doorman on this system? Does what `_doorman` does for a command, as the user the command runs as, up to the
    point where the command would be started. The process ends with 0 when it can (this function does not come
    back then); otherwise the error number of the step that was refused: 16 where a sandbox around this one has a
    doorman already (the kernel hears one per process), 38 where the kernel or this kind of processor has none."""
    if not sys.platform.startswith("linux"):
        return errno.ENOSYS
    try:
        if nobody and os.geteuid() == 0:
            _become_nobody()
        _doorman({"must": True}, None, {})
    except _Refused as e:
        return e.number or errno.EPERM
    except OSError as e:
        return e.errno or errno.EPERM
    return errno.EPERM


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


def _in_use(me: int, limit: int, apart: int | None = None) -> int:
    """Bytes of memory in use by every process beneath `me`, counted together. Under `limit` the answer is the
    quick count (never too low); over it, each process's own share is asked, and that sum is the answer. `apart`:
    one process that is not counted, the run's doorman, which is Lantern's and not the tests'."""
    try:
        pids = [pid for pid in _beneath(me) if pid != apart]
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
    door, mine, theirs = _door(policy), None, None
    if door:
        import socket
        mine, theirs = socket.socketpair()
    sys.stdout.flush()
    sys.stderr.flush()
    child = os.fork()
    if child == 0:
        code = 127
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, before)   # the command hears what any program hears
            os.setpgid(0, 0)            # its own process group: a signal a test sends "to its group" stays in it
            if mine is not None:
                mine.close()
            walls = _restrict(policy, theirs)
            libc.prctl(1, int(signal.SIGKILL), 0, 0, 0)   # after the change of user, which clears it
            if os.getppid() != me:
                os._exit(code)
            if policy.get("sockets"):
                _doorman(policy, cmd, walls)    # comes back only when no doorman was made and none has to be
            os.execvp(cmd[0], cmd)
        except _Refused:
            code = UNAVAILABLE
        except BaseException as e:  # noqa: BLE001 - whatever it is, this side of the fork must end here
            _say(f"sandbox: could not start {cmd[0]}: {e}")
        finally:
            os._exit(code)
    if door:
        # The fetching step's doorkeeper: the command's side made a listener in its own network and hands it over;
        # this side, which is outside that network, answers it. Nothing is handed over when the command's side
        # was refused before it got there, and that side has then said why.
        theirs.close()
        try:
            mine.settimeout(30)
            _, fds, _, _ = socket.recv_fds(mine, 16, 1)
            if fds:
                from . import _stores
                _stores.Door(socket.socket(fileno=fds[0]), door["allowed"], door.get("through"), _say).start()
        except (OSError, ValueError):
            pass
        finally:
            mine.close()
    status, memory, over, look = None, _memory(policy), 0, 0.0
    # With `sockets` and `must` the command runs only beneath a doorman, and the doorman is this process's child.
    apart = child if policy.get("sockets") and policy.get("must") else None
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
                    used = _in_use(me, memory, apart)
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
