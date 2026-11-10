"""POSIX launcher for the test sandbox (`lantern.sandbox`) and the cloud worker's jailed steps: apply the limits,
run the command, and leave nothing it started behind.

    python -c "...main(argv)" POLICY_JSON -- command args...

POLICY_JSON: {"writable": [dirs], "nobody": bool, "python": bool, "net": bool, "must": bool, "parent": pid}
* resource limits: CPU 600 s, files up to 512 MB, no core dumps, and 2 GB of address space for Python tests
  (Node and the JVM reserve far more address space than they use, so they get the wall clock and CPU limit only);
* Linux Landlock (when the kernel has it): writes only beneath `writable`, (ABI 4+) no TCP connect or bind, and
  (ABI 6+) no signal to a process outside the sandbox;
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
import json
import os
import signal
import sys
import time

UNAVAILABLE = 119          # the launcher's own result when it did not start the command
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
}
ASK = 6.0                  # seconds `lantern.sandbox` waits after asking (SIGTERM) before it kills the process group
_SWEEP = 3.0               # seconds the supervisor spends ending what the command started

# Landlock filesystem rights that change things (reads are not restricted)
_FS_WRITE = {1: (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)}
_FS_WRITE[2] = _FS_WRITE[1] | (1 << 13)          # REFER
_FS_WRITE[3] = _FS_WRITE[2] | (1 << 14)          # TRUNCATE
_NET_TCP = (1 << 0) | (1 << 1)                   # BIND_TCP | CONNECT_TCP (ABI 4)
_SCOPE_SIGNAL = 1 << 1                           # LANDLOCK_SCOPE_SIGNAL (ABI 6): no signal to a process outside


class _Refused(Exception):
    """A restriction the sandbox counts on could not be put in place; the reason has been printed."""


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _refuse(word: str, number: int | None = None) -> None:
    _say(f"{MARK} {word}" + (f" {number}" if number else ""))
    raise _Refused(word)


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
        attr = (ctypes.c_uint64 * 3)(fs, _NET_TCP if net else 0, _SCOPE_SIGNAL)
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
    return f"on (ABI {abi}{', no TCP' if abi >= 4 and net else ''}{', no signals outside' if abi >= 6 else ''})", None, 0


def _restrict(policy: dict) -> None:
    """Limits, the unprivileged user, Landlock and no new privileges, in the process that is about to become the
    command. Raises `_Refused`, the reason printed, when the command must not be started."""
    must = bool(policy.get("must"))
    import resource
    limits = [("CPU", 600), ("FSIZE", 512 << 20), ("CORE", 0)] + ([("AS", 2 << 30)] if policy.get("python") else [])
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
    if policy.get("nobody") and os.geteuid() == 0:
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        except OSError as e:
            _refuse("user", e.errno)        # never as root what was to run as nobody
        if os.getuid() != 65534 or os.geteuid() != 65534 or os.getgid() != 65534:
            _refuse("user")
    state, failed, number = _landlock(policy.get("writable", []), bool(policy.get("net")))
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
    status = None
    while True:
        try:
            got, st = os.waitpid(-1, os.WNOHANG)         # also collects orphans handed to this process
        except ChildProcessError:
            break
        if got == child:
            status = st
            break
        if got == 0:                                     # nothing has ended: wait for news (the second is a net)
            news = signal.sigtimedwait(watched, 1.0)
            if news is not None and news.si_signo != signal.SIGCHLD:
                break                                    # asked to stop, or the starting program ended
    left = _end_all(me)
    if left:
        _say(f"sandbox: {left} process(es) the command started could not be ended")
    sys.stdout.flush()
    sys.stderr.flush()
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
