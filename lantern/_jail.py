"""POSIX launcher for the test sandbox (`lantern.sandbox`): apply limits, then exec the test command.

    python -c "...main(argv)" POLICY_JSON -- command args...

POLICY_JSON: {"writable": [dirs], "nobody": bool, "python": bool, "net": bool}
* resource limits: CPU 600 s, files up to 512 MB, no core dumps, and 2 GB of address space for Python tests
  (Node and the JVM reserve far more address space than they use, so they get the wall clock and CPU limit only);
* Linux Landlock (when the kernel has it): writes only beneath `writable`, and (ABI 4+) no TCP connect or bind;
* `nobody`: drop to uid/gid 65534 when started as root (root ignores file modes);
* no_new_privs, so nothing it runs can gain privileges.
Standard library only; it must run before anything from the project is imported.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys

# Landlock filesystem rights that change things (reads are not restricted)
_FS_WRITE = {1: (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)}
_FS_WRITE[2] = _FS_WRITE[1] | (1 << 13)          # REFER
_FS_WRITE[3] = _FS_WRITE[2] | (1 << 14)          # TRUNCATE
_NET_TCP = (1 << 0) | (1 << 1)                   # BIND_TCP | CONNECT_TCP (ABI 4)


def _landlock(writable: list[str], net: bool) -> str:
    if not sys.platform.startswith("linux"):
        return "not Linux"
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        return "kernel has no Landlock"
    fs = _FS_WRITE[min(abi, 3)]
    if abi >= 4 and net:
        attr = (ctypes.c_uint64 * 2)(fs, _NET_TCP)
    else:
        attr = (ctypes.c_uint64 * 1)(fs)
    rfd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0:
        return f"ruleset error {ctypes.get_errno()}"

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
    O_PATH = 0o10000000
    allowed = [(p, fs) for p in writable] + [("/dev", 1 << 1)]   # /dev/null, /dev/tty: write to existing files only
    for path, rights in allowed:
        try:
            fd = os.open(path, O_PATH | os.O_CLOEXEC)
        except OSError:
            continue
        rule = Beneath(rights & fs, fd)
        libc.syscall(445, rfd, 1, ctypes.byref(rule), 0)   # LANDLOCK_RULE_PATH_BENEATH
        os.close(fd)
    libc.prctl(38, 1, 0, 0, 0)                               # PR_SET_NO_NEW_PRIVS
    if libc.syscall(446, rfd, 0) != 0:
        return f"restrict error {ctypes.get_errno()}"
    os.close(rfd)
    return f"on (ABI {abi}{', no TCP' if abi >= 4 and net else ''})"


def main(argv: list[str]) -> None:
    policy = json.loads(argv[0])
    cmd = argv[argv.index("--") + 1:]
    import resource
    for lim, val in ((resource.RLIMIT_CPU, 600), (resource.RLIMIT_FSIZE, 512 << 20), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(lim, (val, val))
        except (ValueError, OSError):
            pass
    if policy.get("python") and hasattr(resource, "RLIMIT_AS"):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
        except (ValueError, OSError):
            pass
    if policy.get("nobody") and os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    state = _landlock(policy.get("writable", []), bool(policy.get("net")))
    if not state.startswith("on"):
        try:
            libc = ctypes.CDLL(None)
            libc.prctl(38, 1, 0, 0, 0)
        except (OSError, AttributeError):
            pass
    print(f"sandbox: Landlock {state}", file=sys.stderr, flush=True)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main(sys.argv[1:])
