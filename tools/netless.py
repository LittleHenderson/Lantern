"""Run a command with no network at all:  python tools/netless.py [--watch FILE] -- COMMAND [ARGUMENT...]

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

Result: the command's own; 2 when this was called wrongly; 3 when this system cannot do it.
"""
from __future__ import annotations

import collections
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "netguard"))
import lantern_netguard as netguard  # noqa: E402

USAGE = "usage: python tools/netless.py [--watch FILE] -- COMMAND [ARGUMENT...]\n"
CLONE_NEWUSER, CLONE_NEWNET = 0x10000000, 0x40000000
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
WITH_SUDO = 'sudo env "PATH=$PATH" "HOME=$HOME" python tools/netless.py -- COMMAND'


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
SERVICES = ("docker.sock", "containerd", "podman", "nscd", "systemd/resolve", "dbus")   # they have their own way out


def summarize(trace_path: str, forwarder_ports=()) -> dict:
    """What a `strace -f -e trace=TRACED` record says about the network: every address outside this computer that a
    program connected or sent to (a name lookup counts: port 53 on any address), with the program."""
    program: dict = {}
    waiting: dict = {}                    # pid -> (call, text so far) for a call another process interrupted
    outside: dict = collections.OrderedDict()
    services: collections.Counter = collections.Counter()
    local = checks = 0

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

    with open(trace_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            m = _LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            pid, rest = m.group(1), m.group(2)
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
            "services_on_this_computer_with_their_own_way_out": dict(services)}


def watched(command: list, out_path: str, forwarder_ports) -> int:
    strace = shutil.which("strace")
    if not strace:
        raise Cannot("--watch needs the strace program (Debian/Ubuntu: apt-get install strace)")
    folder = tempfile.mkdtemp(prefix="netless-")       # the raw record holds the first bytes of what programs sent each
    raw = os.path.join(folder, "trace")                # other on this computer: private, and removed below
    try:
        child = subprocess.Popen([strace, "-f", "-qq", "--seccomp-bpf", "-s", "64", "-o", raw, "-e", f"trace={TRACED}",
                                  "--", *command])
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda number, _frame: child.send_signal(number))
        code = child.wait()
        summary = summarize(raw, forwarder_ports)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    summary["command"], summary["result"] = command[:8], code
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
    outside = summary["outside"]
    sys.stderr.write(f"netless: {summary['connections_on_this_computer']} connections stayed on this computer, "
                     f"{sum(e['count'] for e in outside)} attempts to reach outside it (none can succeed here), "
                     f"{summary['checks_that_there_is_no_route']} checks that there is no route\n")
    for e in outside:
        sys.stderr.write(f"  {e['count']}x {e['kind']} {e['address']}:{e['port']} ({e['result'] or '?'})   by: {e['program']}\n")
    return code if code or not outside else 4


def main(argv: list) -> int:
    watch = None
    if len(argv) >= 2 and argv[0] == "--watch":
        watch, argv = argv[1], argv[2:]
    if len(argv) < 2 or argv[0] != "--":
        sys.stderr.write(USAGE)
        return 2
    command = argv[1:]
    if not sys.platform.startswith("linux"):
        sys.stderr.write("netless: only Linux can give a command a network of its own\n")
        return 3
    forwarder_ports = {a[2] for a in netguard.proxy_variables().values() if netguard.is_local(a[1])}
    try:
        own_network()
        back_to_the_caller()
        if watch:
            return watched(command, watch, forwarder_ports)
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
