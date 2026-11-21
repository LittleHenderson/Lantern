"""A Windows AppContainer of a run's own (`lantern.wincontainer`) and a whole Python of the run's own
(`sandbox._whole_python`): the wall Windows itself keeps around every program of a project's tests (a firm pass or
fail, stage 4, step 5, 2026-11-20).

On Windows Lantern's guard holds Python code only: a program the tests start that is not Python (Node, the system's
own download program, a Python started without the guard) can reach the network and the person's files. The one
wall Windows gives a program without the administrator is an AppContainer: no network where it has no capability,
and only the folders whose rights name it. What such a wall does to an honest test is not written down anywhere
this could rely on (a test's own server, a server in a second program of the same tests, a pool of processes,
the event loop, which Python builds from a listener on this computer), so it is tried on Windows itself first,
as the event loop's two kinds were in step 2. The facts are written out in the log where the job prints them.

The tests of how this module calls Windows run on every system, with a stand-in for Windows' libraries."""
import ctypes
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from lantern import _jail, sandbox, wincontainer

WINDOWS = sys.platform == "win32"
ONLY_WINDOWS = pytest.mark.skipif(not WINDOWS, reason="an AppContainer is Windows' own")


# ---------------------------------------------------------------------------- a stand-in for Windows' libraries
SID_TEXT = "S-1-15-2-1111111111-2222222222-3333333333-4444444444-5555555555-6666666666-7777777777"


class Calls:
    """userenv, advapi32 and kernel32 as `lantern.wincontainer` calls them, writing down every call. `fail` names
    a call that answers as a refusal (with `error` as its number)."""

    def __init__(self, fail: str = "", error: int = 5, exit_code: int = 0, std=(0x11, 0x12, 0x12),
                 inheritable=(0x12,), no_sid: bool = False):
        self.fail, self.error, self.exit_code, self.no_sid = fail, error, exit_code, no_sid
        self.std = dict(zip(wincontainer.STD_HANDLES, std))
        self.inheritable = set(inheritable)
        self.log: list[tuple] = []
        self._kept: list = []

    def _say(self, *what):
        self.log.append(what)

    def calls(self, name: str) -> list[tuple]:
        return [c for c in self.log if c[0] == name]

    def last_error(self) -> int:
        return self.error

    # userenv
    def CreateAppContainerProfile(self, name, display, description, capabilities, count, sid):
        self._say("CreateAppContainerProfile", name, display, description, capabilities, count)
        if self.fail == "CreateAppContainerProfile":
            return -2147024713          # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), as Windows hands it back
        if not self.no_sid:
            sid._obj.value = 0x5100
        return 0

    def DeleteAppContainerProfile(self, name):
        self._say("DeleteAppContainerProfile", name)
        return -2147024891 if self.fail == "DeleteAppContainerProfile" else 0

    # advapi32
    def FreeSid(self, sid):
        self._say("FreeSid", sid.value)

    def ConvertSidToStringSidW(self, sid, out):
        self._say("ConvertSidToStringSidW", sid.value)
        if self.fail == "ConvertSidToStringSidW":
            return 0
        text = ctypes.create_unicode_buffer(SID_TEXT)
        self._kept.append(text)
        out._obj.value = ctypes.addressof(text)
        return 1

    def ConvertStringSidToSidW(self, text, sid):
        self._say("ConvertStringSidToSidW", text)
        if self.fail == "ConvertStringSidToSidW":
            return 0
        sid._obj.value = 0x5200
        return 1

    def GetNamedSecurityInfoW(self, where, kind, which, owner, group, dacl, sacl, described):
        self._say("GetNamedSecurityInfoW", where, kind, which)
        if self.fail == "GetNamedSecurityInfoW":
            return self.error
        dacl._obj.value, described._obj.value = 0x6100, 0x6200
        return 0

    def SetEntriesInAclW(self, count, entries, old, new):
        e = entries._obj
        self._say("SetEntriesInAclW", count, e.grfAccessPermissions, e.grfAccessMode, e.grfInheritance,
                  e.Trustee.TrusteeForm, e.Trustee.ptstrName, old.value)
        if self.fail == "SetEntriesInAclW":
            return self.error
        new._obj.value = 0x6300
        return 0

    def SetNamedSecurityInfoW(self, where, kind, which, owner, group, dacl, sacl):
        self._say("SetNamedSecurityInfoW", where, kind, which, dacl.value)
        return self.error if self.fail == "SetNamedSecurityInfoW" else 0

    # kernel32
    def LocalFree(self, what):
        self._say("LocalFree", what.value if isinstance(what, ctypes.c_void_p) else what)

    def InitializeProcThreadAttributeList(self, room, count, flags, size):
        self._say("InitializeProcThreadAttributeList", room is not None, count)
        if room is None:
            size._obj.value = 64
            self.error = wincontainer.INSUFFICIENT_BUFFER
            return 0
        return 0 if self.fail == "InitializeProcThreadAttributeList" else 1

    def UpdateProcThreadAttribute(self, room, flags, attribute, value, size, previous, returned):
        if attribute == wincontainer.ATTRIBUTE_SECURITY_CAPABILITIES:
            caps = value._obj
            self._say("UpdateProcThreadAttribute", "capabilities", caps.AppContainerSid, caps.Capabilities,
                      caps.CapabilityCount, size)
        else:
            n = size // ctypes.sizeof(ctypes.c_void_p)
            self._say("UpdateProcThreadAttribute", "handles", [value[i] for i in range(n)])
        return 0 if self.fail == "UpdateProcThreadAttribute" else 1

    def DeleteProcThreadAttributeList(self, room):
        self._say("DeleteProcThreadAttributeList")

    def CreateProcessW(self, program, line, process, thread, inherit, flags, environment, folder, startup, info):
        si = startup._obj
        self._say("CreateProcessW", program, line.value, inherit, flags, environment, folder, si.StartupInfo.cb,
                  si.StartupInfo.dwFlags, (si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput,
                                           si.StartupInfo.hStdError), bool(si.lpAttributeList))
        if self.fail == "CreateProcessW":
            return 0
        info._obj.hProcess, info._obj.hThread = 0x7100, 0x7200
        return 1

    def GetStdHandle(self, which):
        return self.std.get(which)

    def GetHandleInformation(self, handle, flags):
        flags._obj.value = wincontainer.HANDLE_FLAG_INHERIT if handle in self.inheritable else 0
        return 1

    def SetHandleInformation(self, handle, mask, flags):
        self._say("SetHandleInformation", handle, mask, flags)
        return 1

    def WaitForSingleObject(self, handle, ms):
        self._say("WaitForSingleObject", handle, ms)
        return wincontainer.WAIT_FAILED if self.fail == "WaitForSingleObject" else 0

    def GetExitCodeProcess(self, handle, code):
        code._obj.value = self.exit_code
        return 1

    def CloseHandle(self, handle):
        self._say("CloseHandle", handle)
        return 1


def test_a_container_is_made_with_no_capability_and_its_profile_is_deleted_once():
    api = Calls()
    box = wincontainer.Container(api=api, name="Lantern.Tests.42.0123456789abcdef")
    assert box.text == SID_TEXT
    made = api.calls("CreateAppContainerProfile")
    assert made == [("CreateAppContainerProfile", "Lantern.Tests.42.0123456789abcdef",
                     "Lantern.Tests.42.0123456789abcdef", wincontainer.DESCRIPTION, None, 0)]
    # the text Windows wrote the SID in is given back
    assert ("LocalFree", api._kept and ctypes.addressof(api._kept[0])) in api.log
    box.close()
    box.close()
    assert api.calls("FreeSid") == [("FreeSid", 0x5100)]
    assert api.calls("DeleteAppContainerProfile") == [("DeleteAppContainerProfile", "Lantern.Tests.42.0123456789abcdef")]


def test_a_profile_windows_refuses_is_said_with_its_number_and_nothing_is_deleted():
    api = Calls(fail="CreateAppContainerProfile")
    with pytest.raises(wincontainer.ContainerError) as e:
        wincontainer.Container(api=api)
    assert e.value.call == "CreateAppContainerProfile" and e.value.code == 0x800700B7
    assert not api.calls("DeleteAppContainerProfile") and not api.calls("FreeSid")


@pytest.mark.parametrize("how", ["no-sid", "no-text"])
def test_a_profile_made_without_a_sid_windows_can_write_out_is_deleted_again(how):
    api = Calls(no_sid=how == "no-sid", fail="ConvertSidToStringSidW" if how == "no-text" else "", error=8)
    with pytest.raises(wincontainer.ContainerError) as e:
        wincontainer.Container(api=api, name="Lantern.Tests.1.00")
    assert e.value.call in ("CreateAppContainerProfile", "ConvertSidToStringSidW")
    assert api.calls("DeleteAppContainerProfile") == [("DeleteAppContainerProfile", "Lantern.Tests.1.00")]
    assert api.calls("FreeSid") == ([] if how == "no-sid" else [("FreeSid", 0x5100)])


def test_a_profile_that_stays_is_said():
    api = Calls(fail="DeleteAppContainerProfile")
    box = wincontainer.Container(api=api)
    with pytest.raises(wincontainer.ContainerError) as e:
        box.close()
    assert e.value.call == "DeleteAppContainerProfile" and e.value.code == 0x80070005
    box.close()       # once: the profile is not asked for again
    assert len(api.calls("DeleteAppContainerProfile")) == 1


@pytest.mark.parametrize("change", [False, True])
def test_a_grant_adds_one_entry_for_the_container_that_a_folder_hands_on(change, tmp_path):
    api = Calls()
    box = wincontainer.Container(api=api)
    box.grant(tmp_path, change=change)
    assert api.calls("GetNamedSecurityInfoW") == [("GetNamedSecurityInfoW", str(tmp_path), wincontainer.SE_FILE_OBJECT,
                                                   wincontainer.DACL_SECURITY_INFORMATION)]
    mask = wincontainer.CHANGE if change else wincontainer.READ_AND_RUN
    assert api.calls("SetEntriesInAclW") == [("SetEntriesInAclW", 1, mask, wincontainer.GRANT_ACCESS,
                                              wincontainer.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                                              wincontainer.TRUSTEE_IS_SID, 0x5100, 0x6100)]
    assert api.calls("SetNamedSecurityInfoW") == [("SetNamedSecurityInfoW", str(tmp_path), wincontainer.SE_FILE_OBJECT,
                                                   wincontainer.DACL_SECURITY_INFORMATION, 0x6300)]
    freed = [c[1] for c in api.calls("LocalFree")]
    assert 0x6300 in freed and 0x6200 in freed and 0x6100 not in freed     # the DACL lies inside what was described
    # Neither mask lets the container change a file's rights or its owner, or take it over
    for right in (0x00040000, 0x00080000, 0x10000000):       # WRITE_DAC, WRITE_OWNER, GENERIC_ALL
        assert not mask & right


@pytest.mark.parametrize("call", ["GetNamedSecurityInfoW", "SetEntriesInAclW", "SetNamedSecurityInfoW"])
def test_a_grant_windows_refuses_is_said_and_frees_what_it_was_given(call, tmp_path):
    api = Calls(fail=call, error=1307)
    box = wincontainer.Container(api=api)
    with pytest.raises(wincontainer.ContainerError) as e:
        box.grant(tmp_path)
    assert e.value.call == call and e.value.code == 1307
    freed = [c[1] for c in api.calls("LocalFree")]
    if call != "GetNamedSecurityInfoW":
        assert 0x6200 in freed
    if call == "SetNamedSecurityInfoW":
        assert 0x6300 in freed
    if call == "SetEntriesInAclW":
        assert not api.calls("SetNamedSecurityInfoW")


def test_the_command_starts_in_the_container_with_its_standard_handles_only_and_its_result_comes_back():
    api = Calls(exit_code=3)
    cmd = ["C:\\run\\py\\python.exe", "-m", "pytest", "a b"]
    assert wincontainer.start(SID_TEXT, cmd, api=api) == 3
    assert api.calls("ConvertStringSidToSidW") == [("ConvertStringSidToSidW", SID_TEXT)]
    assert api.calls("InitializeProcThreadAttributeList") == [("InitializeProcThreadAttributeList", False, 2),
                                                              ("InitializeProcThreadAttributeList", True, 2)]
    assert api.calls("UpdateProcThreadAttribute") == [
        ("UpdateProcThreadAttribute", "capabilities", 0x5200, None, 0, ctypes.sizeof(wincontainer.SecurityCapabilities)),
        ("UpdateProcThreadAttribute", "handles", [0x11, 0x12])]      # the output and the errors are one pipe: once
    # a handle that was not to be inherited is made so; one that was is left as it is
    assert api.calls("SetHandleInformation") == [("SetHandleInformation", 0x11, wincontainer.HANDLE_FLAG_INHERIT,
                                                  wincontainer.HANDLE_FLAG_INHERIT)]
    (_, program, line, inherit, flags, environment, folder, cb, how, std, listed), = api.calls("CreateProcessW")
    assert program is None and line == subprocess.list2cmdline(cmd) and inherit is True
    assert flags == wincontainer.EXTENDED_STARTUPINFO_PRESENT and environment is None and folder is None
    assert cb == ctypes.sizeof(wincontainer.StartupInfoEx) and how == wincontainer.STARTF_USESTDHANDLES
    assert std == (0x11, 0x12, 0x12) and listed
    assert api.calls("WaitForSingleObject") == [("WaitForSingleObject", 0x7100, wincontainer.INFINITE)]
    assert sorted(c[1] for c in api.calls("CloseHandle")) == [0x7100, 0x7200]
    assert len(api.calls("DeleteProcThreadAttributeList")) == 1
    assert ("LocalFree", 0x5200) in api.log


@pytest.mark.parametrize("call", ["ConvertStringSidToSidW", "InitializeProcThreadAttributeList",
                                  "UpdateProcThreadAttribute", "CreateProcessW", "WaitForSingleObject"])
def test_a_command_windows_will_not_start_or_wait_for_is_said_and_everything_is_given_back(call):
    api = Calls(fail=call, error=5)
    with pytest.raises(wincontainer.ContainerError) as e:
        wincontainer.start(SID_TEXT, ["x.exe"], api=api)
    assert e.value.call == call
    made = call not in ("ConvertStringSidToSidW", "InitializeProcThreadAttributeList")
    assert len(api.calls("DeleteProcThreadAttributeList")) == (1 if made else 0)
    assert ("LocalFree", 0x5200) in api.log or call == "ConvertStringSidToSidW"
    started = call == "WaitForSingleObject"
    assert sorted(c[1] for c in api.calls("CloseHandle")) == ([0x7100, 0x7200] if started else [])


def test_the_launcher_says_why_in_lanterns_words_and_ends_as_the_sandbox_reads_it(monkeypatch, capsys):
    def refused(container, cmd, api=None):
        raise wincontainer.ContainerError("CreateProcessW", 5)
    monkeypatch.setattr(wincontainer, "start", refused)
    with pytest.raises(SystemExit) as e:
        wincontainer.main([SID_TEXT, "--", "python.exe"])
    said = capsys.readouterr().out
    assert e.value.code == _jail.UNAVAILABLE == wincontainer.UNAVAILABLE and wincontainer.MARK == _jail.MARK
    assert said.strip() == f"{_jail.MARK} container 5"
    assert sandbox._unavailable(e.value.code, said) == _jail.REASONS["container"] + " (error 5)"
    with pytest.raises(SystemExit) as e:
        wincontainer.main([SID_TEXT, "python.exe"])         # no `--`: nothing is started
    assert e.value.code == _jail.UNAVAILABLE and capsys.readouterr().out.strip() == f"{_jail.MARK} container 87"


@pytest.mark.parametrize("code", [0, 1, 0xC0000005, 0xFFFFFFFF])
def test_the_launcher_ends_with_the_tests_own_result(monkeypatch, code):
    monkeypatch.setattr(wincontainer, "start", lambda container, cmd, api=None: code)
    with pytest.raises(SystemExit) as e:
        wincontainer.main([SID_TEXT, "--", "python.exe"])
    assert e.value.code & 0xFFFFFFFF == code and -(1 << 31) <= e.value.code < (1 << 31)


def test_a_containers_name_is_lanterns_own_and_one_windows_takes():
    names = {wincontainer.name_for(4294967295) for _ in range(20)}
    assert len(names) == 20
    for name in names:
        assert re.fullmatch(r"Lantern\.Tests\.4294967295\.[0-9a-f]{16}", name) and len(name) <= 64


def test_the_whole_python_is_a_python_of_its_own_with_the_runs_libraries_only(tmp_path):
    if not WINDOWS:
        # elsewhere this computer's Python is not of the shape Python documents for Windows
        with pytest.raises(OSError):
            sandbox._whole_python(tmp_path / "py", [str(tmp_path)])
        return
    libs, app = tmp_path / "libs", tmp_path / "app"
    libs.mkdir()
    app.mkdir()
    (libs / "fetched_only.py").write_text("WHERE = 'fetched'\n", encoding="utf-8")
    exe = sandbox._whole_python(tmp_path / "py", [str(libs), str(app)])
    assert Path(exe) == tmp_path / "py" / "python.exe"
    assert not (tmp_path / "py" / "Lib" / "test").exists()
    assert [p.name for p in (tmp_path / "py" / "Lib" / "site-packages").iterdir()] == ["lantern.pth"]
    ask = ("import os, sys, fetched_only, importlib.util\nprint(os.path.realpath(sys.prefix))\n"
           "print(fetched_only.WHERE)\nprint(importlib.util.find_spec('pytest') is None)\n")
    # also as a Python told to pass its environment over, as a test's own second Python may be
    said = subprocess.run([exe, "-I", "-c", ask], capture_output=True, text=True, encoding="utf-8", timeout=120,
                          cwd=str(app), env={k: os.environ[k] for k in ("SYSTEMROOT", "PATH") if k in os.environ})
    assert said.returncode == 0, said.stderr
    assert said.stdout.splitlines() == [os.path.realpath(tmp_path / "py"), "fetched", "True"], said.stdout


# ---------------------------------------------------------------------------- what Windows does, tried on Windows
PROBE = r'''
import asyncio, ctypes, json, multiprocessing, os, socket, subprocess, sys, threading, time
from ctypes import wintypes


def attempt(fn):
    t = time.monotonic()
    try:
        return {"ok": True, "value": fn(), "s": round(time.monotonic() - t, 2)}
    except BaseException as e:
        return {"ok": False, "error": type(e).__name__, "number": getattr(e, "winerror", None) or getattr(e, "errno", None),
                "s": round(time.monotonic() - t, 2)}


def bounded(fn, seconds):
    box = {}
    th = threading.Thread(target=lambda: box.update(r=attempt(fn)), daemon=True)
    th.start()
    th.join(seconds)
    return box.get("r", {"ok": False, "error": "still waiting", "s": seconds})


def program(cmd, seconds=30, word=False, same=None, **kw):
    """A program's result only: `word`, the one word it printed (the probe's own programs print one), and `same`,
    whether the one line it printed names that folder. Nothing it read or printed besides is kept."""
    t = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=seconds, **kw)
        out = {"ok": r.returncode == 0, "rc": r.returncode, "s": round(time.monotonic() - t, 2)}
        if word:
            out["word"] = (r.stdout.split() or [""])[0][:20]
        if same is not None:
            out["same"] = os.path.normcase(os.path.realpath(r.stdout.strip() or "?")) == same
        return out
    except BaseException as e:
        return {"ok": False, "error": type(e).__name__, "s": round(time.monotonic() - t, 2)}


def in_job():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    result = wintypes.BOOL()
    if not k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(result)):
        raise OSError(ctypes.get_last_error(), "IsProcessInJob")
    return bool(result.value)


def job_pids():
    k = ctypes.WinDLL("kernel32", use_last_error=True)

    class Listed(ctypes.Structure):
        _fields_ = [("assigned", wintypes.DWORD), ("listed", wintypes.DWORD), ("ids", ctypes.c_size_t * 256)]
    out = Listed()
    k.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    if not k.QueryInformationJobObject(None, 3, ctypes.byref(out), ctypes.sizeof(out), None):
        raise OSError(ctypes.get_last_error(), "QueryInformationJobObject")
    return out.assigned


def tcp_table():
    size = wintypes.DWORD(0)
    return [ctypes.WinDLL("iphlpapi").GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0), size.value]


def own_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    c = socket.create_connection(srv.getsockname(), timeout=5)
    a, _ = srv.accept()
    c.sendall(b"x")
    got = a.recv(1)
    for s in (a, c, srv):
        s.close()
    return got.decode()


def pair():
    a, b = socket.socketpair()
    a.sendall(b"y")
    got = b.recv(1)
    a.close()
    b.close()
    return got.decode()


def loop():
    async def main():
        await asyncio.sleep(0.01)
        return "ran"
    return asyncio.run(main())


def loop_server():
    async def main():
        async def answer(r, w):
            w.write(await r.read(1))
            await w.drain()
            w.close()
        srv = await asyncio.start_server(answer, "127.0.0.1", 0)
        r, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
        w.write(b"z")
        await w.drain()
        got = await r.read(1)
        w.close()
        srv.close()
        await srv.wait_closed()
        return got.decode()
    return asyncio.run(main())


def datagrams():
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0))
    a.settimeout(5)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.sendto(b"d", a.getsockname())
    got, _ = a.recvfrom(1)
    a.close()
    b.close()
    return got.decode()


SERVER = ("import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 0))\ns.listen()\n"
          "print(s.getsockname()[1], flush=True)\nc, _ = s.accept()\nc.sendall(c.recv(1))\nc.close()\n")


def second_program():
    p = subprocess.Popen([sys.executable, "-I", "-c", SERVER], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        said = p.stdout.readline()
        c = socket.create_connection(("127.0.0.1", int(said)), timeout=5)
        c.sendall(b"w")
        got = c.recv(1)
        c.close()
        return got.decode()
    finally:
        p.kill()
        p.wait()


def pool():
    with multiprocessing.Pool(2) as p:
        return p.map(abs, [-1, -2])


def connect(host, port):
    return lambda: socket.create_connection((host, port), timeout=4).close()


def read(path):
    def go():
        with open(path, "rb") as f:
            f.read(1)
        return True
    return go


def listing(path):
    return lambda: os.listdir(path) is not None


def write(path):
    def go():
        with open(path, "w", encoding="utf-8") as f:
            f.write("x")
        with open(path, encoding="utf-8") as f:
            return f.read() == "x"
    return go


def pipe(name):
    return lambda: open(name, "r+b", buffering=0).close()


def lookup(name):
    return lambda: len(socket.getaddrinfo(name, 443))


NODE_CONNECT = ("const s = require('net').connect(9, process.argv[1]); s.setTimeout(6000, () => { console.log('timeout'); "
                "process.exit(3) }); s.on('connect', () => { console.log('connected'); process.exit(0) }); "
                "s.on('error', e => { console.log(e.code); process.exit(2) })")
NODE_READ = "require('fs').readFileSync(process.argv[1]); console.log('read')"


if __name__ == "__main__":
    given = json.loads(open(sys.argv[1], encoding="utf-8").read())
    def here(p):
        return os.path.normcase(os.path.realpath(p))
    copy, base = here(given["copy"]), here(given["base"])
    facts = {"prefix_is_copy": here(sys.prefix) == copy, "executable_is_copy": here(os.path.dirname(sys.executable)) == copy,
             "cwd_is_app": here(os.getcwd()) == here(given["app"]),
             "base_on_path": any(here(p) == base or here(p).startswith(base + os.sep) for p in sys.path if p)}
    for name, fn in (("in_job", in_job), ("job_pids", job_pids), ("tcp_table", tcp_table), ("loop", loop),
                     ("socketpair", pair), ("own_server", own_server), ("loop_server", loop_server),
                     ("datagrams", datagrams)):
        facts[name] = bounded(fn, 20)
    facts["second_program"] = bounded(second_program, 30)
    facts["pool"] = bounded(pool, 60)
    facts["bare_python"] = program(["python", "-I", "-c", "import sys; print(sys.prefix)"], same=copy)
    facts["bare_python_own_env"] = program(["python", "-I", "-c", "import sys; print(sys.prefix)"], same=copy,
                                           env={"SYSTEMROOT": os.environ["SYSTEMROOT"],
                                                "PATH": os.environ["SYSTEMROOT"] + "\\System32"})
    facts["cmd"] = program(["cmd.exe", "/d", "/c", "echo inside"])
    facts["outside_v4"] = bounded(connect("192.0.2.1", 9), 15)
    facts["outside_v6"] = bounded(connect("2001:db8::1", 9), 15)
    facts["lookup_outside"] = bounded(lookup("lantern-probe.invalid"), 15)
    facts["lookup_self"] = bounded(lookup("localhost"), 15)
    facts["other_listener"] = bounded(connect("127.0.0.1", given["listener"]), 15)
    facts["other_pipe"] = bounded(pipe(given["pipe"]), 15)
    facts["person_read"] = attempt(read(given["person_file"]))
    facts["person_list"] = attempt(listing(given["person"]))
    facts["write_outside"] = attempt(write(os.path.join(given["person"], "new.txt")))
    facts["checkout_read"] = attempt(read(given["checkout_file"]))
    facts["base_python_read"] = attempt(read(given["base_python"]))
    facts["write_tmp"] = attempt(write(os.path.join(given["tmp"], "x.txt")))
    facts["write_app"] = attempt(write(os.path.join(given["app"], "x.txt")))
    facts["share_outside"] = bounded(listing("\\\\192.0.2.1\\share"), 25)
    facts["share_here"] = bounded(listing("\\\\localhost\\C$"), 25)
    if given.get("curl"):
        facts["curl_outside"] = program([given["curl"], "-sS", "--max-time", "8", "http://192.0.2.1:9/"])
        facts["curl_file"] = program([given["curl"], "-sS", "-o", "NUL", "file:///" + given["person_file"].replace("\\", "/")])
    if given.get("node"):
        facts["node_start"] = program([given["node"], "-e", "console.log(process.version)"])
        facts["node_outside"] = program([given["node"], "-e", NODE_CONNECT, "192.0.2.1"], word=True)
        facts["node_other_listener"] = program([given["node"], "-e", NODE_CONNECT.replace("connect(9,", "connect("
                                                + str(given["listener"]) + ","), "127.0.0.1"], word=True)
        facts["node_read"] = program([given["node"], "-e", NODE_READ, given["person_file"]], word=True)
    print("FACTS " + json.dumps(facts), flush=True)
    sys.stdout.flush()
    os._exit(0)
'''
LAUNCH = "import sys; sys.path.insert(0, {root!r}); from lantern.wincontainer import main; main(sys.argv[1:])"
# What an honest test does, which must still work inside the container
HONEST = ("loop", "socketpair", "own_server", "loop_server", "datagrams", "second_program", "pool", "cmd",
          "write_tmp", "write_app", "in_job", "lookup_self")
# What lies outside the run, which must be refused inside it, and refused by Windows: not left to time out
REFUSED = ("outside_v4", "outside_v6", "other_listener", "other_pipe", "person_read", "person_list", "write_outside",
           "checkout_read", "share_outside", "share_here")
REFUSED_PROGRAMS = ("curl_outside", "curl_file", "node_outside", "node_other_listener", "node_read")


def _count(folder: Path) -> tuple[int, int]:
    files = size = 0
    for here, _, names in os.walk(folder):
        for name in names:
            files += 1
            size += os.path.getsize(os.path.join(here, name))
    return files, size


@pytest.fixture(scope="module")
def tried(tmp_path_factory):
    """Everything tried once: a container, a whole Python in the run's folder, the probe started in the container
    from inside a job of the run's own, as the sandbox starts the tests' command. Returns (facts, costs)."""
    if not WINDOWS:
        pytest.skip("an AppContainer is Windows' own")
    root = tmp_path_factory.mktemp("run")
    person = tmp_path_factory.mktemp("person")
    (person / "secret.txt").write_text("the person's own words\n", encoding="utf-8")
    tmp, app = root / "tmp", root / "app"
    costs: dict = {}
    t = time.monotonic()
    box = wincontainer.Container()
    costs["make"] = round(time.monotonic() - t, 2)
    listener = socket.socket()
    pipe = None
    try:
        t = time.monotonic()
        box.grant(root)
        costs["grant_empty"] = round(time.monotonic() - t, 2)
        tmp.mkdir()
        app.mkdir()
        box.grant(tmp, change=True)
        box.grant(app, change=True)
        t = time.monotonic()
        exe = sandbox._whole_python(root / "py", [str(app)])
        costs["copy_python"] = round(time.monotonic() - t, 2)
        costs["files"], costs["bytes"] = _count(root / "py")
        t = time.monotonic()
        box.grant(root / "py")          # what a grant costs over a folder that is full already
        costs["grant_full"] = round(time.monotonic() - t, 2)
        (root / "probe.py").write_text(PROBE, encoding="utf-8")
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        reached: list = []
        threading.Thread(target=lambda: reached.append(listener.accept()), daemon=True).start()
        from multiprocessing.connection import Listener
        pipe = Listener(family="AF_PIPE")
        threading.Thread(target=lambda: reached.append(pipe.accept()), daemon=True).start()
        curl = Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) / "System32" / "curl.exe"
        given = {"listener": listener.getsockname()[1], "pipe": pipe.address, "person": str(person),
                 "person_file": str(person / "secret.txt"), "checkout_file": str(Path(__file__).resolve().parents[1] / "pyproject.toml"),
                 "base_python": str(Path(sys.base_prefix) / "python.exe"), "tmp": str(tmp), "app": str(app),
                 "copy": str(root / "py"), "base": sys.base_prefix,
                 "curl": str(curl) if curl.is_file() else "", "node": shutil.which("node") or ""}
        (root / "given.json").write_text(json.dumps(given), encoding="utf-8")
        env = sandbox._env_base(tmp)
        env["PATH"] = os.pathsep.join([os.path.dirname(exe), env.get("PATH", "")])
        root_of_lantern = str(Path(wincontainer.__file__).resolve().parent.parent)
        cmd = [sys.executable, "-I", "-c", LAUNCH.format(root=root_of_lantern), box.text, "--", exe,
               str(root / "probe.py"), str(root / "given.json")]
        lines: list[str] = []
        t = time.monotonic()
        rc, output, timed_out = sandbox._stream(cmd, app, env, 400, lines.append,
                                                job=lambda: sandbox._windows_job(2048))
        costs["probe"] = round(time.monotonic() - t, 2)
        costs["rc"], costs["timed_out"], costs["reached_outside"] = rc, timed_out, len(reached)
        said = [line for line in output.splitlines() if line.startswith("FACTS ")]
        facts = json.loads(said[-1][len("FACTS "):]) if said else {"no facts": output[-3000:]}
    finally:
        listener.close()
        if pipe is not None:
            pipe.close()
        t = time.monotonic()
        box.close()
        costs["delete"] = round(time.monotonic() - t, 2)
    return facts, costs


@ONLY_WINDOWS
def test_what_windows_did_is_written_out(tried, capsys):
    facts, costs = tried
    with capsys.disabled():
        print("\n[wincontainer] costs: " + json.dumps(costs))
        for name, value in facts.items():
            print(f"[wincontainer] {name}: {json.dumps(value)[:300]}")
    assert "no facts" not in facts, facts
    assert costs["rc"] == 0 and not costs["timed_out"], costs


@ONLY_WINDOWS
def test_in_the_container_the_tests_python_is_the_runs_own_whole_python(tried):
    facts, _ = tried
    assert facts["prefix_is_copy"] and facts["executable_is_copy"] and facts["cwd_is_app"], facts
    assert not facts["base_on_path"], facts         # nothing of this computer's Python is on its path
    for how in ("bare_python", "bare_python_own_env"):
        assert facts[how].get("ok") and facts[how].get("same"), facts[how]


@ONLY_WINDOWS
@pytest.mark.parametrize("name", HONEST)
def test_what_an_honest_test_does_still_works_in_the_container(tried, name):
    facts, _ = tried
    assert facts[name].get("ok"), facts[name]


@ONLY_WINDOWS
@pytest.mark.parametrize("name", REFUSED)
def test_what_lies_outside_the_run_is_refused_by_windows_in_the_container(tried, name):
    facts, costs = tried
    fact = facts[name]
    assert not fact.get("ok") and fact.get("error") not in ("TimeoutError", "still waiting"), fact
    if name in ("other_listener", "other_pipe"):
        assert costs["reached_outside"] == 0, costs


@ONLY_WINDOWS
@pytest.mark.parametrize("name", REFUSED_PROGRAMS)
def test_a_program_that_is_not_python_is_refused_too(tried, name):
    facts, _ = tried
    if name not in facts:
        pytest.skip("Node is not installed on this computer" if name.startswith("node") else "no curl.exe in System32")
    fact = facts[name]
    assert not fact.get("ok") and fact.get("rc") not in (None, 28) and fact.get("word") != "timeout", fact
