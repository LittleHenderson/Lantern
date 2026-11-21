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
import _winapi, asyncio, ctypes, json, multiprocessing, os, re, socket, subprocess, sys, threading, time
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


CODE = re.compile(r"\bcode:?\s+'?([A-Z][A-Z0-9_]{1,24})\b")
SYSCALL = re.compile(r"\bsyscall:?\s+'?([a-z][a-z0-9_]{1,24})\b")


def program(cmd, seconds=30, word=False, same=None, codes=False, **kw):
    """A program's result only: `word`, the one word it printed (the probe's own programs print one), `same`,
    whether the one line it printed names that folder, and `codes`, the error code and the system call a program
    of Node names when it fails (`EPERM`, `lstat`). Nothing it read or printed besides is kept."""
    t = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=seconds, **kw)
        out = {"ok": r.returncode == 0, "rc": r.returncode, "s": round(time.monotonic() - t, 2)}
        if word:
            out["word"] = (r.stdout.split() or [""])[0][:20]
        if codes:
            said = r.stdout + "\n" + r.stderr
            out["codes"] = sorted(set(CODE.findall(said)))[:4]
            out["syscalls"] = sorted(set(SYSCALL.findall(said)))[:4]
            out["module"] = "Cannot find module" in said
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


def tables():
    """What Windows answers when asked how large its tables of this computer's sockets are, in the forms Lantern's
    guard asks for them (with the program of each): 122 is "a larger buffer", 5 is "access denied"."""
    ip = ctypes.WinDLL("iphlpapi")
    out = {}
    for name, call, family, form in (("tcp4", ip.GetExtendedTcpTable, 2, 5), ("tcp6", ip.GetExtendedTcpTable, 23, 5),
                                     ("udp4", ip.GetExtendedUdpTable, 2, 1)):
        size = wintypes.DWORD(0)
        out[name] = call(None, ctypes.byref(size), False, family, form, 0)
    return out


def token():
    """Whether this program's token is an AppContainer's, and whether it is the one the run made (`given["sid"]`)."""
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.LocalFree.argtypes = [ctypes.c_void_p]
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD)]
    a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    h = wintypes.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(h)):      # TOKEN_QUERY
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        flag, got = wintypes.DWORD(), wintypes.DWORD()
        if not a.GetTokenInformation(h, 29, ctypes.byref(flag), 4, ctypes.byref(got)):      # TokenIsAppContainer
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        buf = ctypes.create_string_buffer(256)
        if not a.GetTokenInformation(h, 31, buf, 256, ctypes.byref(got)):                # TokenAppContainerSid
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        text = wintypes.LPWSTR()
        if not a.ConvertSidToStringSidW(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
        try:
            return {"container": bool(flag.value), "same": text.value == given["sid"]}
        finally:
            k.LocalFree(text)
    finally:
        k.CloseHandle(h)


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


def datagrams_to(host, port):
    def go():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for _ in range(3):
                s.sendto(b"u", (host, port))
        return "sent"
    return go


PLAIN = "\\\\.\\pipe\\"
LOCAL = PLAIN + "LOCAL\\"


def pipe_pair(prefix):
    """A pipe made and its other end opened the way multiprocessing makes one, under a name of the given form."""
    name = prefix + "pyc-%d-probe-%d" % (os.getpid(), time.monotonic_ns())
    h1 = _winapi.CreateNamedPipe(name, _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
                                 1, 4096, 4096, _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL)
    try:
        _winapi.CloseHandle(_winapi.CreateFile(name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                                               _winapi.OPEN_EXISTING, 0, _winapi.NULL))
    finally:
        _winapi.CloseHandle(h1)
    return True


def local(name):
    if (isinstance(name, str) and name[:len(PLAIN)].lower() == PLAIN.lower()
            and not name[len(PLAIN):].upper().startswith("LOCAL\\")):
        return LOCAL + name[len(PLAIN):]
    return name


def local_names():
    """What a guard inside the container would do: every pipe name of this program put under the container's own
    part of the names (`\\\\.\\pipe\\LOCAL\\`), at each call Python's own modules name a pipe with."""
    import _overlapped
    for module, attrs in ((_winapi, ("CreateNamedPipe", "CreateFile", "WaitNamedPipe")), (_overlapped, ("ConnectPipe",))):
        for attr in attrs:
            def wrapped(name, *rest, _real=getattr(module, attr)):
                return _real(local(name), *rest)
            setattr(module, attr, wrapped)


if os.environ.get("PROBE_LOCAL_PIPES") == "1":      # the programs multiprocessing starts read this file first
    local_names()


def mp_pipe():
    from multiprocessing.connection import Pipe
    a, b = Pipe()
    a.send("p")
    got = b.recv()
    a.close()
    b.close()
    return got


def mp_listener():
    from multiprocessing.connection import Client, Listener
    with Listener(family="AF_PIPE") as srv:
        box = {}
        th = threading.Thread(target=lambda: box.update(c=srv.accept()), daemon=True)
        th.start()
        c = Client(srv.address, family="AF_PIPE")
        th.join(10)
        c.send("l")
        got = box["c"].recv()
        c.close()
        box["c"].close()
        return got


def manager():
    with multiprocessing.Manager() as m:
        d = m.dict()
        d["k"] = "m"
        return d["k"]


def loop_subprocess():
    async def main():
        p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", "print('a')",
                                                 stdout=asyncio.subprocess.PIPE)
        out, _ = await p.communicate()
        return out.decode().strip()
    return asyncio.run(main())


def broker(name):
    """A pipe a program outside the container made for this container alone: opened, asked, answered."""
    h = _winapi.CreateFile(name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
                           _winapi.OPEN_EXISTING, 0, _winapi.NULL)
    try:
        _winapi.WriteFile(h, b"tcp 1")
        data, _ = _winapi.ReadFile(h, 64)
        return data == b"yes"           # whether the answer was the one it gives (nothing read is kept)
    finally:
        _winapi.CloseHandle(h)


def closed_port():
    """A connection to a port of this computer that nobody holds (one the run held a moment ago)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    socket.create_connection(("127.0.0.1", port), timeout=4).close()


def other_pipe_by_name():
    _winapi.CloseHandle(_winapi.CreateFile(given["pipe"], _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0,
                                           _winapi.NULL, _winapi.OPEN_EXISTING, 0, _winapi.NULL))


NODE_CONNECT = ("const s = require('net').connect(9, process.argv[1]); s.setTimeout(6000, () => { console.log('timeout'); "
                "process.exit(3) }); s.on('connect', () => { console.log('connected'); process.exit(0) }); "
                "s.on('error', e => { console.log(e.code); process.exit(2) })")
NODE_READ = "require('fs').readFileSync(process.argv[1]); console.log('read')"
NODE_WRITE = "require('fs').writeFileSync(process.argv[1], 'x'); console.log('wrote')"
NODE_DATAGRAM = ("const d = require('dgram').createSocket('udp4'); "
                 "d.send(Buffer.from('n'), Number(process.argv[1]), '127.0.0.1', e => { console.log(e ? e.code : 'sent'); "
                 "d.close() })")
NODE_OWN_SERVER = ("const net = require('net'); const srv = net.createServer(c => c.end('n')); "
                   "srv.listen(0, '127.0.0.1', () => { const c = net.connect(srv.address().port, '127.0.0.1'); "
                   "c.on('data', () => { console.log('ok'); process.exit(0) }); "
                   "c.on('error', e => { console.log(e.code); process.exit(2) }) }); "
                   "setTimeout(() => { console.log('timeout'); process.exit(3) }, 6000)")


if __name__ == "__main__":
    given = json.loads(open(sys.argv[1], encoding="utf-8").read())
    def here(p):
        return os.path.normcase(os.path.realpath(p))
    copy, base = here(given["copy"]), here(given["base"])
    facts = {"prefix_is_copy": here(sys.prefix) == copy, "executable_is_copy": here(os.path.dirname(sys.executable)) == copy,
             "cwd_is_app": here(os.getcwd()) == here(given["app"]),
             "base_on_path": any(here(p) == base or here(p).startswith(base + os.sep) for p in sys.path if p)}
    for name, fn in (("in_job", in_job), ("job_pids", job_pids), ("tables", tables), ("token", token), ("loop", loop),
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
    if given.get("listener6"):
        facts["other_listener_v6"] = bounded(connect("::1", given["listener6"]), 15)
    facts["any_listener_loopback"] = bounded(connect("127.0.0.1", given["any"]), 15)
    if given.get("own"):
        facts["own_address"] = bounded(connect(given["own"], given["any"]), 15)
    facts["other_datagram"] = bounded(datagrams_to("127.0.0.1", given["udp"]), 15)
    if given.get("own"):
        facts["own_address_datagram"] = bounded(datagrams_to(given["own"], given["udp_any"]), 15)
    facts["outside_datagram"] = bounded(datagrams_to("192.0.2.1", 9), 15)     # whether Windows refuses it at all
    facts["closed_port"] = bounded(closed_port, 15)
    facts["broker"] = bounded(lambda: broker(given["broker"]), 15)
    facts["broker_no_label"] = bounded(lambda: broker(given["broker_no_label"]), 15)
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
        curl = given["curl"]
        facts["curl_outside"] = program([curl, "-sS", "--max-time", "8", "http://192.0.2.1:9/"])
        facts["curl_file"] = program([curl, "-sS", "-o", "NUL", "file:///" + given["person_file"].replace("\\", "/")])
        facts["curl_other_listener"] = program([curl, "-sS", "--max-time", "8", f"http://127.0.0.1:{given['listener']}/"])
        if given.get("own"):
            facts["curl_own_address"] = program([curl, "-sS", "--max-time", "8", f"http://{given['own']}:{given['any']}/"])
    if given.get("node"):
        facts["node_start"] = program([given["node"], "-e", "console.log(process.version)"])
        facts["node_system_read"] = attempt(read(given["node"]))
    if given.get("node_copy"):
        node = given["node_copy"]
        facts["node_copy_start"] = program([node, "-e", "console.log(process.version)"])
        facts["node_copy_own_server"] = program([node, "-e", NODE_OWN_SERVER], word=True)
        facts["node_copy_outside"] = program([node, "-e", NODE_CONNECT, "192.0.2.1"], word=True)
        facts["node_copy_other_listener"] = program([node, "-e", NODE_CONNECT.replace("connect(9,", "connect("
                                                     + str(given["listener"]) + ","), "127.0.0.1"], word=True)
        facts["node_copy_read"] = program([node, "-e", NODE_READ, given["person_file"]], word=True)
        facts["node_copy_write"] = program([node, "-e", NODE_WRITE, os.path.join(given["person"], "node.txt")],
                                           word=True)
        facts["node_copy_datagram"] = program([node, "-e", NODE_DATAGRAM, str(given["udp_node"])], word=True)
        if given.get("npm_cli"):
            facts["npm_version"] = program([node, given["npm_cli"], "--version"], seconds=90, codes=True)
            # npm as the sandbox starts it: its home, settings, cache and temp folder inside the run (`_env_base`),
            # and the copy of Node first on PATH, so that the shell npm runs a script with finds it
            home = os.path.join(given["tmp"], "home")
            os.makedirs(home, exist_ok=True)
            env = dict(os.environ, HOME=home, USERPROFILE=home, APPDATA=home, LOCALAPPDATA=home, TEMP=given["tmp"],
                       TMP=given["tmp"], npm_config_cache=os.path.join(given["tmp"], "npm"),
                       npm_config_update_notifier="false",
                       PATH=os.path.dirname(node) + os.pathsep + os.environ.get("PATH", ""))
            facts["npm_version_home"] = program([node, given["npm_cli"], "--version"], seconds=90, codes=True, env=env)
            js = os.path.join(given["tmp"], "js")
            os.makedirs(js, exist_ok=True)
            with open(os.path.join(js, "package.json"), "w", encoding="utf-8") as f:
                json.dump({"name": "probe", "version": "1.0.0", "scripts": {"test": "node -e \"console.log('t')\""}}, f)
            facts["npm_test_home"] = program([node, given["npm_cli"], "test", "--silent"], seconds=90, word=True,
                                             codes=True, env=env, cwd=js)
    # the pipes: Windows' answer to each kind of name, then what multiprocessing and the event loop do once every
    # name is put under the container's own part (as a guard inside it would put them)
    facts["pipe_plain"] = bounded(lambda: pipe_pair(PLAIN), 15)
    facts["pipe_local"] = bounded(lambda: pipe_pair(LOCAL), 15)
    facts["loop_subprocess"] = bounded(loop_subprocess, 30)
    os.environ["PROBE_LOCAL_PIPES"] = "1"
    local_names()
    facts["mp_pipe_local"] = bounded(mp_pipe, 15)
    facts["mp_listener_local"] = bounded(mp_listener, 20)
    facts["pool_local"] = bounded(pool, 60)
    facts["manager_local"] = bounded(manager, 60)
    facts["loop_subprocess_local"] = bounded(loop_subprocess, 30)
    facts["other_pipe_local"] = bounded(other_pipe_by_name, 15)
    print("FACTS " + json.dumps(facts), flush=True)
    sys.stdout.flush()
    os._exit(0)
'''
LAUNCH = "import sys; sys.path.insert(0, {root!r}); from lantern.wincontainer import main; main(sys.argv[1:])"
# What an honest test does, which must still work inside the container (a pipe, a pool of processes, a manager and
# the event loop's programs once their pipes are named under the container's own part of the names)
HONEST = ("loop", "socketpair", "own_server", "loop_server", "datagrams", "second_program", "cmd", "write_tmp",
          "write_app", "in_job", "lookup_self", "pipe_local", "mp_pipe_local", "mp_listener_local", "pool_local",
          "manager_local", "loop_subprocess_local")
# What lies outside the run, which must be refused inside it, and refused by Windows at once: not left to time out
REFUSED = ("outside_v4", "outside_v6", "lookup_outside", "other_pipe", "other_pipe_local", "person_read", "person_list",
           "write_outside", "checkout_read", "base_python_read", "share_outside", "share_here")
# Another program of this computer that waits at an address: Windows drops what the container sends there without
# a word, so the try may wait; what counts is that nothing reached that program (which listens for it, `reached`)
UNREACHED = {"other_listener": "tcp", "other_listener_v6": "tcp6", "any_listener_loopback": "any",
             "own_address": "any"}
REFUSED_PROGRAMS = {"curl_outside": None, "curl_file": None, "curl_other_listener": "tcp", "curl_own_address": "any",
                    "node_copy_outside": None, "node_copy_other_listener": "tcp", "node_copy_read": None,
                    "node_copy_write": None}
# Datagrams sent from the container to a socket of another program of this computer (`other_datagram`,
# `own_address_datagram`, `node_copy_datagram`) are counted in `costs["reached"]` and written out with the rest.
# npm with a home the run may not read (`npm_version`) is written out only: the sandbox gives the tests a home of
# their own inside the run (`sandbox._env_base`)
HONEST_PROGRAMS = ("node_copy_start", "node_copy_own_server", "npm_version_home", "npm_test_home")
SAYS = {"node_copy_own_server": "ok", "npm_test_home": "t"}      # the one word each prints when it worked


def _own_address() -> str:
    """This computer's own address on its network (not its loopback one), by its own name: no packet is sent."""
    try:
        found = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return ""
    return next((a[4][0] for a in found if not a[4][0].startswith("127.")), "")


def _place(path: str) -> str:
    """Where a program lies, in one word (never the path)."""
    here = os.path.normcase(os.path.realpath(path))
    for word, variable in (("program-files", "ProgramFiles"), ("program-files-x86", "ProgramFiles(x86)"),
                           ("tool-cache", "RUNNER_TOOL_CACHE"), ("home", "USERPROFILE")):
        base = os.environ.get(variable)
        if base and here.startswith(os.path.normcase(os.path.realpath(base)) + os.sep):
            return word
    return "other"


def _take(srv, kind: str, reached: list) -> None:
    """Every connection or datagram that reaches one of the programs outside the run, counted until it is closed."""
    while True:
        try:
            if kind == "udp":
                srv.recvfrom(64)
            else:
                srv.accept()[0].close()
        except (TimeoutError, socket.timeout):
            continue
        except OSError:
            return
        reached.append(kind)


class _Broker:
    """A pipe this program makes for the container alone (its owner, the system and the container's SID; with or
    without the mark that lets a program of low integrity write to it), which answers one question with "yes"."""

    def __init__(self, sid: str, label: bool):
        import _winapi
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            ctypes.c_wchar_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        self._sd = ctypes.c_void_p()
        text = f"D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GRGW;;;{sid})" + ("S:(ML;;NW;;;LW)" if label else "")
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, ctypes.byref(self._sd), None):
            raise ctypes.WinError(ctypes.get_last_error())

        class Attributes(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]
        self._sa = Attributes(ctypes.sizeof(Attributes), self._sd, False)
        self.name = "\\\\.\\pipe\\lantern-probe-" + os.urandom(8).hex()
        self._h = _winapi.CreateNamedPipe(self.name, _winapi.PIPE_ACCESS_DUPLEX,
                                          _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
                                          1, 512, 512, 0, ctypes.addressof(self._sa))
        self.asked = 0
        self._done = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        import _winapi
        try:
            _winapi.ConnectNamedPipe(self._h)
            if self._done.is_set():
                return
            data, _ = _winapi.ReadFile(self._h, 64)
            if data:
                self.asked += 1
                _winapi.WriteFile(self._h, b"yes")
        except OSError:
            return

    def close(self):
        import _winapi
        self._done.set()
        try:                    # the server waits for a caller: be one, so that it stops waiting
            _winapi.CloseHandle(_winapi.CreateFile(self.name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0,
                                                   _winapi.NULL, _winapi.OPEN_EXISTING, 0, _winapi.NULL))
        except OSError:
            pass
        ctypes.WinDLL("kernel32").LocalFree(self._sd)


def _pipe_for(sid: str, label: bool) -> _Broker:
    return _Broker(sid, label)


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
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_any = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_node = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    every = socket.socket()
    brokers: list = []
    listener6 = None
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
        node = shutil.which("node") or ""
        node_copy = npm_cli = ""
        if node:
            costs["node_place"] = _place(node)
        if node.lower().endswith(".exe"):          # not a script that starts it (a version manager's)
            t = time.monotonic()
            (root / "node").mkdir()
            node_copy = shutil.copy2(node, root / "node" / "node.exe")
            npm = Path(node).resolve().parent / "node_modules" / "npm"
            if (npm / "bin" / "npm-cli.js").is_file():
                shutil.copytree(npm, root / "node" / "node_modules" / "npm", symlinks=True)
                npm_cli = str(root / "node" / "node_modules" / "npm" / "bin" / "npm-cli.js")
            costs["copy_node"] = round(time.monotonic() - t, 2)
            costs["node_files"], costs["node_bytes"] = _count(root / "node")
        reached: list = []
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        threading.Thread(target=_take, args=(listener, "tcp", reached), daemon=True).start()
        every.bind(("0.0.0.0", 0))
        every.listen()
        threading.Thread(target=_take, args=(every, "any", reached), daemon=True).start()
        for sock, kind, where in ((udp, "udp", "127.0.0.1"), (udp_any, "udp_any", "0.0.0.0"),
                                  (udp_node, "udp_node", "127.0.0.1")):
            sock.bind((where, 0))
            sock.settimeout(0.5)
            threading.Thread(target=_take, args=(sock, kind, reached), daemon=True).start()
        brokers += [_pipe_for(box.text, label=True), _pipe_for(box.text, label=False)]
        try:
            listener6 = socket.socket(socket.AF_INET6)
            listener6.bind(("::1", 0))
            listener6.listen()
            threading.Thread(target=_take, args=(listener6, "tcp6", reached), daemon=True).start()
        except OSError:
            listener6 = None
        from multiprocessing.connection import Listener
        pipe = Listener(family="AF_PIPE")
        threading.Thread(target=lambda: reached.append(pipe.accept() and "pipe"), daemon=True).start()
        curl = Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) / "System32" / "curl.exe"
        given = {"listener": listener.getsockname()[1], "pipe": pipe.address, "person": str(person),
                 "person_file": str(person / "secret.txt"), "checkout_file": str(Path(__file__).resolve().parents[1] / "pyproject.toml"),
                 "base_python": str(Path(sys.base_prefix) / "python.exe"), "tmp": str(tmp), "app": str(app),
                 "copy": str(root / "py"), "base": sys.base_prefix, "sid": box.text,
                 "udp": udp.getsockname()[1], "any": every.getsockname()[1], "own": _own_address(),
                 "udp_any": udp_any.getsockname()[1], "udp_node": udp_node.getsockname()[1],
                 "broker": brokers[0].name, "broker_no_label": brokers[1].name,
                 "listener6": listener6.getsockname()[1] if listener6 is not None else 0,
                 "curl": str(curl) if curl.is_file() else "", "node": node, "node_copy": str(node_copy),
                 "npm_cli": npm_cli}
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
        time.sleep(1)                   # a datagram on its way is counted too
        costs["rc"], costs["timed_out"], costs["reached_outside"] = rc, timed_out, len(reached)
        costs["reached"] = {kind: reached.count(kind) for kind in ("tcp", "tcp6", "any", "udp", "udp_any", "udp_node",
                                                                   "pipe")}
        costs["brokers_asked"] = [b.asked for b in brokers]
        said = [line for line in output.splitlines() if line.startswith("FACTS ")]
        facts = json.loads(said[-1][len("FACTS "):]) if said else {"no facts": output[-3000:]}
    finally:
        for s in (listener, udp, udp_any, udp_node, every, listener6):
            if s is not None:
                s.close()
        for b in brokers:
            b.close()
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
def test_windows_refuses_a_pipe_named_outside_the_containers_own_part_of_the_names(tried):
    """Why a pool of processes, a manager and the event loop's programs need their pipes named under `LOCAL\\`
    inside a container: Windows refuses to make a pipe under any other name there ("access denied", 5)."""
    facts, _ = tried
    for name in ("pipe_plain", "pool", "loop_subprocess"):
        assert not facts[name].get("ok") and facts[name].get("number") == 5, (name, facts[name])
    assert facts["pipe_local"].get("ok"), facts["pipe_local"]


@ONLY_WINDOWS
def test_inside_the_container_a_program_can_tell_it_is_in_the_runs_own(tried):
    """What a guard inside the container needs before it leaves this computer's own address to Windows."""
    facts, _ = tried
    assert facts["token"].get("ok") and facts["token"]["value"] == {"container": True, "same": True}, facts["token"]


@ONLY_WINDOWS
@pytest.mark.parametrize("name", REFUSED)
def test_what_lies_outside_the_run_is_refused_by_windows_in_the_container(tried, name):
    facts, costs = tried
    fact = facts[name]
    assert not fact.get("ok") and fact.get("error") not in ("TimeoutError", "still waiting"), fact
    assert costs["reached"]["pipe"] == 0, costs


@ONLY_WINDOWS
@pytest.mark.parametrize("name", sorted(UNREACHED))
def test_another_program_of_this_computer_is_not_reached_from_the_container(tried, name):
    facts, costs = tried
    if name not in facts:
        pytest.skip("this computer has no IPv6 loopback" if name.endswith("v6") else "this computer has no address "
                    "of its own on a network")
    assert not facts[name].get("ok"), facts[name]
    assert costs["reached"][UNREACHED[name]] == 0, costs


@ONLY_WINDOWS
@pytest.mark.parametrize("name", sorted(REFUSED_PROGRAMS))
def test_a_program_that_is_not_python_is_refused_too(tried, name):
    facts, costs = tried
    if name not in facts:
        pytest.skip("Node is not installed on this computer" if name.startswith("node") else
                    "no curl.exe in System32" if name in ("curl_outside", "curl_file", "curl_other_listener") else
                    "this computer has no address of its own on a network")
    fact, kind = facts[name], REFUSED_PROGRAMS[name]
    assert not fact.get("ok") and fact.get("rc") is not None, fact
    if kind is None:
        assert fact.get("rc") != 28 and fact.get("word") != "timeout", fact
    else:
        assert costs["reached"][kind] == 0, costs


@ONLY_WINDOWS
@pytest.mark.parametrize("name", HONEST_PROGRAMS)
def test_a_program_that_is_not_python_does_its_honest_work_in_the_container(tried, name):
    facts, _ = tried
    if name not in facts:
        pytest.skip("Node is not installed on this computer" if name.startswith("node") else "Node came without npm")
    assert facts[name].get("ok"), facts[name]
    assert facts[name].get("word") == SAYS[name] if name in SAYS else True, facts[name]
