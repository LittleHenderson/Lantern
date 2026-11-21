"""A Windows AppContainer of a run's own: the wall Windows itself keeps around every program of a project's tests.

`lantern.sandbox` runs a project's tests in a restricted process. On Linux the kernel keeps every program of a run
to the run's walls (a network of its own, Landlock, the doorman), whatever language it is written in. On Windows
the one such wall a program can be given without the administrator is an AppContainer: Windows gives the program a
token of its own kind, and with it

* no network at all, where the container is given no capability (Windows refuses the connection itself, whoever
  writes the program: Node, a compiled program, a Python started without Lantern's guard);
* no file or folder but those whose rights name the container, or name every application package (Windows' own
  folders do, so the system's programs and libraries still load), so the person's own files are out of its reach;
* and every program it starts is in the same container, as every program a job's member starts is in the job.

A container is made for each run under a name of its own (`PREFIX`, the number of the program that made it, a
random part) and given the run's folders (`Container.grant`: to read and run what is there, or to change it too),
and its profile is deleted after the run; the rights it was given go with the run's folder. `main` is the small
program that starts the tests' command inside it (`python -c ... -- <container> -- <command>`), from inside the
run's job (`lantern.winjob`): what the command starts is in the job and in the container.

Every result is read here. A call that fails raises `ContainerError`, which names the call and Windows' error number;
`main` then says so on its own line (`MARK`, the word `container`) and ends with `UNAVAILABLE`, the tests are not
run, and `lantern.sandbox` says why in words of its own (`lantern._jail.REASONS`).

Windows does not tell a program inside the container who holds a port of this computer (its tables of this computer's
sockets answer "access denied" there), and Lantern's guard inside lets a test connect only to a port the run's own
programs hold. So the launcher, outside the container and inside the run's job, answers that through a pipe of its
own (`Broker`): only the container may open an end of it, and only the launcher makes its ends.

Only documented calls of userenv, advapi32, kernel32 and iphlpapi are used. `api` stands for those libraries, so the
tests can hand in a stand-in on any system; the real ones are loaded only on Windows.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import subprocess
import sys
import threading
import time

PREFIX = "Lantern.Tests."               # every container Lantern makes: then the maker's number, then a random part
DESCRIPTION = "Lantern: the tests of one run, kept from the network and from the person's files"
MARK = "LANTERN-SANDBOX-UNAVAILABLE:"   # the line `lantern.sandbox` reads (the same mark as `lantern._jail.MARK`)
UNAVAILABLE = 119                       # ... and the result (`lantern._jail.UNAVAILABLE`)

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
GRANT_ACCESS = 1                        # ACCESS_MODE: added to what the folder grants already
SUB_CONTAINERS_AND_OBJECTS_INHERIT = 3  # the folder, and every file and folder in it, now and made later
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0
# FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: read a file, list a folder, run a program, load a library
READ_AND_RUN = 0x001200A9
# ... and FILE_GENERIC_WRITE and DELETE ("Modify"): make, write and remove; not change the rights or the owner
CHANGE = 0x001301BF

ATTRIBUTE_HANDLE_LIST = 0x00020002            # PROC_THREAD_ATTRIBUTE_HANDLE_LIST
ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009  # PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
STD_HANDLES = (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4)   # STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
HANDLE_FLAG_INHERIT = 0x00000001
INFINITE = 0xFFFFFFFF
WAIT_FAILED = 0xFFFFFFFF
INSUFFICIENT_BUFFER = 122               # ERROR_INSUFFICIENT_BUFFER: the size InitializeProcThreadAttributeList asks for
INVALID_HANDLE = ctypes.c_void_p(-1).value

# The broker: the launcher's pipe that says, for the guard inside the container, whose a port of this computer is.
BROKER_VARIABLE = "LANTERN_SANDBOX_BROKER"            # its name, chosen by `lantern.sandbox` for each run
BROKER_PID_VARIABLE = "LANTERN_SANDBOX_BROKER_PID"    # the program that made it, which the guard checks
BROKER_PREFIX = "\\\\.\\pipe\\lantern-broker-"        # ... then 32 hexadecimal digits
# Its rights: its owner and the system everything; the container only what opening an end to read and write takes
# (SYNCHRONIZE, FILE_READ_ATTRIBUTES, FILE_WRITE_DATA, FILE_READ_DATA), not the right to make another end of it
# (FILE_CREATE_PIPE_INSTANCE); and a program of low integrity, as every program in a container is, may write to it.
BROKER_RIGHTS = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;0x100083;;;{sid})S:(ML;;NW;;;LW)"
BROKER_OPEN = 0x00100083                # what the guard asks for when it opens an end (the same rights)
BROKER_ENDS = 4                         # ends the launcher keeps, each answering one question at a time
QUESTION = 3                            # b"t" (a listener) or b"u" (a datagram socket), then the port in two bytes
YES, NO = b"1", b"0"
PIPE_ACCESS_DUPLEX = 0x00000003
FIRST_PIPE_INSTANCE = 0x00080000        # FILE_FLAG_FIRST_PIPE_INSTANCE: the name is nobody's before the launcher's
REJECT_REMOTE_CLIENTS = 0x00000008      # PIPE_REJECT_REMOTE_CLIENTS (and byte mode, waiting: 0)
PIPE_CONNECTED = 535                    # ERROR_PIPE_CONNECTED: a caller came before the broker waited for one
NO_DATA = 232                           # ERROR_NO_DATA: the caller has gone already
MORE_DATA = 234                         # ERROR_MORE_DATA
NOT_SUPPORTED = 50                      # ERROR_NOT_SUPPORTED: this computer has no IPv6
SDDL_REVISION_1 = 1
JOB_PROCESS_IDS = 3                     # JobObjectBasicProcessIdList
TCP_LISTENERS = 3                       # TCP_TABLE_OWNER_PID_LISTENER
UDP_OWNERS = 1                          # UDP_TABLE_OWNER_PID
# (datagram, family) -> (a row's size, where its port is, where its program is): MIB_TCPROW_OWNER_PID,
# MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID (the guard's `_ROWS`)
ROWS = {(False, 2): (24, 8, 20), (False, 23): (56, 20, 52), (True, 2): (12, 4, 8), (True, 23): (28, 20, 24)}

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int
_HANDLE = ctypes.c_void_p
_HRESULT = ctypes.c_int32


class Trustee(ctypes.Structure):
    """TRUSTEE_W, naming one SID"""
    _fields_ = [("pMultipleTrustee", ctypes.c_void_p), ("MultipleTrusteeOperation", ctypes.c_int),
                ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", ctypes.c_void_p)]


class ExplicitAccess(ctypes.Structure):
    """EXPLICIT_ACCESS_W"""
    _fields_ = [("grfAccessPermissions", _DWORD), ("grfAccessMode", ctypes.c_int), ("grfInheritance", _DWORD),
                ("Trustee", Trustee)]


class SecurityCapabilities(ctypes.Structure):
    """SECURITY_CAPABILITIES: the container, and no capability"""
    _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                ("CapabilityCount", _DWORD), ("Reserved", _DWORD)]


class StartupInfo(ctypes.Structure):
    """STARTUPINFOW"""
    _fields_ = [("cb", _DWORD), ("lpReserved", ctypes.c_wchar_p), ("lpDesktop", ctypes.c_wchar_p),
                ("lpTitle", ctypes.c_wchar_p), ("dwX", _DWORD), ("dwY", _DWORD), ("dwXSize", _DWORD),
                ("dwYSize", _DWORD), ("dwXCountChars", _DWORD), ("dwYCountChars", _DWORD),
                ("dwFillAttribute", _DWORD), ("dwFlags", _DWORD), ("wShowWindow", ctypes.c_uint16),
                ("cbReserved2", ctypes.c_uint16), ("lpReserved2", ctypes.c_void_p), ("hStdInput", _HANDLE),
                ("hStdOutput", _HANDLE), ("hStdError", _HANDLE)]


class StartupInfoEx(ctypes.Structure):
    """STARTUPINFOEXW"""
    _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


class ProcessInformation(ctypes.Structure):
    """PROCESS_INFORMATION"""
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE), ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


class SecurityAttributes(ctypes.Structure):
    """SECURITY_ATTRIBUTES"""
    _fields_ = [("nLength", _DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", _BOOL)]


class ContainerError(OSError):
    """A call for the container failed. `call` is its name, `code` Windows' error number or result (0 when the call
    itself succeeded and its answer was the wrong one)."""

    def __init__(self, call: str, code: int, why: str = ""):
        self.call, self.code = call, int(code or 0) & 0xFFFFFFFF
        super().__init__(f"{call} failed (Windows error {self.code:#x})" if not why else f"{call}: {why}")


class _Api:
    """The functions this module calls, each with its argument and result types declared (without them ctypes passes
    a handle or a SID as a 32-bit number, which cuts a 64-bit one short)."""

    CALLS = {
        "userenv": (("CreateAppContainerProfile", _HRESULT, [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                                             ctypes.c_void_p, _DWORD, ctypes.POINTER(ctypes.c_void_p)]),
                    ("DeleteAppContainerProfile", _HRESULT, [ctypes.c_wchar_p])),
        "advapi32": (("FreeSid", ctypes.c_void_p, [ctypes.c_void_p]),
                     ("ConvertSidToStringSidW", _BOOL, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]),
                     ("ConvertStringSidToSidW", _BOOL, [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]),
                     ("GetNamedSecurityInfoW", _DWORD, [ctypes.c_wchar_p, ctypes.c_int, _DWORD, ctypes.c_void_p,
                                                        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                                        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]),
                     ("SetEntriesInAclW", _DWORD, [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.POINTER(ctypes.c_void_p)]),
                     ("SetNamedSecurityInfoW", _DWORD, [ctypes.c_wchar_p, ctypes.c_int, _DWORD, ctypes.c_void_p,
                                                        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]),
                     ("ConvertStringSecurityDescriptorToSecurityDescriptorW", _BOOL, [
                         ctypes.c_wchar_p, _DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)])),
        "kernel32": (("LocalFree", ctypes.c_void_p, [ctypes.c_void_p]),
                     ("InitializeProcThreadAttributeList", _BOOL, [ctypes.c_void_p, _DWORD, _DWORD,
                                                                   ctypes.POINTER(ctypes.c_size_t)]),
                     ("UpdateProcThreadAttribute", _BOOL, [ctypes.c_void_p, _DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                                           ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]),
                     ("DeleteProcThreadAttributeList", None, [ctypes.c_void_p]),
                     ("CreateProcessW", _BOOL, [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p,
                                                _BOOL, _DWORD, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p,
                                                ctypes.c_void_p]),
                     ("GetStdHandle", _HANDLE, [_DWORD]),
                     ("GetHandleInformation", _BOOL, [_HANDLE, ctypes.POINTER(_DWORD)]),
                     ("SetHandleInformation", _BOOL, [_HANDLE, _DWORD, _DWORD]),
                     ("WaitForSingleObject", _DWORD, [_HANDLE, _DWORD]),
                     ("GetExitCodeProcess", _BOOL, [_HANDLE, ctypes.POINTER(_DWORD)]),
                     ("CloseHandle", _BOOL, [_HANDLE]),
                     ("CreateNamedPipeW", _HANDLE, [ctypes.c_wchar_p, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD,
                                                    ctypes.c_void_p]),
                     ("ConnectNamedPipe", _BOOL, [_HANDLE, ctypes.c_void_p]),
                     ("DisconnectNamedPipe", _BOOL, [_HANDLE]),
                     ("ReadFile", _BOOL, [_HANDLE, ctypes.c_void_p, _DWORD, ctypes.POINTER(_DWORD), ctypes.c_void_p]),
                     ("WriteFile", _BOOL, [_HANDLE, ctypes.c_void_p, _DWORD, ctypes.POINTER(_DWORD), ctypes.c_void_p]),
                     ("FlushFileBuffers", _BOOL, [_HANDLE]),
                     ("QueryInformationJobObject", _BOOL, [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD,
                                                            ctypes.POINTER(_DWORD)])),
        "iphlpapi": (("GetExtendedTcpTable", _DWORD, [ctypes.c_void_p, ctypes.POINTER(_DWORD), _BOOL, ctypes.c_ulong,
                                                     ctypes.c_int, ctypes.c_ulong]),
                     ("GetExtendedUdpTable", _DWORD, [ctypes.c_void_p, ctypes.POINTER(_DWORD), _BOOL, ctypes.c_ulong,
                                                     ctypes.c_int, ctypes.c_ulong])),
    }

    def __init__(self):
        for library, calls in self.CALLS.items():
            dll = ctypes.WinDLL(library, use_last_error=True)    # Windows only: this class is made nowhere else
            for name, result, arguments in calls:
                fn = getattr(dll, name)
                fn.restype, fn.argtypes = result, arguments
                setattr(self, name, fn)

    @staticmethod
    def last_error() -> int:
        return ctypes.get_last_error()


def _need(api, call: str, result):
    """A call that answers with a true value when it worked and leaves its error number for `last_error`."""
    if not result:
        raise ContainerError(call, api.last_error())
    return result


def _done(call: str, code: int) -> None:
    """A call that answers with its error number (0 when it worked), or with an HRESULT."""
    if code:
        raise ContainerError(call, code)


def name_for(pid: int | None = None) -> str:
    """A container's name: `PREFIX`, the number of the program that makes it, and a random part (Windows takes a
    name of at most 64 characters among `-_. A-Za-z0-9`)."""
    return f"{PREFIX}{os.getpid() if pid is None else pid}.{secrets.token_hex(8)}"


class Container:
    """One AppContainer profile, made now and deleted by `close`. `text` is its SID as text, which `main` is handed."""

    def __init__(self, api=None, name: str | None = None):
        self.api = api if api is not None else _Api()
        self.name = name or name_for()
        self.sid = ctypes.c_void_p(None)
        self.made = False
        _done("CreateAppContainerProfile", self.api.CreateAppContainerProfile(
            self.name, self.name, DESCRIPTION, None, 0, ctypes.byref(self.sid)))
        self.made = True
        try:
            if not self.sid.value:
                raise ContainerError("CreateAppContainerProfile", 0, "Windows made the profile and gave no SID")
            self.text = sid_text(self.api, self.sid)
        except BaseException:
            self.close()
            raise

    def grant(self, path, change: bool = False) -> None:
        """Let the container read and run what is in `path` (a folder: and in every file and folder in it, now and
        later), and with `change` make, write and remove there too. Added to what the folder grants already."""
        where = str(path)
        dacl, described = ctypes.c_void_p(None), ctypes.c_void_p(None)
        _done("GetNamedSecurityInfoW", self.api.GetNamedSecurityInfoW(
            where, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, ctypes.byref(dacl), None,
            ctypes.byref(described)))
        try:
            entry = ExplicitAccess(CHANGE if change else READ_AND_RUN, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                                   Trustee(None, 0, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, self.sid.value))
            new = ctypes.c_void_p(None)
            _done("SetEntriesInAclW", self.api.SetEntriesInAclW(1, ctypes.byref(entry), dacl, ctypes.byref(new)))
            try:
                # Windows hands the folder's new rights on to what is in it (the files already there too)
                _done("SetNamedSecurityInfoW", self.api.SetNamedSecurityInfoW(
                    where, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, new, None))
            finally:
                self.api.LocalFree(new)
        finally:
            self.api.LocalFree(described)

    def close(self) -> None:
        """Give the SID back and delete the profile, once each. Raises `ContainerError` when the profile stays."""
        sid, self.sid = self.sid, ctypes.c_void_p(None)
        if sid.value:
            self.api.FreeSid(sid)
        if self.made:
            self.made = False
            _done("DeleteAppContainerProfile", self.api.DeleteAppContainerProfile(self.name))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def sid_text(api, sid) -> str:
    """A SID as Windows writes it (`S-1-15-2-...` for a container)."""
    out = ctypes.c_void_p(None)
    _need(api, "ConvertSidToStringSidW", api.ConvertSidToStringSidW(sid, ctypes.byref(out)))
    try:
        return ctypes.wstring_at(out.value)
    finally:
        api.LocalFree(out)


def _inherited_handles(api) -> list:
    """The program's own standard handles, each once and each to be inherited (the pipes `lantern.sandbox` reads)."""
    handles: list = []
    for which in STD_HANDLES:
        h = api.GetStdHandle(which)
        if not h or h == INVALID_HANDLE or h in handles:
            continue
        flags = _DWORD(0)
        _need(api, "GetHandleInformation", api.GetHandleInformation(h, ctypes.byref(flags)))
        if not flags.value & HANDLE_FLAG_INHERIT:
            _need(api, "SetHandleInformation", api.SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
        handles.append(h)
    return handles


def start(container: str, cmd: list[str], api=None) -> int:
    """Run `cmd` in the container whose SID is `container` (as text), with this program's standard handles, its
    environment and its folder; wait for it, and return its result. Nothing else of this program is handed on."""
    api = api if api is not None else _Api()
    sid = ctypes.c_void_p(None)
    _need(api, "ConvertStringSidToSidW", api.ConvertStringSidToSidW(container, ctypes.byref(sid)))
    try:
        caps = SecurityCapabilities(sid.value, None, 0, 0)
        handles = _inherited_handles(api)
        size = ctypes.c_size_t(0)
        api.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))     # asks how much room the list takes
        if not size.value:
            raise ContainerError("InitializeProcThreadAttributeList", api.last_error())
        room = (ctypes.c_byte * size.value)()
        _need(api, "InitializeProcThreadAttributeList",
              api.InitializeProcThreadAttributeList(room, 2, 0, ctypes.byref(size)))
        info = ProcessInformation()
        try:
            _need(api, "UpdateProcThreadAttribute", api.UpdateProcThreadAttribute(
                room, 0, ATTRIBUTE_SECURITY_CAPABILITIES, ctypes.byref(caps), ctypes.sizeof(caps), None, None))
            listed = (_HANDLE * max(1, len(handles)))(*handles)
            if handles:     # only these are inherited, whatever else this program holds that could be
                _need(api, "UpdateProcThreadAttribute", api.UpdateProcThreadAttribute(
                    room, 0, ATTRIBUTE_HANDLE_LIST, listed, ctypes.sizeof(_HANDLE) * len(handles), None, None))
            si = StartupInfoEx()
            si.StartupInfo.cb = ctypes.sizeof(StartupInfoEx)
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
            si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = (
                api.GetStdHandle(which) for which in STD_HANDLES)
            si.lpAttributeList = ctypes.cast(room, ctypes.c_void_p)
            line = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmd))
            _need(api, "CreateProcessW", api.CreateProcessW(
                None, line, None, None, bool(handles), EXTENDED_STARTUPINFO_PRESENT, None, None, ctypes.byref(si),
                ctypes.byref(info)))
        finally:
            api.DeleteProcThreadAttributeList(room)
        api.CloseHandle(info.hThread)
        try:
            if api.WaitForSingleObject(info.hProcess, INFINITE) == WAIT_FAILED:
                raise ContainerError("WaitForSingleObject", api.last_error())
            code = _DWORD(0)
            _need(api, "GetExitCodeProcess", api.GetExitCodeProcess(info.hProcess, ctypes.byref(code)))
            return code.value
        finally:
            api.CloseHandle(info.hProcess)
    finally:
        api.LocalFree(sid)


def rows_at(raw: bytes, row: int, at: int, who: int, port: int) -> set[int] | None:
    """The programs of the rows of one of Windows' tables of this computer's sockets (`raw`: its number of rows, then
    the rows) whose port is `port`, or None where the table is not as long as it says."""
    n = int.from_bytes(raw[:4], "little")
    if 4 + n * row > len(raw):
        return None
    return {int.from_bytes(raw[o + who:o + who + 4], "little") for o in range(4, 4 + n * row, row)
            if int.from_bytes(raw[o + at:o + at + 2], "big") == port}


def owners(api, port: int, dgram: bool) -> set[int] | None:
    """The programs (by number) that hold this computer's sockets at `port`, as Windows' own tables of them say:
    listeners, or (`dgram`) datagram sockets, of either family. None where Windows does not say."""
    call = api.GetExtendedUdpTable if dgram else api.GetExtendedTcpTable
    found: set[int] = set()
    for family in (2, 23):
        row, at, who = ROWS[(dgram, family)]
        size, raw, got = _DWORD(0), None, 0
        for _ in range(8):
            room = (ctypes.c_char * max(size.value, 8))()
            got = call(room, ctypes.byref(size), False, family, UDP_OWNERS if dgram else TCP_LISTENERS, 0)
            if got == 0:
                raw = room.raw
                break
            if got != INSUFFICIENT_BUFFER:      # else the table grew since its size was asked
                break
        if raw is None:
            if family == 23 and got == NOT_SUPPORTED:
                continue
            return None
        these = rows_at(raw, row, at, who, port)
        if these is None:
            return None
        found |= these
    return found


def job_pids(api) -> set[int] | None:
    """The programs of this program's own job, as Windows lists them (the launcher's job is the run's: nothing
    started in it can leave it). None where Windows does not say."""
    ptr, n = ctypes.sizeof(ctypes.c_void_p), 64
    for _ in range(6):
        size = 8 + n * ptr
        room = (ctypes.c_char * size)()
        if api.QueryInformationJobObject(None, JOB_PROCESS_IDS, room, size, None):
            raw = room.raw
            listed = int.from_bytes(raw[4:8], "little")
            if 8 + listed * ptr > len(raw):
                return None
            return {int.from_bytes(raw[8 + i * ptr:8 + (i + 1) * ptr], "little") for i in range(listed)}
        if api.last_error() != MORE_DATA:       # else more programs than the list could hold
            return None
        n *= 4
    return None


def answer(question: bytes, owners_of, pids) -> bytes:
    """The broker's answer to one question (`QUESTION` bytes): `YES` when Windows names a program holding a socket
    of that kind at that port and every such program is one of the run's job (`owners_of(port, dgram)`, `pids()`),
    else `NO`, also for a question of any other shape and where Windows does not say."""
    if len(question) != QUESTION or question[:1] not in (b"t", b"u"):
        return NO
    port = int.from_bytes(question[1:], "big")
    if not port:
        return NO
    found = owners_of(port, question[:1] == b"u")
    if not found:
        return NO
    mine = pids()
    return YES if mine and found <= mine else NO


def broker_name(name: str) -> bool:
    """Is `name` a broker's name as `lantern.sandbox` makes one (`BROKER_PREFIX` and 32 hexadecimal digits)?"""
    rest = name[len(BROKER_PREFIX):] if name.startswith(BROKER_PREFIX) else ""
    return len(rest) == 32 and all(c in "0123456789abcdef" for c in rest)


class Broker:
    """The pipe through which the launcher answers the guard inside the container whose a port of this computer is
    (`answer`), with `BROKER_ENDS` ends, each in a thread of its own for as long as the launcher runs. Its rights
    (`BROKER_RIGHTS`) let the container open an end and nothing more, and the first end is made with
    FILE_FLAG_FIRST_PIPE_INSTANCE, so a pipe of that name that somebody made before is refused, not shared. An end
    that Windows refuses to wait on `GIVE_UP` times in a row, `PAUSE` seconds apart, stops answering (the guard
    then takes no answer as a no)."""

    PAUSE = 0.05
    GIVE_UP = 50

    def __init__(self, name: str, sid: str, api=None):
        self.api = api if api is not None else _Api()
        self.name, self.ends, self.threads = name, [], []
        described = ctypes.c_void_p(None)
        _need(self.api, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
              self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                  BROKER_RIGHTS.format(sid=sid), SDDL_REVISION_1, ctypes.byref(described), None))
        self._described = described
        self._attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), described.value, False)
        try:
            for _ in range(BROKER_ENDS):
                h = self.api.CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | (0 if self.ends else FIRST_PIPE_INSTANCE),
                                              REJECT_REMOTE_CLIENTS, BROKER_ENDS, 64, 64, 0,
                                              ctypes.byref(self._attributes))
                if not h or h == INVALID_HANDLE:
                    raise ContainerError("CreateNamedPipeW", self.api.last_error())
                self.ends.append(h)
        except BaseException:
            for h in self.ends:
                self.api.CloseHandle(h)
            self.api.LocalFree(described)
            raise
        for h in self.ends:
            self.threads.append(threading.Thread(target=self._serve, args=(h,), daemon=True))
            self.threads[-1].start()

    def _read(self, h) -> bytes:
        got = b""
        while len(got) < QUESTION:
            room, n = ctypes.create_string_buffer(QUESTION - len(got)), _DWORD(0)
            if not self.api.ReadFile(h, room, len(room), ctypes.byref(n), None) or not n.value:
                break
            got += room.raw[:n.value]
        return got

    def _serve(self, h) -> None:
        api, failed = self.api, 0
        while failed < self.GIVE_UP:
            if not api.ConnectNamedPipe(h, None):
                error = api.last_error()
                if error == NO_DATA:            # the caller has gone again: the end is made ready for the next
                    api.DisconnectNamedPipe(h)
                    continue
                if error != PIPE_CONNECTED:
                    failed += 1
                    time.sleep(self.PAUSE)
                    continue
            failed = 0
            try:
                said = answer(self._read(h), lambda port, dgram: owners(api, port, dgram), lambda: job_pids(api))
                out, n = ctypes.create_string_buffer(said, len(said)), _DWORD(0)
                if api.WriteFile(h, out, len(said), ctypes.byref(n), None):
                    api.FlushFileBuffers(h)         # until the guard has read it
            finally:
                api.DisconnectNamedPipe(h)


def _exit_code(code: int) -> int:
    """A Windows result (a DWORD) as the number `sys.exit` hands Windows back unchanged."""
    return code - (1 << 32) if code >= 1 << 31 else code


def main(argv: list[str]) -> None:
    """`<container SID> -- <command...>`: the command, run in the container; this program ends with its result.
    Where `BROKER_VARIABLE` names a pipe, the broker answers there for as long as the command runs, and the command
    is told which program made it (`BROKER_PID_VARIABLE`)."""
    if len(argv) < 3 or argv[1] != "--":
        print(f"{MARK} container 87", flush=True)      # ERROR_INVALID_PARAMETER
        sys.exit(UNAVAILABLE)
    try:
        name = os.environ.get(BROKER_VARIABLE, "")
        if name:
            if not broker_name(name):
                raise ContainerError("CreateNamedPipeW", 123)    # ERROR_INVALID_NAME
            Broker(name, argv[0])
            os.environ[BROKER_PID_VARIABLE] = str(os.getpid())   # in the environment the command is started with
        code = start(argv[0], argv[2:])
    except ContainerError as e:
        print(f"{MARK} container {e.code}", flush=True)
        sys.exit(UNAVAILABLE)
    sys.exit(_exit_code(code))
