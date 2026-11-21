"""Start a program on Windows with descriptors 3 and 4 handed over, inside a Job Object, with every call checked (a
firm pass or fail, stage 5, the browser checks: docs/browser.md).

A browser of the Chromium family told `--remote-debugging-pipe` reads what it is told from its descriptor 3 and writes
its answers to its descriptor 4. On Windows a descriptor is the C library's own number for a handle, and the C library
hands its descriptors to a program it starts in the startup information's `lpReserved2` (the protocol of Microsoft's C
library: a 32-bit count, then one flag byte per descriptor, then one handle per descriptor; `crt_block`), which the
new program's C library reads before its `main`. Python's `subprocess` cannot write that block, so this module calls
`CreateProcessW` itself:

    start(argv, env=..., cwd=..., fds={0: (h, FOPEN | FDEV), ..., 3: (h, FOPEN | FPIPE), 4: (...)}, job=job)

* Only the handles named in `fds` are handed over (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), however many of this
  program's own handles can be inherited at that moment, each once (`handle_list`).
* The program is made suspended, put in `job` (`winjob.Job.take`: `AssignProcessToJobObject`, then `IsProcessInJob`)
  and only then let run (`ResumeThread`), so nothing it starts is outside the job: everything ends with `job.stop()`
  or when the job's last handle closes (`KILL_ON_JOB_CLOSE`).
* It gets the environment it is given and nothing of this program's (`env_block`), no console, and a process group of
  its own.

Every result is read. A call that fails raises `SpawnError` (the call and Windows' error number); a program that was
made and could not be put in the job, or not let run, is ended before it runs one instruction, and every handle and the
attribute list are given back on every path. `k32` stands for kernel32 so the tests can hand in a stand-in on any
system (tests/test_winspawn.py); the real one is loaded only on Windows."""

from __future__ import annotations

import ctypes
import struct
import subprocess

# the C library's flags for a descriptor it hands over (lowio: FOPEN, FPIPE, FDEV)
FOPEN, FPIPE, FDEV = 0x01, 0x08, 0x40

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
FLAGS = (CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
         | CREATE_NO_WINDOW)
STARTF_USESTDHANDLES = 0x00000100
HANDLE_LIST = 0x00020002                # PROC_THREAD_ATTRIBUTE_HANDLE_LIST
INSUFFICIENT_BUFFER = 122               # ERROR_INSUFFICIENT_BUFFER: what the first call for the list's size says
WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED = 0, 0x102, 0xFFFFFFFF
INFINITE = 0xFFFFFFFF
RESUME_FAILED = 0xFFFFFFFF              # ResumeThread's (DWORD)-1
MOST_DESCRIPTORS = 5                    # 0, 1, 2 and the pipe's two ends
INVALID_HANDLE = ctypes.c_void_p(-1).value

_DWORD = ctypes.c_uint32                # c_ulong is four bytes on Windows only; these structures are read by tests anywhere
_WORD = ctypes.c_uint16
_BOOL = ctypes.c_int
_HANDLE = ctypes.c_void_p


class StartupInfo(ctypes.Structure):
    """STARTUPINFOW"""
    _fields_ = [("cb", _DWORD), ("lpReserved", ctypes.c_void_p), ("lpDesktop", ctypes.c_void_p),
                ("lpTitle", ctypes.c_void_p), ("dwX", _DWORD), ("dwY", _DWORD), ("dwXSize", _DWORD),
                ("dwYSize", _DWORD), ("dwXCountChars", _DWORD), ("dwYCountChars", _DWORD),
                ("dwFillAttribute", _DWORD), ("dwFlags", _DWORD), ("wShowWindow", _WORD), ("cbReserved2", _WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", _HANDLE), ("hStdOutput", _HANDLE),
                ("hStdError", _HANDLE)]


class StartupInfoEx(ctypes.Structure):
    """STARTUPINFOEXW"""
    _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


class ProcessInformation(ctypes.Structure):
    """PROCESS_INFORMATION"""
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE), ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


class SpawnError(OSError):
    """A call failed. `call` is its name, `code` Windows' error number (0 when the call itself succeeded and its answer
    was the wrong one)."""

    def __init__(self, call: str, code: int, why: str = ""):
        self.call, self.code = call, int(code or 0)
        super().__init__(f"{call} failed (Windows error {self.code})" if not why else f"{call}: {why}")


class _Kernel32:
    """kernel32's functions as this module calls them, each with its argument and result types declared (without
    them ctypes passes a handle as a 32-bit number, which cuts a 64-bit handle short)."""

    CALLS = (("CreateProcessW", _BOOL, [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, _BOOL,
                                        _DWORD, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p]),
             ("InitializeProcThreadAttributeList", _BOOL, [ctypes.c_void_p, _DWORD, _DWORD,
                                                           ctypes.POINTER(ctypes.c_size_t)]),
             ("UpdateProcThreadAttribute", _BOOL, [ctypes.c_void_p, _DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                                   ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]),
             ("DeleteProcThreadAttributeList", None, [ctypes.c_void_p]),
             ("ResumeThread", _DWORD, [_HANDLE]),
             ("TerminateProcess", _BOOL, [_HANDLE, ctypes.c_uint]),
             ("WaitForSingleObject", _DWORD, [_HANDLE, _DWORD]),
             ("GetExitCodeProcess", _BOOL, [_HANDLE, ctypes.POINTER(_DWORD)]),
             ("CloseHandle", _BOOL, [_HANDLE]))

    def __init__(self):
        dll = ctypes.WinDLL("kernel32", use_last_error=True)    # Windows only: this class is made nowhere else
        for name, result, arguments in self.CALLS:
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = result, arguments
            setattr(self, name, fn)

    @staticmethod
    def last_error() -> int:
        return ctypes.get_last_error()


def crt_block(fds: dict[int, tuple[int, int]], size: int | None = None) -> bytes:
    """The C library's block of descriptors 0 to the highest one in `fds` ({descriptor: (handle, flags)}): the count,
    a flag byte for each, a handle for each (`size` bytes; a descriptor not named is no descriptor: flags 0 and the
    handle that is none)."""
    size = size or ctypes.sizeof(ctypes.c_void_p)
    if size not in (4, 8):
        raise ValueError("a handle is four or eight bytes")
    if not fds or min(fds) < 0 or max(fds) >= MOST_DESCRIPTORS:
        raise ValueError(f"descriptors from 0 to {MOST_DESCRIPTORS - 1} only")
    count = max(fds) + 1
    none = (1 << (8 * size)) - 1
    flags = [fds[i][1] if i in fds else 0 for i in range(count)]
    handles = [fds[i][0] if i in fds else none for i in range(count)]
    if any(not 0 <= f <= 0xFF for f in flags) or any(not h or not 0 < h <= none for h in handles):
        raise ValueError("a flag is one byte, and a descriptor named has a handle")
    return struct.pack(f"<i{count}B{count}{'Q' if size == 8 else 'I'}", count, *flags, *handles)


def handle_list(fds: dict[int, tuple[int, int]]) -> list[int]:
    """The handles the program inherits: each handle of `fds` once, in the order of the descriptors (Windows refuses
    a list that names one twice)."""
    seen: list[int] = []
    for i in sorted(fds):
        handle = fds[i][0]
        if handle not in seen:
            seen.append(handle)
    return seen


def env_block(env: dict[str, str]) -> str:
    """The environment as Windows takes it (`CREATE_UNICODE_ENVIRONMENT`): each `name=value` ended by a NUL, sorted by
    name without regard to case, and one more NUL (two for an empty one: Windows reads a block up to its first two
    NULs). Nothing of this program's own environment is added."""
    lines = []
    for name, value in sorted(env.items(), key=lambda kv: kv[0].upper()):
        if not name or "=" in name or "\0" in name or "\0" in value:
            raise ValueError("an environment variable's name has no '=' and neither part has a NUL")
        lines.append(f"{name}={value}\0")
    return "".join(lines) + "\0" if lines else "\0\0"


class Process:
    """A program `start` made: `pid`, `poll()`, `wait(timeout)`, `kill()` and `close()` as `subprocess.Popen` has
    them, on the process handle Windows gave."""

    def __init__(self, handle: int, pid: int, args: list[str], k32):
        self.handle, self.pid, self.args, self.k32 = handle, pid, list(args), k32
        self.returncode: int | None = None

    def _need(self, call: str, result):
        if not result:
            raise SpawnError(call, self.k32.last_error())
        return result

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        if not self.handle:
            raise SpawnError("WaitForSingleObject", 0, "the process handle was given back")
        ms = INFINITE if timeout is None else max(0, min(int(timeout * 1000), INFINITE - 1))
        said = self.k32.WaitForSingleObject(self.handle, ms)
        if said == WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.args, timeout)
        if said != WAIT_OBJECT_0:
            raise SpawnError("WaitForSingleObject", self.k32.last_error() if said == WAIT_FAILED else 0,
                             "" if said == WAIT_FAILED else f"it answered {said}")
        code = _DWORD(0)
        self._need("GetExitCodeProcess", self.k32.GetExitCodeProcess(self.handle, ctypes.byref(code)))
        self.returncode = int(code.value)
        return self.returncode

    def poll(self) -> int | None:
        try:
            return self.wait(0)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        if self.returncode is None and self.handle:
            self._need("TerminateProcess", self.k32.TerminateProcess(self.handle, 1))

    def close(self) -> None:
        """Give the process handle back, once."""
        handle, self.handle = self.handle, None
        if handle:
            self.k32.CloseHandle(handle)


def start(argv: list[str], *, env: dict[str, str], cwd: str, fds: dict[int, tuple[int, int]], job,
          k32=None) -> Process:
    """Start `argv[0]` (a full path) with `argv`, handing it `fds` ({descriptor: (handle, flags)}, 0 to 4; every
    handle already inheritable, 0, 1 and 2 its standard handles), in the folder `cwd`, with only `env` for its
    environment; put it in `job` before it runs; let it run. SpawnError (or the job's JobError) when any of that
    fails, after the program, if one was made, was ended."""
    k32 = k32 if k32 is not None else _Kernel32()
    if not all(i in fds for i in (0, 1, 2)):
        raise ValueError("descriptors 0, 1 and 2 are the program's standard handles and are always named")
    block = crt_block(fds)
    reserved = ctypes.create_string_buffer(block, len(block))
    inherit = handle_list(fds)
    handles = (_HANDLE * len(inherit))(*inherit)
    command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
    environment = ctypes.create_unicode_buffer(env_block(env))

    info = StartupInfoEx()
    info.StartupInfo.cb = ctypes.sizeof(info)
    info.StartupInfo.dwFlags = STARTF_USESTDHANDLES
    info.StartupInfo.hStdInput, info.StartupInfo.hStdOutput, info.StartupInfo.hStdError = \
        fds[0][0], fds[1][0], fds[2][0]
    info.StartupInfo.cbReserved2 = len(block)
    info.StartupInfo.lpReserved2 = ctypes.cast(reserved, ctypes.c_void_p).value

    size = ctypes.c_size_t(0)
    if k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size)) or \
            k32.last_error() != INSUFFICIENT_BUFFER or not size.value:
        raise SpawnError("InitializeProcThreadAttributeList", k32.last_error(), "it did not say the list's size")
    attributes = ctypes.create_string_buffer(size.value)
    if not k32.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)):
        raise SpawnError("InitializeProcThreadAttributeList", k32.last_error())
    made = ProcessInformation()
    try:
        if not k32.UpdateProcThreadAttribute(attributes, 0, HANDLE_LIST, handles, ctypes.sizeof(handles), None, None):
            raise SpawnError("UpdateProcThreadAttribute", k32.last_error())
        info.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p).value
        if not k32.CreateProcessW(argv[0], command, None, None, 1, FLAGS, environment, cwd, ctypes.byref(info),
                                  ctypes.byref(made)):
            raise SpawnError("CreateProcessW", k32.last_error())
    finally:
        k32.DeleteProcThreadAttributeList(attributes)
    try:
        job.take(made.dwProcessId)
        if k32.ResumeThread(made.hThread) == RESUME_FAILED:
            raise SpawnError("ResumeThread", k32.last_error())
    except BaseException:
        k32.TerminateProcess(made.hProcess, 1)      # it never ran: nothing of it is left
        k32.WaitForSingleObject(made.hProcess, 5000)
        k32.CloseHandle(made.hProcess)
        raise
    finally:
        k32.CloseHandle(made.hThread)
    return Process(made.hProcess, made.dwProcessId, argv, k32)
