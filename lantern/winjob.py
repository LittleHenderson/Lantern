"""The Windows Job Object the test sandbox runs a project's tests in, with every call checked.

`lantern.sandbox` runs a project's own tests in a restricted process. On Windows the part of that restriction the
operating system itself keeps is a Job Object: the memory of the tests and of everything they started, counted
together, and one handle through which every process the tests started, however deep, can be ended. Used by
`sandbox._stream` like this:

    job = Job(memory)              # CreateJobObjectW, CreateIoCompletionPort, SetInformationJobObject (three times)
    proc = subprocess.Popen(cmd, creationflags=SUSPENDED | ...)    # made, but it has not run one instruction
    job.take(proc.pid)             # AssignProcessToJobObject, then IsProcessInJob to see that it is so
    job.release(proc.pid)          # the process runs from here (ResumeThread on its thread)
    ...
    job.over_memory()              # GetQueuedCompletionStatus: has Windows said the job went over its memory?
    job.stop()                     # TerminateJobObject: every process in the job, children of children too
    job.count()                    # how many are still there (0 once they are gone)
    job.close()                    # what the port still holds is read, then CloseHandle, once for each handle

The memory (a firm pass or fail, stage 4, 2026-11-20) is what Windows has given the job's programs together (their
commit: memory a program asked for counts when it asks, written to or not). Windows tells the job's port when it
goes over `memory`, a notification limit, whose message Windows promises to deliver; `sandbox._stream` then ends
the run and says it was over its memory, never that its tests failed. Beneath that a wall (`wall`: twice the
limit, and at least 1 GB above it) keeps a program that asks for very much at once from taking the computer's
memory before the run is ended; Windows refuses such a request and tells the port where it can (it does not
promise that message). Until then the limit was the job's limit for each process alone: tests whose programs went
over it together were not stopped, and a program that went over it alone was refused memory, so its tests failed
and the run read as failed.

The process is put in the job before it runs, so nothing it starts is outside the job: a process started by a
member of a job belongs to that job (the job does not allow "breakaway"). Until 2026-11-10 the process was put in
the job after it had started (what it had started by then stayed outside: a virtual environment's `python.exe`
starts the real interpreter as a child at once), no call's result was read, a failure was swallowed and the tests
ran without the job, and the job's handle was never closed.

Every result is read here. A call that fails raises `JobError`, which names the call and Windows' error number;
`sandbox._stream` then ends the process, which has not run, and the tests are not run (`sandbox.Unavailable`).

Only documented calls of kernel32 are used. `k32` stands for that library, so the tests can hand in a stand-in on
any system (tests/test_sandbox_safety.py); the real one is loaded only on Windows.
"""

from __future__ import annotations

import ctypes

# CreateProcess: the new process's first thread waits until ResumeThread
SUSPENDED = 0x00000004

KILL_ON_JOB_CLOSE = 0x00002000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
PROCESS_MEMORY = 0x00000100             # JOB_OBJECT_LIMIT_PROCESS_MEMORY (not used since 2026-11-20)
JOB_MEMORY = 0x00000200                 # JOB_OBJECT_LIMIT_JOB_MEMORY: the job's programs together
BASIC_ACCOUNTING = 1                    # JobObjectBasicAccountingInformation
ASSOCIATE_PORT = 7                      # JobObjectAssociateCompletionPortInformation
EXTENDED_LIMIT = 9                      # JobObjectExtendedLimitInformation
NOTIFICATION_LIMIT = 12                 # JobObjectNotificationLimitInformation
# what Windows tells the port (GetQueuedCompletionStatus hands the message's number as "bytes transferred")
MSG_PROCESS_MEMORY_LIMIT = 9            # JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT
MSG_JOB_MEMORY_LIMIT = 10               # JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: a request refused at the wall
MSG_NOTIFICATION_LIMIT = 11             # JOB_OBJECT_MSG_NOTIFICATION_LIMIT: over the one notification limit set here
MEMORY_MESSAGES = (MSG_PROCESS_MEMORY_LIMIT, MSG_JOB_MEMORY_LIMIT, MSG_NOTIFICATION_LIMIT)
WAIT_TIMEOUT = 258                      # what GetQueuedCompletionStatus says when the port holds nothing
TOLERANCE_LOW = 1                       # ToleranceLow, ToleranceIntervalShort: valid values for fields not used here
# what the calls below need of the process: assign (SET_QUOTA, TERMINATE), IsProcessInJob (QUERY_LIMITED_INFORMATION)
PROCESS_RIGHTS = 0x0100 | 0x0001 | 0x1000
THREAD_SUSPEND_RESUME = 0x0002
SNAPTHREAD = 0x00000004                 # TH32CS_SNAPTHREAD
NO_MORE_FILES = 18                      # ERROR_NO_MORE_FILES: how Thread32Next says the list has ended
INVALID_HANDLE = ctypes.c_void_p(-1).value
RESUME_FAILED = 0xFFFFFFFF              # ResumeThread's (DWORD)-1

_DWORD = ctypes.c_uint32                # c_ulong is four bytes on Windows only; these structures are read by tests anywhere
_BOOL = ctypes.c_int
_HANDLE = ctypes.c_void_p


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                               "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", _DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", _DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD)]


class ExtendedLimits(ctypes.Structure):
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION"""
    _fields_ = [("Basic", _BasicLimits), ("Io", _IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


class NotificationLimits(ctypes.Structure):
    """JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION"""
    _fields_ = [("IoReadBytesLimit", ctypes.c_uint64), ("IoWriteBytesLimit", ctypes.c_uint64),
                ("PerJobUserTimeLimit", ctypes.c_int64), ("JobMemoryLimit", ctypes.c_uint64),
                ("RateControlTolerance", ctypes.c_int32), ("RateControlToleranceInterval", ctypes.c_int32),
                ("LimitFlags", _DWORD)]


class PortLink(ctypes.Structure):
    """JOBOBJECT_ASSOCIATE_COMPLETION_PORT"""
    _fields_ = [("CompletionKey", ctypes.c_void_p), ("CompletionPort", _HANDLE)]


class Accounting(ctypes.Structure):
    """JOBOBJECT_BASIC_ACCOUNTING_INFORMATION"""
    _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", _DWORD), ("TotalProcesses", _DWORD), ("ActiveProcesses", _DWORD),
                ("TotalTerminatedProcesses", _DWORD)]


class ThreadEntry(ctypes.Structure):
    """THREADENTRY32"""
    _fields_ = [("dwSize", _DWORD), ("cntUsage", _DWORD), ("th32ThreadID", _DWORD), ("th32OwnerProcessID", _DWORD),
                ("tpBasePri", ctypes.c_int32), ("tpDeltaPri", ctypes.c_int32), ("dwFlags", _DWORD)]


class JobError(OSError):
    """A call of the job failed. `call` is its name, `code` Windows' error number (0 when the call itself succeeded
    and its answer was the wrong one)."""

    def __init__(self, call: str, code: int, why: str = ""):
        self.call, self.code = call, int(code or 0)
        super().__init__(f"{call} failed (Windows error {self.code})" if not why else f"{call}: {why}")


class _Kernel32:
    """kernel32's functions as this module calls them, each with its argument and result types declared (without
    them ctypes passes a handle as a 32-bit number, which cuts a 64-bit handle short)."""

    CALLS = (("CreateJobObjectW", _HANDLE, [ctypes.c_void_p, ctypes.c_wchar_p]),
             ("SetInformationJobObject", _BOOL, [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD]),
             ("QueryInformationJobObject", _BOOL, [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD, ctypes.c_void_p]),
             ("OpenProcess", _HANDLE, [_DWORD, _BOOL, _DWORD]),
             ("AssignProcessToJobObject", _BOOL, [_HANDLE, _HANDLE]),
             ("IsProcessInJob", _BOOL, [_HANDLE, _HANDLE, ctypes.POINTER(_BOOL)]),
             ("TerminateJobObject", _BOOL, [_HANDLE, ctypes.c_uint]),
             ("CloseHandle", _BOOL, [_HANDLE]),
             ("CreateToolhelp32Snapshot", _HANDLE, [_DWORD, _DWORD]),
             ("Thread32First", _BOOL, [_HANDLE, ctypes.c_void_p]),
             ("Thread32Next", _BOOL, [_HANDLE, ctypes.c_void_p]),
             ("OpenThread", _HANDLE, [_DWORD, _BOOL, _DWORD]),
             ("ResumeThread", _DWORD, [_HANDLE]),
             ("CreateIoCompletionPort", _HANDLE, [_HANDLE, _HANDLE, ctypes.c_size_t, _DWORD]),
             ("GetQueuedCompletionStatus", _BOOL, [_HANDLE, ctypes.POINTER(_DWORD), ctypes.POINTER(ctypes.c_size_t),
                                                   ctypes.POINTER(ctypes.c_void_p), _DWORD]))

    def __init__(self):
        dll = ctypes.WinDLL("kernel32", use_last_error=True)    # Windows only: this class is made nowhere else
        for name, result, arguments in self.CALLS:
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = result, arguments
            setattr(self, name, fn)

    @staticmethod
    def last_error() -> int:
        return ctypes.get_last_error()


def wall(memory: int) -> int:
    """The bytes the job's programs together are refused beyond: twice the limit, and at least 1 GB above it, so that
    a program that asks for much at once is stopped by the limit's message rather than refused by the wall."""
    return max(2 * memory, memory + (1 << 30))


class Job:
    """One Job Object: `memory` bytes for its programs together (Windows tells the job's port when they go over, and
    refuses them beyond `wall(memory)`), and every process ends when it is stopped or closed."""

    def __init__(self, memory: int = 2 << 30, k32=None):
        self.k32 = k32 if k32 is not None else _Kernel32()
        self.handle = self.port = None
        self.memory, self.refused = memory, False
        self.handle = self._need("CreateJobObjectW", self.k32.CreateJobObjectW(None, None))
        try:
            # the port first, so that nothing Windows tells the job is lost
            port = self.k32.CreateIoCompletionPort(INVALID_HANDLE, None, 0, 1)
            self.port = self._need("CreateIoCompletionPort", port)
            link = PortLink(None, self.port)
            self._set("SetInformationJobObject", ASSOCIATE_PORT, link)
            info = ExtendedLimits()
            info.Basic.LimitFlags = KILL_ON_JOB_CLOSE | JOB_MEMORY
            info.JobMemoryLimit = wall(memory)
            self._set("SetInformationJobObject", EXTENDED_LIMIT, info)
            note = NotificationLimits()
            note.LimitFlags, note.JobMemoryLimit = JOB_MEMORY, memory
            note.RateControlTolerance = note.RateControlToleranceInterval = TOLERANCE_LOW
            self._set("SetInformationJobObject", NOTIFICATION_LIMIT, note)
        except BaseException:
            self.close()
            raise

    def _set(self, call: str, kind: int, info) -> None:
        self._need(call, self.k32.SetInformationJobObject(self.handle, kind, ctypes.byref(info), ctypes.sizeof(info)))

    def _need(self, call: str, result):
        if not result:
            raise JobError(call, self.k32.last_error())
        return result

    def take(self, pid: int) -> None:
        """Put the process in the job, and see that it is there."""
        process = self._need("OpenProcess", self.k32.OpenProcess(PROCESS_RIGHTS, 0, pid))
        try:
            self._need("AssignProcessToJobObject", self.k32.AssignProcessToJobObject(self.handle, process))
            inside = _BOOL(0)
            self._need("IsProcessInJob", self.k32.IsProcessInJob(process, self.handle, ctypes.byref(inside)))
            if not inside.value:
                raise JobError("IsProcessInJob", 0, "Windows says the process is not in the job it was put in")
        finally:
            self.k32.CloseHandle(process)

    def release(self, pid: int) -> int:
        """Let a process that was made suspended run. Returns how many of its threads were resumed (one, for a
        process that has not run yet)."""
        snapshot = self.k32.CreateToolhelp32Snapshot(SNAPTHREAD, 0)
        if not snapshot or snapshot == INVALID_HANDLE:
            raise JobError("CreateToolhelp32Snapshot", self.k32.last_error())
        resumed = 0
        try:
            entry = ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            more = self.k32.Thread32First(snapshot, ctypes.byref(entry))
            if not more:
                raise JobError("Thread32First", self.k32.last_error())
            while more:
                if entry.th32OwnerProcessID == pid:
                    thread = self._need("OpenThread", self.k32.OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID))
                    try:
                        for _ in range(64):     # a thread suspended more than once needs as many resumes
                            before = self.k32.ResumeThread(thread)
                            if before == RESUME_FAILED:
                                raise JobError("ResumeThread", self.k32.last_error())
                            if before <= 1:
                                break
                        resumed += 1
                    finally:
                        self.k32.CloseHandle(thread)
                more = self.k32.Thread32Next(snapshot, ctypes.byref(entry))
            code = self.k32.last_error()
            if code not in (0, NO_MORE_FILES):
                raise JobError("Thread32Next", code)
        finally:
            self.k32.CloseHandle(snapshot)
        if not resumed:
            raise JobError("Thread32Next", 0, f"no thread of process {pid} was found, so it was not started")
        return resumed

    def count(self) -> int:
        """How many processes are running in the job now."""
        info = Accounting()
        self._need("QueryInformationJobObject",
                   self.k32.QueryInformationJobObject(self.handle, BASIC_ACCOUNTING, ctypes.byref(info), ctypes.sizeof(info), None))
        return int(info.ActiveProcesses)

    def over_memory(self) -> bool:
        """Whether Windows has told the job's port that its programs together went over `memory`, or that one of
        them was refused memory at the wall. Every message the port holds is read and taken off it (it is also told
        of each program that starts and ends); once true it stays true."""
        while self.port and not self.refused:
            what, key, where = _DWORD(0), ctypes.c_size_t(0), ctypes.c_void_p(None)
            if not self.k32.GetQueuedCompletionStatus(self.port, ctypes.byref(what), ctypes.byref(key),
                                                      ctypes.byref(where), 0):
                code = self.k32.last_error()
                if code == WAIT_TIMEOUT and not where.value:
                    break                     # nothing more
                raise JobError("GetQueuedCompletionStatus", code)
            if what.value in MEMORY_MESSAGES:
                self.refused = True
        return self.refused

    def stop(self) -> None:
        """End every process in the job."""
        if self.handle:
            self._need("TerminateJobObject", self.k32.TerminateJobObject(self.handle, 1))

    def close(self) -> None:
        """Give the handles back, once each, after reading what the port still holds (Windows may tell of the memory
        as the run ends). The job is set to end its processes when its last handle closes."""
        try:
            self.over_memory()
        except OSError:
            pass                              # what it would have said is lost; the handles still go back
        port, self.port = self.port, None
        handle, self.handle = self.handle, None
        if port:
            self.k32.CloseHandle(port)
        if handle:
            self.k32.CloseHandle(handle)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
