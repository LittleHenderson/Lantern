"""How Lantern starts a program on Windows with descriptors 3 and 4 handed over, inside a Job Object
(`lantern.winspawn`; a firm pass or fail, stage 5, the browser checks: docs/browser.md).

On every system: a stand-in for kernel32 answers as Windows does, so the order of the calls, what each is handed and
every way one can fail are checked here; a failure gives back every handle and the attribute list, and a program that
was made and not put in its job, or not let run, is ended before it runs. On Windows itself: a real program is handed
the two ends of a pipe as its descriptors 3 and 4 by the C library's own protocol, inside a real job, and an
inheritable handle of Lantern's that is not named does not reach it."""

from __future__ import annotations

import ctypes
import json
import os
import struct
import subprocess
import sys
import threading
import time

import pytest

from lantern import winjob, winspawn
from lantern.winspawn import FDEV, FOPEN, FPIPE

POINTER = ctypes.sizeof(ctypes.c_void_p)
FDS = {0: (0x10, FOPEN | FDEV), 1: (0x14, FOPEN | FDEV), 2: (0x18, FOPEN), 3: (0x20, FOPEN | FPIPE),
       4: (0x24, FOPEN | FPIPE)}


class Kernel32:
    """What `winspawn` calls, answering as Windows does. `fail` names a call that fails (`code` is then what
    GetLastError says; "size" makes the first question for the attribute list's size go wrong); `waits` are what
    WaitForSingleObject answers, in order."""

    LIST_SIZE = 48

    def __init__(self, fail: str = "", code: int = 87, waits=(), exit_code: int = 0):
        self.fail, self.code, self.waits, self.exit_code = fail, code, list(waits), exit_code
        self.calls: list[str] = []
        self.open: set[int] = set()
        self.closed: list[int] = []
        self.lists = 0                  # attribute lists made and not yet given back
        self.list_at = None
        self.seen: dict = {}
        self._error, self._next = 0, 500

    def last_error(self) -> int:
        return self._error

    def _handle(self) -> int:
        self._next += 4
        self.open.add(self._next)
        return self._next

    def _said(self, name: str, result, failed=0):
        self.calls.append(name)
        if name == self.fail:
            self._error = self.code
            return failed
        self._error = 0
        return result

    def InitializeProcThreadAttributeList(self, attributes, count, flags, size):
        assert (count, flags) == (1, 0)
        if attributes is None:              # the question for the size: it fails and says the size
            self.calls.append("InitializeProcThreadAttributeList(size)")
            if self.fail == "size":
                self._error = 5
                return 0
            size._obj.value, self._error = self.LIST_SIZE, winspawn.INSUFFICIENT_BUFFER
            return 0
        assert ctypes.sizeof(attributes) >= self.LIST_SIZE and size._obj.value == self.LIST_SIZE
        made = self._said("InitializeProcThreadAttributeList", 1)
        if made:
            self.lists += 1
            self.list_at = ctypes.addressof(attributes)
        return made

    def UpdateProcThreadAttribute(self, attributes, flags, attribute, value, size, previous, returned):
        assert ctypes.addressof(attributes) == self.list_at and flags == 0 and previous is None and returned is None
        assert attribute == winspawn.HANDLE_LIST and size == ctypes.sizeof(value)
        self.seen["inherited"] = [int(h) for h in value]
        return self._said("UpdateProcThreadAttribute", 1)

    def DeleteProcThreadAttributeList(self, attributes):
        assert ctypes.addressof(attributes) == self.list_at
        self.calls.append("DeleteProcThreadAttributeList")
        self.lists -= 1

    def CreateProcessW(self, program, command, process_attrs, thread_attrs, inherit, flags, environment, cwd, info,
                       made):
        start = info._obj
        self.seen.update(
            program=program, command=command.value, inherit=inherit, flags=flags, environment=environment[:],
            cwd=cwd, cb=start.StartupInfo.cb, startup_flags=start.StartupInfo.dwFlags,
            std=(start.StartupInfo.hStdInput, start.StartupInfo.hStdOutput, start.StartupInfo.hStdError),
            block=ctypes.string_at(start.StartupInfo.lpReserved2, start.StartupInfo.cbReserved2),
            list_at=start.lpAttributeList, security=(process_attrs, thread_attrs))
        if not self._said("CreateProcessW", 1):
            return 0
        made._obj.hProcess, made._obj.hThread = self._handle(), self._handle()
        made._obj.dwProcessId, made._obj.dwThreadId = 4242, 4243
        self.seen["process"], self.seen["thread"] = made._obj.hProcess, made._obj.hThread
        return 1

    def ResumeThread(self, thread):
        assert thread == self.seen["thread"] and thread in self.open
        return self._said("ResumeThread", 1, winspawn.RESUME_FAILED)

    def TerminateProcess(self, process, code):
        assert process in self.open
        self.seen["ended"] = code
        return self._said("TerminateProcess", 1)

    def WaitForSingleObject(self, handle, ms):
        assert handle in self.open
        self.seen.setdefault("waited", []).append(ms)
        return self._said("WaitForSingleObject", self.waits.pop(0) if self.waits else winspawn.WAIT_OBJECT_0,
                          winspawn.WAIT_FAILED)

    def GetExitCodeProcess(self, process, code):
        assert process in self.open
        code._obj.value = self.exit_code
        return self._said("GetExitCodeProcess", 1)

    def CloseHandle(self, handle):
        assert handle in self.open, f"a handle closed twice, or one that was never given: {handle}"
        self.open.discard(handle)
        self.closed.append(handle)
        return self._said("CloseHandle", 1)


class Job:
    """A stand-in for `winjob.Job`: `take` is written into kernel32's own list of calls, so their order shows."""

    def __init__(self, k32: Kernel32, fail: bool = False):
        self.k32, self.fail, self.taken = k32, fail, []

    def take(self, pid: int) -> None:
        self.k32.calls.append("take")
        if self.fail:
            raise winjob.JobError("AssignProcessToJobObject", 5)
        self.taken.append(pid)


def _start(k32, job=None, fds=FDS, env=None):
    return winspawn.start([r"C:\Program Files\B\b.exe", "--x=a b", "about:blank"], env=env or {"SystemRoot": r"C:\W"},
                          cwd=r"C:\T\profile", fds=fds, job=job or Job(k32), k32=k32)


def test_the_structures_are_the_size_windows_reads():
    want = {8: (104, 112, 24), 4: (68, 72, 16)}[POINTER]
    assert (ctypes.sizeof(winspawn.StartupInfo), ctypes.sizeof(winspawn.StartupInfoEx),
            ctypes.sizeof(winspawn.ProcessInformation)) == want


def test_the_c_librarys_block_of_descriptors_byte_for_byte():
    # the protocol of Microsoft's C library: a 32-bit count, a flag byte per descriptor, a handle per descriptor,
    # packed (no padding), little-endian
    flags = bytes([0x41, 0x41, 0x01, 0x09, 0x09])
    eight = b"".join(h.to_bytes(8, "little") for h in (0x10, 0x14, 0x18, 0x20, 0x24))
    four = b"".join(h.to_bytes(4, "little") for h in (0x10, 0x14, 0x18, 0x20, 0x24))
    assert winspawn.crt_block(FDS, 8) == b"\x05\x00\x00\x00" + flags + eight
    assert winspawn.crt_block(FDS, 4) == b"\x05\x00\x00\x00" + flags + four
    assert len(winspawn.crt_block(FDS, 8)) == 4 + 5 + 5 * 8                 # 49: no padding anywhere
    assert winspawn.crt_block(FDS) == winspawn.crt_block(FDS, POINTER)
    # a descriptor not named is no descriptor: no flags, and the handle that is none
    without_3 = {k: v for k, v in FDS.items() if k != 3}
    block = winspawn.crt_block(without_3, 8)
    assert block[4:9] == bytes([0x41, 0x41, 0x01, 0x00, 0x09])
    assert struct.unpack_from("<Q", block, 9 + 3 * 8)[0] == 2 ** 64 - 1


@pytest.mark.parametrize("fds", [{}, {5: (0x10, FOPEN)}, {-1: (0x10, FOPEN)}, {0: (0x10, 0x100)},
                                 {0: (0, FOPEN)}, {0: (2 ** 64, FOPEN)}])
def test_a_block_that_would_name_what_is_no_descriptor_is_refused(fds):
    with pytest.raises(ValueError):
        winspawn.crt_block(fds, 8)


def test_each_handle_is_handed_over_once():
    # Windows refuses a list that names one handle twice; NUL may well be in and out
    same = {0: (7, FOPEN | FDEV), 1: (7, FOPEN | FDEV), 2: (9, FOPEN), 3: (11, FOPEN | FPIPE), 4: (12, FOPEN | FPIPE)}
    assert winspawn.handle_list(same) == [7, 9, 11, 12]
    assert winspawn.handle_list(FDS) == [0x10, 0x14, 0x18, 0x20, 0x24]


def test_the_environment_is_only_what_it_is_given(monkeypatch):
    monkeypatch.setenv("LANTERN_NOT_HANDED_ON", "this program's own")
    block = winspawn.env_block({"b": "2", "SystemRoot": r"C:\W", "A": "x=y"})
    assert block == "A=x=y\0b=2\0SystemRoot=C:\\W\0\0"                     # sorted without regard to case
    assert "LANTERN_NOT_HANDED_ON" not in block
    assert winspawn.env_block({}) == "\0\0"                                       # Windows reads to the first two
    for bad in ({"": "x"}, {"a=b": "x"}, {"a": "x\0y"}, {"a\0": "x"}):
        with pytest.raises(ValueError):
            winspawn.env_block(bad)


def test_a_program_is_made_paused_put_in_its_job_and_only_then_let_run():
    k32 = Kernel32()
    job = Job(k32)
    proc = _start(k32, job, env={"SystemRoot": r"C:\W", "TEMP": r"C:\T\profile\tmp"})
    assert k32.calls == ["InitializeProcThreadAttributeList(size)", "InitializeProcThreadAttributeList",
                         "UpdateProcThreadAttribute", "CreateProcessW", "DeleteProcThreadAttributeList", "take",
                         "ResumeThread", "CloseHandle"]
    seen = k32.seen
    assert seen["program"] == r"C:\Program Files\B\b.exe"
    assert seen["command"] == subprocess.list2cmdline([r"C:\Program Files\B\b.exe", "--x=a b", "about:blank"])
    assert seen["flags"] & winspawn.CREATE_SUSPENDED and seen["flags"] & winspawn.EXTENDED_STARTUPINFO_PRESENT
    assert seen["flags"] & winspawn.CREATE_UNICODE_ENVIRONMENT and seen["flags"] & winspawn.CREATE_NO_WINDOW
    assert not seen["flags"] & 0x01000000                                  # never CREATE_BREAKAWAY_FROM_JOB
    assert seen["inherit"] == 1 and seen["inherited"] == winspawn.handle_list(FDS)   # only the handles named
    assert seen["list_at"] == k32.list_at and seen["security"] == (None, None)
    assert seen["cb"] == ctypes.sizeof(winspawn.StartupInfoEx)
    assert seen["startup_flags"] & winspawn.STARTF_USESTDHANDLES
    assert seen["std"] == (0x10, 0x14, 0x18)
    assert seen["block"] == winspawn.crt_block(FDS)
    assert seen["environment"].rstrip("\0") + "\0\0" == "SystemRoot=C:\\W\0TEMP=C:\\T\\profile\\tmp\0\0"
    assert seen["cwd"] == r"C:\T\profile"
    assert job.taken == [4242] and proc.pid == 4242
    assert k32.lists == 0                                                  # the attribute list given back
    assert k32.open == {seen["process"]} and k32.closed == [seen["thread"]]
    proc.close()
    proc.close()                                                           # given back once
    assert k32.open == set() and k32.closed == [seen["thread"], seen["process"]]


@pytest.mark.parametrize("fail", ["size", "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute",
                                  "CreateProcessW", "take", "ResumeThread"])
def test_every_failure_gives_back_what_was_taken_and_leaves_nothing_running(fail):
    k32 = Kernel32(fail="" if fail == "take" else fail, code=1450)
    job = Job(k32, fail=fail == "take")
    with pytest.raises((winspawn.SpawnError, winjob.JobError)) as caught:
        _start(k32, job)
    call = {"size": "InitializeProcThreadAttributeList", "take": "AssignProcessToJobObject"}.get(fail, fail)
    assert caught.value.call == call
    if fail not in ("size", "take"):
        assert caught.value.code == 1450                                   # Windows' own number is kept
    assert k32.lists == 0                                                  # every list made was given back
    assert k32.open == set()                                               # and every handle
    made = "CreateProcessW" in k32.calls and fail != "CreateProcessW"
    if made:                                                               # it was made: it never ran, and is ended
        assert "ResumeThread" not in k32.calls[:k32.calls.index("take")]
        assert k32.seen["ended"] == 1 and "TerminateProcess" in k32.calls
        if fail == "take":
            assert "ResumeThread" not in k32.calls                         # never let run outside its job
    else:
        assert "TerminateProcess" not in k32.calls and "take" not in k32.calls
    if fail in ("size", "InitializeProcThreadAttributeList"):
        assert "CreateProcessW" not in k32.calls and "DeleteProcThreadAttributeList" not in k32.calls
    if fail == "UpdateProcThreadAttribute":
        assert "CreateProcessW" not in k32.calls and "DeleteProcThreadAttributeList" in k32.calls


def test_the_standard_descriptors_are_always_named():
    k32 = Kernel32()
    for missing in (0, 1, 2):
        with pytest.raises(ValueError):
            _start(k32, fds={k: v for k, v in FDS.items() if k != missing})
    assert k32.calls == []                                                 # refused before anything was asked


def test_a_process_is_waited_for_polled_ended_and_given_back_once():
    k32 = Kernel32(waits=[winspawn.WAIT_TIMEOUT, winspawn.WAIT_TIMEOUT, winspawn.WAIT_OBJECT_0], exit_code=3)
    proc = _start(k32)
    assert proc.poll() is None
    with pytest.raises(subprocess.TimeoutExpired):
        proc.wait(timeout=1.5)
    assert k32.seen["waited"][-1] == 1500
    proc.kill()
    assert k32.seen["ended"] == 1
    assert proc.wait() == 3 and proc.returncode == 3 and k32.seen["waited"][-1] == winspawn.INFINITE
    assert proc.poll() == 3                                                # asked no more once it is known
    proc.close()
    proc.close()
    assert k32.open == set()
    failing = Kernel32(fail="WaitForSingleObject", code=6)
    other = _start(failing)
    with pytest.raises(winspawn.SpawnError) as caught:
        other.wait(1)
    assert (caught.value.call, caught.value.code) == ("WaitForSingleObject", 6)
    other.close()
    with pytest.raises(winspawn.SpawnError):
        other.wait(1)                                                      # its handle was given back


# On Windows itself: a real program, a real job.

CHILD = r"""
import ctypes, json, os, subprocess, sys
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetCurrentProcess.restype = ctypes.c_void_p
k32.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
k32.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
asked = b""
while not asked.endswith(b"\n"):
    piece = os.read(3, 4096)
    if not piece:
        break
    asked += piece
inside = ctypes.c_int(0)
k32.IsProcessInJob(k32.GetCurrentProcess(), None, ctypes.byref(inside))
place = ctypes.create_unicode_buffer(1024)
named = k32.GetFinalPathNameByHandleW(int(sys.argv[1]), place, 1024, 0)
child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(600)"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=0x08000000)
said = {"asked": asked.decode(), "in_job": bool(inside.value), "env": sorted(os.environ), "cwd": os.getcwd(),
        "child": child.pid, "not_handed": place.value if named else ""}
os.write(4, (json.dumps(said) + "\n").encode())
import time
time.sleep(600)
"""


def _ended(pid: int, seconds: float = 15) -> bool:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype, k32.OpenProcess.argtypes = ctypes.c_void_p, [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.WaitForSingleObject.restype, k32.WaitForSingleObject.argtypes = ctypes.c_uint32, [ctypes.c_void_p, ctypes.c_uint32]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(0x00100000 | 0x1000, 0, pid)       # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return True                                         # no such process any more
    try:
        return k32.WaitForSingleObject(h, int(seconds * 1000)) == 0
    finally:
        k32.CloseHandle(h)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows itself: its C library, its jobs")
def test_on_windows_a_program_gets_descriptors_3_and_4_inside_its_job_and_no_other_handle(tmp_path):
    import msvcrt
    python = getattr(sys, "_base_executable", None) or sys.executable
    to_child, to_lantern = os.pipe(), os.pipe()            # (read, write) each
    nul_in = os.open(os.devnull, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    nul_out = os.open(os.devnull, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
    lines = os.open(tmp_path / "lines.txt", os.O_WRONLY | os.O_CREAT | os.O_BINARY | os.O_NOINHERIT)
    kept = os.open(tmp_path / "not-handed.txt", os.O_WRONLY | os.O_CREAT | os.O_BINARY | os.O_NOINHERIT)
    child_ends = (to_child[0], to_lantern[1], nul_in, nul_out, lines)
    for fd in (*child_ends, kept):                          # `kept` may be inherited too, and is not named
        os.set_handle_inheritable(msvcrt.get_osfhandle(fd), True)
    h = msvcrt.get_osfhandle
    fds = {0: (h(nul_in), FOPEN | FDEV), 1: (h(nul_out), FOPEN | FDEV), 2: (h(lines), FOPEN),
           3: (h(to_child[0]), FOPEN | FPIPE), 4: (h(to_lantern[1]), FOPEN | FPIPE)}
    job = winjob.Job(memory=1 << 30)
    proc = None
    try:
        proc = winspawn.start([python, "-I", "-S", "-c", CHILD, str(h(kept))],
                              env={"SystemRoot": os.environ["SystemRoot"], "MARK": "given"}, cwd=str(tmp_path),
                              fds=fds, job=job)
        for fd in child_ends:
            os.close(fd)
        os.write(to_child[1], b"asked through 3\n")
        got: list[bytes] = []

        def read():
            while not b"".join(got).endswith(b"\n"):
                piece = os.read(to_lantern[0], 65536)
                if not piece:
                    return
                got.append(piece)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(timeout=60)
        said = json.loads(b"".join(got))
        assert said["asked"] == "asked through 3\n"                        # its 3 is the pipe Lantern writes
        assert said["in_job"] is True                                      # and it was in the job from the start
        assert said["not_handed"] == ""                                    # a handle not named did not reach it
        assert {e.upper() for e in said["env"]} == {"SYSTEMROOT", "MARK"}
        assert os.path.normcase(said["cwd"]) == os.path.normcase(str(tmp_path))
        assert job.count() >= 2                                            # it and what it started
        job.stop()
        end = time.monotonic() + 15
        while job.count() and time.monotonic() < end:
            time.sleep(0.05)
        assert job.count() == 0
        assert proc.wait(15) == 1                                          # ended by the job
        assert _ended(said["child"])                                       # what it started ended with it
    finally:
        if proc is not None:
            proc.close()
        job.close()
        for fd in (to_child[1], to_lantern[0], kept):
            os.close(fd)
