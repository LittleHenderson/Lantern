"""Tests that use process locks, pools and queues get an answer, in a memory folder of the run's own (2026-11-13).

Python's `multiprocessing` (and with it `concurrent.futures.ProcessPoolExecutor`) makes every lock, pool and queue
from a named semaphore, which Linux keeps as a file in `/dev/shm`: a folder every program of the computer shares,
and one the sandbox has never let the tests write in. So a project whose tests start a pool of processes failed in
the sandbox with "Permission denied" from below Python, with nothing said about a refusal, and the release decision
read "tests failed" (found 2026-11-13 by running three such tests there: 3 of 3 failed).

Now a run on Linux has a `/dev/shm` of its own, empty, limited in size and gone with the run (a mount of its own,
`lantern._jail._own_memory`), and its own names for the older kind of shared memory (System V), which outlives the
program that made it. The dangerous twins: what another program of this computer keeps in the shared folder, or
under such a name, is not there for the tests, and nothing the tests make is there afterwards."""
import ctypes
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from lantern import _jail, sandbox

LINUX = sys.platform.startswith("linux")
only_posix = pytest.mark.skipif(os.name != "posix", reason="process pools under the guard on Windows: stage 4 of this work")
needs_shm = pytest.mark.skipif(not (LINUX and os.path.isdir("/dev/shm")), reason="needs Linux's /dev/shm")
UNITTEST = ["python", "-m", "unittest", "-v"]


def QUIET(line):
    """A log nobody reads."""


def _project(folder: Path, source: str) -> Path:
    folder.mkdir(parents=True)
    (folder / "pyproject.toml").write_text("[project]\nname = 'tiny'\n", encoding="utf-8")
    (folder / "test_tiny.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return folder


def _can() -> bool:
    """Can a run be given a memory folder of its own here? (Not where these tests run in a sandbox themselves.)"""
    return LINUX and not sandbox.own_memory()


POOLS = '''
    import concurrent.futures
    import multiprocessing as mp
    import unittest
    from multiprocessing import shared_memory


    def double(x):
        return 2 * x


    def put(q, lock):
        with lock:
            q.put("from the other process")


    class T(unittest.TestCase):
        def test_a_lock_and_a_queue_between_two_processes(self):
            q, lock = mp.Queue(), mp.Lock()
            p = mp.Process(target=put, args=(q, lock))
            p.start()
            self.assertEqual(q.get(timeout=60), "from the other process")
            p.join(60)
            self.assertEqual(p.exitcode, 0)

        def test_a_pool(self):
            with mp.Pool(2) as pool:
                self.assertEqual(pool.map(double, [1, 2, 3]), [2, 4, 6])

        def test_a_pool_of_the_newer_kind(self):
            with concurrent.futures.ProcessPoolExecutor(2) as pool:
                self.assertEqual(list(pool.map(double, [1, 2, 3])), [2, 4, 6])

        def test_memory_two_processes_share(self):
            block = shared_memory.SharedMemory(create=True, size=1024)
            try:
                block.buf[:5] = b"hello"
                again = shared_memory.SharedMemory(name=block.name)
                self.assertEqual(bytes(again.buf[:5]), b"hello")
                again.close()
            finally:
                block.close()
                block.unlink()
'''


@only_posix
@pytest.mark.parametrize("can", [True, False], ids=["a memory folder of the run's own", "a system that makes none"])
def test_tests_that_use_process_locks_pools_and_queues_run(tmp_path, monkeypatch, can):
    """The honest project: what passes at home passes in the sandbox, and nothing is said to have been refused.
    Where the system gives a run no memory folder of its own (an ordinary user on a Linux that refuses new
    namespaces; a run inside a run), such tests cannot run where the kernel keeps writes in the run's folders:
    the sheet and the log say so, and the run is not counted as tests that failed."""
    from lantern import release
    if not can:
        monkeypatch.setattr(sandbox, "_OWN_MEMORY", ["this test takes the memory folder of its own away"])
    elif LINUX and not _can():
        pytest.skip("this system gives a run no memory folder of its own (it refuses a new namespace)")
    lines = []
    repo = _project(tmp_path / "tiny", POOLS)
    res = sandbox.run(repo, UNITTEST, log=lines.append, backend="subprocess")
    # the sheet of the backend the run above used: where Docker is installed the default sheet is the container's
    # (GitHub's machines have Docker; this test failed there)
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    sheet = " ".join(sandbox.describe(repo, "python")["details"])
    if LINUX and not can:
        assert "this test takes the memory folder of its own away, so tests that start a pool of processes" in sheet
        assert any("no memory folder of their own" in line for line in lines), lines
        if sandbox.landlock_abi() >= 1:          # the wall that keeps a run's writes in its own folders
            assert res["returncode"] == 1, res["output_tail"]
            assert res["blocked"] == [{"kind": "write", "what": sandbox.NO_PROCESS_LOCK}], res["blocked"]
            said = release._tests(True, {"trace": {"ran": True, "returncode": 1, "blocked": res["blocked"]}})
            assert said["state"] == "missing", said
        return
    assert res["returncode"] == 0, res["output_tail"]
    assert res["blocked"] == []
    if LINUX:
        assert "a memory folder of its own for process pools" in sheet
        assert any("a memory folder of its own" in line for line in lines), lines


LAUNCHER = "import sys; from lantern._jail import main; main(sys.argv[1:])"
HERE = Path(_jail.__file__).resolve().parent.parent


@pytest.mark.skipif(not (LINUX and sandbox.landlock_abi() >= 1),
                    reason="needs Linux with Landlock (under whose rules no mount can be made)")
@pytest.mark.parametrize("must", [True, False])
def test_the_launcher_does_not_start_the_command_when_the_memory_folder_it_was_asked_for_cannot_be_made(must, tmp_path):
    """Lantern asks for the folder only where it tried the system first, and promises with it that the shared
    memory of the person's other programs is out of reach: a launcher that then cannot make it starts nothing.
    Here it cannot because it is started under the rules of another launcher, which allow no mount. (Without
    `must`, the cloud service's steps, it says so and carries on, as with every other wall.)"""
    mark = tmp_path / "ran.txt"
    outer = {"writable": [str(tmp_path)], "nobody": False, "python": False, "net": False, "must": True}
    inner = dict(outer, must=must, shm=64 << 20)
    r = subprocess.run([sys.executable, "-c", LAUNCHER, json.dumps(outer), "--",
                        sys.executable, "-c", LAUNCHER, json.dumps(inner), "--",
                        sys.executable, "-I", "-S", "-c", f"open({str(mark)!r}, 'w').close()"],
                       capture_output=True, text=True, encoding="utf-8", timeout=120, cwd=HERE)
    assert "sandbox: a memory folder of its own could not be made" in r.stderr, r.stderr
    if must:
        assert r.returncode == _jail.UNAVAILABLE and not mark.exists(), r
        assert (_jail.MARK + " own-memory") in r.stderr and "own-memory" in _jail.REASONS
    else:
        assert r.returncode == 0 and mark.exists() and _jail.MARK not in r.stderr, r


REFUSED_LOCK = '''Traceback (most recent call last):
  File "/usr/lib/python3.12/multiprocessing/synchronize.py", line 57, in __init__
    sl = self._semlock = _multiprocessing.SemLock(
PermissionError: [Errno 13] Permission denied
'''


def test_a_run_with_no_memory_folder_says_what_was_refused_and_any_other_run_does_not():
    """What a run's output is read for where the launcher said it could make no memory folder: the refused lock
    is the sandbox's doing, and such a run is not counted as tests that failed. The same error in a run that had
    one, and any other error on the way through the same code, are the tests' own."""
    from lantern import release
    refused = sandbox.blocked_reasons(REFUSED_LOCK, no_memory_folder=True)
    assert refused == [{"kind": "write", "what": sandbox.NO_PROCESS_LOCK}]
    said = release._tests(True, {"trace": {"ran": True, "returncode": 1, "blocked": refused}})
    assert said["state"] == "missing", said
    assert sandbox.blocked_reasons(REFUSED_LOCK) == []          # a run that had a memory folder
    another = REFUSED_LOCK.replace("PermissionError: [Errno 13] Permission denied", "OSError: [Errno 28] No space left on device")
    assert sandbox.blocked_reasons(another, no_memory_folder=True) == []
    said = release._tests(True, {"trace": {"ran": True, "returncode": 1, "blocked": []}})
    assert said["state"] == "failed", said


THEIRS = '''
    import ctypes
    import os
    import subprocess
    import sys
    import unittest
    from multiprocessing import shared_memory

    NAME, KEY = {name!r}, {key}
    libc = ctypes.CDLL(None, use_errno=True)


    def refused(fn):
        try:
            return "got " + repr(fn())[:60]
        except BaseException as e:
            return "refused " + type(e).__name__


    def run(*cmd):
        done = subprocess.run(list(cmd), capture_output=True, text=True, timeout=60)
        if done.returncode != 0:
            raise PermissionError(done.returncode)
        return done.stdout


    def old_kind(key, flags=0):
        number = libc.shmget(key, 4096, flags)
        if number < 0:
            raise OSError(ctypes.get_errno(), "shmget")
        return number


    class T(unittest.TestCase):
        def test_what_another_program_keeps_there_is_not_there(self):
            tries = {{
                "the file": lambda: open("/dev/shm/" + NAME).read(),
                "the file, another program": lambda: run("cat", "/dev/shm/" + NAME),
                "the file, a python without the guard": lambda: run(sys.executable, "-S", "-c", "print(open('/dev/shm/%s').read())" % NAME),
                "the file, as shared memory": lambda: bytes(shared_memory.SharedMemory(name=NAME).buf[:7]),
                "a change to the file": lambda: open("/dev/shm/" + NAME, "r+").write("changed"),
                "the file removed": lambda: os.remove("/dev/shm/" + NAME),
                "its name among the others": lambda: [n for n in os.listdir("/dev/shm") if n == NAME][0],
                "memory of the older kind": lambda: old_kind(KEY),
            }}
            said = {{name: refused(fn) for name, fn in tries.items()}}
            self.assertEqual([name for name, what in said.items() if not what.startswith("refused ")], [], said)

        def test_what_the_tests_leave_there(self):
            with open("/dev/shm/left-by-the-tests-" + NAME, "w") as f:
                f.write("left")
            shared_memory.SharedMemory(name="left-" + NAME, create=True, size=4096).close()     # never unlinked
            old_kind(KEY + 1, 0o1000 | 0o666)                                                 # IPC_CREAT, never removed
'''


@needs_shm
def test_what_another_program_keeps_in_shared_memory_is_not_the_tests_and_nothing_is_left_there(tmp_path):
    """The dangerous twin. Another program of this computer keeps a file in /dev/shm that every user may read and
    change, and a block of the older kind of shared memory under a number: the tests find neither, by whichever
    program they look, and what they leave behind themselves is gone with the run."""
    if not _can():
        pytest.skip("this system gives a run no memory folder of its own (it refuses a new namespace)")
    name = "lantern-test-" + os.urandom(6).hex()
    theirs = Path("/dev/shm") / name
    libc = ctypes.CDLL(None, use_errno=True)
    key = 0x4C000000 | int.from_bytes(os.urandom(3), "big")
    theirs.write_text("PLANTED", encoding="utf-8")
    os.chmod(theirs, 0o666)
    number = libc.shmget(key, 4096, 0o1000 | 0o2000 | 0o666)       # IPC_CREAT | IPC_EXCL, every user may attach
    assert number >= 0, ctypes.get_errno()
    try:
        before = set(os.listdir("/dev/shm"))
        res = sandbox.run(_project(tmp_path / "tiny", THEIRS.format(name=name, key=key)), UNITTEST, log=QUIET,
                          backend="subprocess")
        assert res["returncode"] == 0, res["output_tail"]
        assert "PLANTED" not in res["output_tail"]
        assert theirs.read_text(encoding="utf-8") == "PLANTED"
        assert set(os.listdir("/dev/shm")) == before
        assert libc.shmget(key, 4096, 0) == number                 # theirs is still there, under its number
        assert libc.shmget(key + 1, 4096, 0) < 0                   # and what the tests made is not on this computer
    finally:
        libc.shmctl(number, 0, None)                               # IPC_RMID
        left = libc.shmget(key + 1, 4096, 0)
        if left >= 0:
            libc.shmctl(left, 0, None)
        for path in (theirs, Path("/dev/shm") / ("left-by-the-tests-" + name), Path("/dev/shm") / ("left-" + name)):
            path.unlink(missing_ok=True)


@needs_shm
def test_the_memory_folder_of_a_run_holds_no_more_than_it_was_given(tmp_path):
    """A run cannot fill the computer's memory through its memory folder: it has a size, and a file that grows
    past it is refused by the system."""
    if not _can():
        pytest.skip("this system gives a run no memory folder of its own (it refuses a new namespace)")
    source = '''
        import os
        import unittest


        class T(unittest.TestCase):
            def test_a_file_larger_than_the_folder(self):
                size = os.statvfs("/dev/shm").f_blocks * os.statvfs("/dev/shm").f_frsize
                self.assertTrue(0 < size <= 1 << 30, size)
                fd = os.open("/dev/shm/large", os.O_WRONLY | os.O_CREAT, 0o600)
                with self.assertRaises(OSError):
                    left = size + (1 << 20)
                    while left > 0:
                        left -= os.write(fd, bytes(1 << 20))
                os.close(fd)
    '''
    res = sandbox.run(_project(tmp_path / "tiny", source), UNITTEST, log=QUIET, backend="subprocess")
    assert res["returncode"] == 0, res["output_tail"]
