"""The memory a project's tests get (2026-11-13): 2 GB of memory really used, by the tests and everything they
started counted together, unless the person sets another limit: in the app (the sheet of "Watch my tests run"),
on the command line (`--test-memory`) or for a whole installation (LANTERN_TEST_MEMORY_MB).

Until then the restricted process gave each Python process 2 GB of address space, which is not memory: a program
reserves space it never uses (a large file mapped, a thread's stack, an allocator's arenas), and Lantern's own
tests, which pass at home, were stopped in the sandbox after 302 of them with MemoryError and reported as "the
tests failed", a release that is Blocked. Two things were wrong: what was counted, and the word for it. Now what
is counted is memory in use, looked at from outside by the launcher's supervisor (Linux), and tests that were
stopped for it are tests that did not finish: "Incomplete", never a failure and never a pass.

Each case stands beside its twin: space reserved and never used beside memory really used, a run under its limit
beside the same run over it, memory that programs share beside memory each has for itself."""
import json
import os
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from test_sandbox import BACKENDS, _tiny

from lantern import _jail, cli, pipeline, release, sandbox

PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]
LINUX = sys.platform.startswith("linux")
watched = pytest.mark.skipif(not LINUX, reason="memory in use is looked at by the launcher's supervisor, which is Linux's")


def QUIET(line):
    """A log nobody reads."""


# ------------------------------------------------------------------------------------------------- the limit
def test_two_gigabytes_unless_the_person_sets_another_limit(monkeypatch):
    monkeypatch.delenv("LANTERN_TEST_MEMORY_MB", raising=False)
    assert sandbox.memory_limit() == 2048 == sandbox.MEMORY_MB
    assert sandbox.memory_limit(4096) == 4096 and sandbox.memory_limit("512") == 512
    monkeypatch.setenv("LANTERN_TEST_MEMORY_MB", "8192")
    assert sandbox.memory_limit() == 8192
    assert sandbox.memory_limit(4096) == 4096               # what is asked for this run wins over the installation's
    for junk in ("", "lots", "-5", "nan", "1e400", "0", "100"):    # no number of megabytes, or under the least: 2 GB
        monkeypatch.setenv("LANTERN_TEST_MEMORY_MB", junk)
        assert sandbox.memory_limit() == 2048, junk
    monkeypatch.setenv("LANTERN_TEST_MEMORY_MB", "99999999999")    # more than the most: the most
    assert sandbox.memory_limit() == sandbox.MEGABYTES[1]


@pytest.mark.parametrize("asked", [0, -1, 127, (1 << 20) + 1, "lots", "", 2.5, True, [512], float("nan")])
def test_a_limit_the_person_asks_for_is_a_whole_number_of_megabytes(asked):
    """Said, never quietly changed into another number."""
    with pytest.raises(ValueError, match="from 128 to 1048576"):
        sandbox.memory_limit(asked)


def test_a_limit_in_words():
    assert sandbox.memory_words(2048) == "2 GB" and sandbox.memory_words(256) == "256 MB"
    assert sandbox.memory_words(1536) == "1536 MB" and sandbox.memory_words(1024) == "1 GB"
    for junk in (None, "2048", True, -1, 0, 2.5, float("nan"), 10 ** 12, "<b>"):
        assert sandbox.memory_words(junk) == "", junk


def test_the_sheet_says_the_memory_the_tests_will_have(tmp_path, monkeypatch):
    monkeypatch.delenv("LANTERN_SANDBOX", raising=False)
    monkeypatch.delenv("LANTERN_TEST_MEMORY_MB", raising=False)
    monkeypatch.setattr(sandbox, "docker_ok", lambda: False)
    words = " | ".join(sandbox.describe(tmp_path, "python")["details"])
    if LINUX:
        assert "2 GB of memory for the tests and everything they start, counted together" in words, words
        assert "4 GB of memory" in " | ".join(sandbox.describe(tmp_path, "python", memory=4096)["details"])
    monkeypatch.setenv("LANTERN_SANDBOX", "docker")
    assert any("512 MB memory" in d for d in sandbox.describe(tmp_path, "python", memory=512)["details"])


# ------------------------------------------------------------------------------------- reserved is not used
RESERVES = '''
import mmap

def test_space_that_is_reserved_and_never_used():
    space = mmap.mmap(-1, 3 << 30)          # 3 GB of address space; one page of it is ever written
    space[0:1] = b"x"
    assert space[0:1] == b"x"
    space.close()
'''


@watched
def test_tests_that_reserve_far_more_space_than_they_use_run_as_they_do_at_home(tmp_path):
    repo = _tiny(tmp_path / "tiny", RESERVES)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
    assert r["returncode"] == 0, r["output_tail"]
    assert r["over_memory"] is False and r["memory_limit"] == 2048 and r["blocked"] == []


# ------------------------------------------------------------------------------------------ really used
USES = '''
import os, subprocess, sys, time

def test_uses_more_and_more():
    kid = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], start_new_session=True)
    print("STARTED", kid.pid, flush=True)       # something it started, which moved out of its group
    held = []
    for _ in range(TIMES):                      # 16 MB at a time, every page of it written
        held.append(bytearray(os.urandom(1 << 20) * 16))
        time.sleep(0.05)
    time.sleep(HOLD)
    kid.kill()
'''


def _started(output: str) -> int:
    return int(next(line.split()[1] for line in output.splitlines() if line.startswith("STARTED ")))


@watched
def test_tests_that_use_more_memory_than_their_limit_are_stopped_and_it_is_said(tmp_path):
    repo = _tiny(tmp_path / "tiny", USES.replace("TIMES", "40").replace("HOLD", "20"))     # 640 MB
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", memory=256)
    assert r["over_memory"] is True and r["memory_limit"] == 256, (r["returncode"], r["output_tail"])
    assert r["returncode"] is None and r["timed_out"] is False and r["cancelled"] is False
    assert r["not_ended"] == [] and not os.path.exists(f"/proc/{_started(r['output_tail'])}")
    said = [x for x in lines if "more memory than their limit (256 MB)" in x]
    assert said and "every process it started was ended" in said[0], lines[-8:]
    assert "test_uses_more_and_more" not in "".join(x for x in lines if "passed" in x or "failed" in x)


@watched
def test_the_same_tests_under_their_limit_pass(tmp_path):
    repo = _tiny(tmp_path / "tiny", USES.replace("TIMES", "4").replace("HOLD", "2"))       # 64 MB
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", memory=256)
    assert r["returncode"] == 0 and r["over_memory"] is False and r["memory_limit"] == 256, r["output_tail"]
    assert not any("more memory than" in x for x in lines), lines


SEVERAL = '''
import subprocess, sys, time

def test_four_programs_that_use_100_mb_each():
    code = "import os, time; held = bytearray(os.urandom(1 << 20) * 100); print('UP', flush=True); time.sleep(60)"
    kids = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE) for _ in range(4)]
    for k in kids:
        k.stdout.readline()
    time.sleep(HOLD)
    for k in kids:
        k.kill()
'''


@watched
def test_what_the_tests_started_counts_with_them(tmp_path):
    """No one program is over the limit; together they are."""
    repo = _tiny(tmp_path / "tiny", SEVERAL.replace("HOLD", "20"))
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", memory=256)
    assert r["over_memory"] is True and r["returncode"] is None and r["not_ended"] == [], r["output_tail"]


@watched
def test_the_same_programs_with_room_for_all_four_pass(tmp_path):
    repo = _tiny(tmp_path / "tiny", SEVERAL.replace("HOLD", "2"))
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", memory=1024)
    assert r["returncode"] == 0 and r["over_memory"] is False, r["output_tail"]


SHARED = '''
import os, time

def test_a_program_and_four_copies_of_it_that_share_150_mb():
    held = bytearray(os.urandom(1 << 20) * 150)
    kids = []
    for _ in range(4):
        pid = os.fork()
        if pid == 0:
            time.sleep(4)           # a copy that writes nothing: every page of the 150 MB stays shared with it
            os._exit(0)
        kids.append(pid)
    for pid in kids:
        assert os.waitpid(pid, 0)[1] == 0
    assert len(held) == 150 << 20
'''


@watched
def test_memory_that_programs_share_is_counted_once(tmp_path):
    """Five programs that each show 150 MB and have 150 MB between them: under a limit of 400 MB, where the same
    memory counted for each of them would be 750 MB."""
    repo = _tiny(tmp_path / "tiny", SHARED)
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", memory=400)
    assert r["returncode"] == 0 and r["over_memory"] is False, r["output_tail"]


def test_the_words_alone_and_the_result_alone_are_the_tests_own(tmp_path):
    """The launcher says it in a line of the run's output together with a result of its own. A test that prints the
    line and fails has failed, and so has one that ends with that result and no line."""
    repo = _tiny(tmp_path / "says", "def test_says_it():\n    print('LANTERN-SANDBOX-LIMIT: memory 9 1')\n    assert False\n")
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
    assert r["returncode"] == 1 and r["over_memory"] is False, r["output_tail"]
    assert release._tests(True, {"trace": {"ran": True, **{k: r[k] for k in ("returncode", "over_memory", "blocked")}}})["state"] == "failed"
    repo = _tiny(tmp_path / "ends", "import os\n\ndef test_ends_with_it():\n    os._exit(118)\n")
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
    assert r["returncode"] == 118 == _jail.OVER_MEMORY and r["over_memory"] is False, r["output_tail"]
    assert release._tests(True, {"trace": {"ran": True, **{k: r[k] for k in ("returncode", "over_memory", "blocked")}}})["state"] == "failed"


# ------------------------------------------------------------------------------------------- the launcher
@watched
def test_the_launcher_counts_memory_in_use_and_leaves_reserved_space_alone(tmp_path):
    """With a limit to watch, the launcher sets no limit on address space; without one (the cloud service's steps,
    which read a project) it keeps the 2 GB it always set."""
    show = [sys.executable, "-c", "import resource; print('AS', resource.getrlimit(resource.RLIMIT_AS)[0])"]
    for more, want in (({"memory": 256 << 20}, "AS -1"), ({}, f"AS {2 << 30}"), ({"memory": "lots"}, f"AS {2 << 30}"),
                       ({"memory": True}, f"AS {2 << 30}"), ({"memory": -5}, f"AS {2 << 30}")):
        policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": False, "must": True, **more}
        r = subprocess.run([sys.executable, "-c", "import sys; from lantern._jail import main; main(sys.argv[1:])",
                            json.dumps(policy), "--", *show], capture_output=True, text=True, encoding="utf-8",
                           timeout=120, cwd=Path(_jail.__file__).resolve().parent.parent)
        assert want in r.stdout, (more, r.stdout, r.stderr)


@watched
def test_what_a_program_calls_itself_does_not_change_what_is_counted(tmp_path):
    """The count is read from what the kernel says of each program, which begins with the program's own name."""
    code = ("import ctypes, os, time\n"
            "ctypes.CDLL(None).prctl(15, b'VmRSS: 0 kB', 0, 0, 0)\n"       # PR_SET_NAME
            "held = bytearray(os.urandom(1 << 20) * 300)\n"
            "time.sleep(20)\n")
    policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": False, "must": True, "memory": 128 << 20}
    r = subprocess.run([sys.executable, "-c", "import sys; from lantern._jail import main; main(sys.argv[1:])",
                        json.dumps(policy), "--", sys.executable, "-c", code], capture_output=True, text=True,
                       encoding="utf-8", timeout=120, cwd=Path(_jail.__file__).resolve().parent.parent)
    assert r.returncode == _jail.OVER_MEMORY and f"{_jail.LIMIT_MARK} memory " in r.stderr, (r.returncode, r.stderr)


# -------------------------------------------------------------------------------------- the check's record
def _stopped_for_memory(seen: dict):
    def run(repo, words, log=print, timeout=sandbox.WALL_CLOCK, **more):
        seen.update(more)
        return sandbox.Result(pairs=[], returncode=None, timed_out=False, over_memory=True, cancelled=False, blocked=[],
                              not_ended=[], backend="subprocess", language="python", traced=True, own_network=False,
                              memory_limit=more.get("memory") or 2048, output_tail="", stderr_tail="")
    return run


def test_the_check_gives_the_tests_the_memory_the_person_set_and_says_which_limit_stopped_them(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(sandbox, "run", _stopped_for_memory(seen))
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    lines = []
    res = pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=lines.append, test_memory=512)
    assert seen["memory"] == 512
    tr = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    assert tr["over_memory"] is True and tr["returncode"] is None and tr["memory_limit"] == 512, tr
    assert not tr.get("timed_out"), tr
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    tests = next(c for c in rd["release"]["criteria"] if c["id"] == "tests")
    assert res["release"] == rd["release"]["decision"] == "Incomplete" and tests["state"] == "missing", rd["release"]
    assert "more memory than their limit (512 MB)" in tests["why"] and "not a pass and not a failure" in tests["why"], tests
    assert "--test-memory" in tests["fix"] and "more memory" in tests["fix"], tests
    assert any("more memory than their limit (512 MB)" in x for x in lines), lines[-12:]
    check = next(c for cat in rd["categories"] for c in cat["checks"] if c["id"] == "tests-pass")
    assert check["status"] == "skip" and check.get("required") is True and "memory" in check["evidence"], check


def test_the_words_for_a_run_that_was_stopped_for_its_memory():
    tests = release._tests(True, {"trace": {"ran": True, "returncode": None, "over_memory": True, "memory_limit": 2048}})
    assert tests["state"] == "missing" and "more memory than their limit (2 GB)" in tests["why"], tests
    older = release._tests(True, {"trace": {"ran": True, "returncode": None, "over_memory": True}})
    assert older["state"] == "missing" and "more memory than their limit." in older["why"], older
    planted = release._tests(True, {"trace": {"ran": True, "returncode": None, "over_memory": True, "memory_limit": "<b>"}})
    assert "<b>" not in planted["why"], planted
    # the near-misses: tests that ended by themselves with an error are failed tests, whatever else the record says
    failed = release._tests(True, {"trace": {"ran": True, "returncode": 1, "over_memory": False, "memory_limit": 2048}})
    assert failed["state"] == "failed", failed
    said = release._tests(True, {"trace": {"ran": True, "returncode": 1, "over_memory": True, "memory_limit": 2048}})
    assert said["state"] == "failed", said


def test_without_a_word_from_the_person_the_check_gives_two_gigabytes(tmp_path, monkeypatch):
    monkeypatch.delenv("LANTERN_TEST_MEMORY_MB", raising=False)
    seen = {}
    monkeypatch.setattr(sandbox, "run", _stopped_for_memory(seen))
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=QUIET)
    assert seen["memory"] == 2048
    monkeypatch.setenv("LANTERN_TEST_MEMORY_MB", "4096")
    pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=QUIET)
    assert seen["memory"] == 4096
    with pytest.raises(ValueError, match="from 128 to 1048576"):
        pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=QUIET, test_memory=5)


@watched
def test_the_whole_check_on_tests_that_use_too_much_memory_is_incomplete_not_blocked(tmp_path, capsys):
    """Nothing stood in for the sandbox here: `lantern analyze --trace --sandbox --test-memory 256`."""
    repo = _tiny(tmp_path / "hungry", USES.replace("TIMES", "40").replace("HOLD", "20"))
    code = cli.main(["analyze", str(repo), "--offline", "--trace", "--sandbox", "--test-memory", "256", "--",
                     "python", "-m", "pytest", "-q", "-s"])
    said = capsys.readouterr()
    assert code == 0, said.err[-2000:]
    tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
    assert tr["over_memory"] is True and tr["memory_limit"] == 256 and tr["returncode"] is None, tr
    rel = json.loads((repo / ".lantern" / "readiness.json").read_text(encoding="utf-8"))["release"]
    assert rel["decision"] == "Incomplete" and "tests" in " ".join(str(x) for x in rel["missing"]), rel
    code = cli.main(["analyze", str(repo), "--offline", "--require", "passed", "--trace", "--sandbox", "--test-memory",
                     "256", "--", "python", "-m", "pytest", "-q", "-s"])
    assert code == 1 and "the release decision is Incomplete" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------------ the command line
def test_on_the_command_line_the_limit_is_given_in_megabytes(tmp_path, monkeypatch, capsys):
    seen = []

    def analyze(repo, out, privacy="full", trace_cmd=None, no_scan=False, **more):
        seen.append(more)
        return {"counts": {}, "release": "Incomplete"}

    monkeypatch.setattr(pipeline, "analyze", analyze)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    assert cli.main(["analyze", str(repo), "--trace", "--sandbox", "--test-memory", "4096", "--", "python", "-m", "pytest"]) == 0
    assert seen[-1]["sandbox"] is True and seen[-1]["test_memory"] == 4096, seen
    assert cli.main(["analyze", str(repo), "--trace", "--sandbox", "--", "python", "-m", "pytest"]) == 0
    assert seen[-1].get("test_memory") is None, seen
    for bad in ("0", "100", "lots"):
        with pytest.raises(SystemExit):
            cli.main(["analyze", str(repo), "--trace", "--sandbox", "--test-memory", bad, "--", "python", "-m", "pytest"])
        assert "from 128 to 1048576" in capsys.readouterr().err
    with pytest.raises(SystemExit):                          # the limit is the sandbox's: nothing counts it without one
        cli.main(["analyze", str(repo), "--trace", "--test-memory", "4096", "--", "python", "-m", "pytest"])
    assert "--sandbox" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------------------- Docker
FAKE_DOCKER = '''#!/bin/sh
# a stand-in for the docker program: "run" writes down what it was asked and ends as run.mode says; "inspect"
# answers the line of inspect.mode that belongs to this ask (the first ask the first line, and so on; the last
# line for every ask after it) and ends as inspect.rc says, when that file is there; "rm" removes
here=$(dirname "$0")
case "$1" in
  run) echo "$@" > "$here/run.log"; exit "$(cat "$here/run.mode")" ;;
  inspect) echo "$@" >> "$here/inspect.log"
    n=$(wc -l < "$here/inspect.log")
    said=$(sed -n "${n}p" "$here/inspect.mode")
    [ -n "$said" ] || said=$(tail -n 1 "$here/inspect.mode")
    echo "$said"
    if [ -f "$here/inspect.rc" ]; then exit "$(cat "$here/inspect.rc")"; fi
    exit 0 ;;
  rm) echo "$@" >> "$here/rm.log"; echo "$3"; exit 0 ;;
esac
exit 0
'''


class _Clock:
    """The clock Lantern asks Docker by, in a test: time passes only while Lantern waits between two asks, and
    each wait is written down. So how often Docker is asked is what the code decides: the first form of these
    tests counted asks inside a fifth of a real second, and a stand-in that takes 0.15 s to answer, as on a busy
    machine, failed one of them with correct code (the browser job of CI, fourth push of #186, had one failed
    test of 4,745 that its log did not name)."""

    def __init__(self):
        self.now, self.waits = 0.0, []

    def __call__(self) -> float:
        return self.now

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds


def _fake_docker(tmp_path, monkeypatch, run: str, inspect: str) -> tuple[Path, _Clock]:
    """`inspect` is what Docker answers, one line for each time it is asked. The asking goes by a clock of the
    test's own (`_Clock`), with the waits a real run has: nothing here waits a real second."""
    clock = _Clock()
    monkeypatch.setattr(sandbox, "_oom_clock", clock, raising=False)
    monkeypatch.setattr(sandbox, "_oom_wait", clock.wait, raising=False)
    where = tmp_path / "bin"
    where.mkdir(parents=True)
    (where / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
    (where / "docker").chmod(0o755)
    (where / "run.mode").write_text(run, encoding="utf-8")
    (where / "inspect.mode").write_text(inspect + "\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(where) + os.pathsep + os.environ["PATH"])
    return where, clock


def _asked(where: Path) -> int:
    log = where / "inspect.log"
    return len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0


@pytest.mark.skipif(os.name != "posix", reason="the stand-in for the docker program is a shell script")
@pytest.mark.parametrize("code, answer, over", [("137", "true", True), ("137", "false", False), ("1", "true", True),
                                                 ("1", "false", False), ("0", "true", False), ("137", "<b>", False)])
def test_a_container_stopped_for_its_memory_is_said_and_no_failure(code, answer, over, tmp_path, monkeypatch):
    """Docker counts the memory a container uses and ends a program in it that goes over; asked afterwards, it says
    so. (A stand-in for the docker program; the real one is tried below.)"""
    where, _ = _fake_docker(tmp_path, monkeypatch, code, answer)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="docker", memory=512)
    asked = (where / "run.log").read_text(encoding="utf-8")
    assert "--memory 512m" in asked and "--memory-swap 512m" in asked and " --rm " not in asked, asked
    assert (where / "rm.log").read_text(encoding="utf-8").startswith("rm -f lantern-sbx-")   # removed all the same
    assert r["over_memory"] is over and r["memory_limit"] == 512, (r["returncode"], lines)
    if over:
        assert r["returncode"] is None and r["cancelled"] is False
        assert any("more memory than their limit (512 MB)" in x for x in lines), lines
    else:
        assert r["returncode"] == int(code)


DOCKER_ONLY = pytest.mark.skipif(os.name != "posix", reason="the stand-in for the docker program is a shell script")


@DOCKER_ONLY
@pytest.mark.parametrize("code, answers, asks", [("137", "false\nfalse\ntrue", 3), ("137", "false\ntrue", 2),
                                                  ("1", "false\nfalse\nfalse\ntrue", 4), ("2", "false\ntrue", 2)])
def test_dockers_answer_about_the_memory_may_come_after_the_containers_end(code, answers, asks, tmp_path, monkeypatch):
    """Docker learns that the kernel ended a program for the container's memory from a message of its own, and that
    message may arrive after the container has ended. Asked once, right at the end, Docker said "false" in CI on
    2026-11-13 (the third push of #186, Python 3.13), and tests stopped for their memory read as tests that failed:
    "Blocked" where "Incomplete" is true. So a "false" is asked again for a while; a "true" is believed at once."""
    where, clock = _fake_docker(tmp_path, monkeypatch, code, answers)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="docker", memory=512)
    assert r["over_memory"] is True and r["returncode"] is None and r["cancelled"] is False, (r["returncode"], lines)
    assert any("more memory than their limit (512 MB)" in x for x in lines), lines
    assert _asked(where) == asks                                 # and no more once Docker has said yes
    assert clock.waits == [sandbox.OOM_ASK_AGAIN] * (asks - 1)   # the yes ends the waiting: one wait before each ask
    assert (where / "rm.log").read_text(encoding="utf-8").startswith("rm -f lantern-sbx-")


@DOCKER_ONLY
@pytest.mark.parametrize("code, wait", [("137", "OOM_WAIT_KILLED"), ("1", "OOM_WAIT")])
def test_a_no_that_stays_is_believed_after_a_wait_that_ends(code, wait, tmp_path, monkeypatch):
    """The twin: tests that failed, or were ended by a kill that was not for the container's memory. Docker goes on
    saying "false", Lantern stops asking when the wait is over, and the run is what it was: ended with that number.
    After a kill (137) the log says that Docker was asked and did not name the memory."""
    where, clock = _fake_docker(tmp_path, monkeypatch, code, "false")
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    lines = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="docker", memory=512)
    assert r["over_memory"] is False and r["returncode"] == int(code), lines
    seconds = getattr(sandbox, wait)
    assert sum(clock.waits) == pytest.approx(seconds), clock.waits        # asked for that long, and the asking ends
    assert _asked(where) == len(clock.waits) + 1 >= seconds / sandbox.OOM_ASK_AGAIN + 1   # again after every wait
    assert all(0 < w <= sandbox.OOM_ASK_AGAIN for w in clock.waits), clock.waits
    said = [x for x in lines if "did not say" in x]
    if code == "137":
        assert len(said) == 1 and "137" in said[0] and f"asked {_asked(where)} times" in said[0], lines
        assert "failure of the tests" in said[0]
    else:
        assert not said, lines
    assert (where / "rm.log").read_text(encoding="utf-8").startswith("rm -f lantern-sbx-")


@DOCKER_ONLY
def test_a_kill_is_asked_about_longer_than_any_other_error(tmp_path, monkeypatch):
    """The kernel ends a program over its memory with a kill, which Docker reports as 137: that is where a late
    answer matters most. A test runner that lost a child to the limit reports a failure of its own (1, 2, ...)
    some time after the kill, when Docker has usually heard."""
    assert 0 < sandbox.OOM_ASK_AGAIN < sandbox.OOM_WAIT < sandbox.OOM_WAIT_KILLED <= 10
    assert sandbox._oom_clock is time.monotonic and sandbox._oom_wait is time.sleep   # a real run goes by the real clock
    asks = {}
    for code in ("137", "1"):
        where, _ = _fake_docker(tmp_path / code, monkeypatch, code, "false")
        repo = _tiny(tmp_path / code / "tiny", "def test_ok():\n    assert True\n")
        assert sandbox.run(repo, PYTEST, log=QUIET, backend="docker", memory=512)["returncode"] == int(code)
        asks[code] = _asked(where)
    assert asks["137"] > asks["1"] >= 2, asks


@DOCKER_ONLY
@pytest.mark.parametrize("code, answers, rc, asks", [("137", "true", None, 1),       # a yes: asked once
                                                      ("0", "true", None, 0),         # tests that passed: not asked
                                                      ("125", "true", None, 0),       # Docker itself failed: not asked
                                                      ("137", "<b>", None, 1),        # no answer of Docker's: no waiting
                                                      ("137", "", None, 1),
                                                      ("137", "false", "1", 1)])      # docker inspect ended with an error
def test_docker_is_asked_no_more_often_than_it_takes(code, answers, rc, asks, tmp_path, monkeypatch):
    where, clock = _fake_docker(tmp_path, monkeypatch, code, answers)
    if rc:
        (where / "inspect.rc").write_text(rc, encoding="utf-8")
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="docker", memory=512)
    assert _asked(where) == asks, (_asked(where), r["returncode"])
    assert clock.waits == []                                     # and nothing is waited for
    assert r["over_memory"] is (code == "137" and answers == "true" and not rc)


@pytest.mark.parametrize("backend", BACKENDS)
def test_tests_over_their_memory_limit_in_either_sandbox(backend, tmp_path):
    if backend == "subprocess" and not LINUX:
        pytest.skip("memory in use is looked at by the launcher's supervisor, which is Linux's")
    repo = _tiny(tmp_path / "tiny", USES.replace("TIMES", "40").replace("HOLD", "20"))
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend, memory=256)
    assert r["over_memory"] is True and r["returncode"] is None and r["memory_limit"] == 256, r["output_tail"]
    repo = _tiny(tmp_path / "small", USES.replace("TIMES", "4").replace("HOLD", "1"))
    r = sandbox.run(repo, PYTEST, log=QUIET, backend=backend, memory=256)
    assert r["returncode"] == 0 and r["over_memory"] is False, r["output_tail"]


# ---------------------------------------------------------------------------------------------------- the app
def test_in_the_app_the_sheet_takes_the_memory_limit_and_remembers_it(tmp_path, monkeypatch):
    from test_server import call, wait

    from lantern.server import App, Handler, Store
    monkeypatch.delenv("LANTERN_TEST_MEMORY_MB", raising=False)
    monkeypatch.setenv("LANTERN_SANDBOX", "subprocess")
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.app = App(store, "tok-123", httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
        code, pj = call(base, "/api/projects", "POST", {"path": str(repo)})
        pid = (pj.get("project") or pj)["id"]
        code, d = call(base, f"/api/projects/{pid}/testcmd")
        assert code == 200 and d["memory_mb"] == 2048 and d["memory_range"] == [128, 1 << 20], d
        for bad in (0, 100, "lots", 2.5):
            code, e = call(base, f"/api/projects/{pid}/trace", "POST",
                           {"command": " ".join(PYTEST), "confirm": True, "memory_mb": bad})
            assert code == 400 and "from 128 to 1048576" in e["error"], (bad, code, e)
        code, j = call(base, f"/api/projects/{pid}/trace", "POST",
                       {"command": " ".join(PYTEST), "confirm": True, "memory_mb": 4096})
        assert code == 202, j
        done = wait(base, j["id"], timeout=180)
        assert done["status"] == "done" and done["result"]["returncode"] == 0, done
        assert done["result"]["memory_limit"] == 4096 and done["result"]["over_memory"] is False, done["result"]
        tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
        assert tr["memory_limit"] == 4096 and tr["returncode"] == 0, tr
        code, d = call(base, f"/api/projects/{pid}/testcmd")           # remembered for the next run, of any project
        assert d["memory_mb"] == 4096, d
        code, s = call(base, "/api/state")
        assert s["settings"]["test_memory_mb"] == 4096, s["settings"]
        code, _ = call(base, "/api/settings", "POST", {"privacy": "structure"})      # saving something else keeps it
        assert code == 200 and call(base, "/api/state")[1]["settings"]["test_memory_mb"] == 4096
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_app_page_has_the_field_and_the_words(tmp_path):
    page = (Path(sandbox.__file__).parent / "viewer" / "app.html").read_text(encoding="utf-8")
    assert 'id="testmem"' in page and "memory_mb" in page and "r.over_memory" in page
