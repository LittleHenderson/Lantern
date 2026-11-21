"""The limit on the programs a project's tests run at once (a firm pass or fail, stage 3, step 5, 2026-11-21).

On the website a check's tests run on a machine of their own (`lantern.runner`), as an ordinary user whom nothing
else of that machine runs as. A test that starts programs without end (a flood: each program waits, and more keep
coming) is stopped at a limit on that user's programs, their threads counted as the kernel counts them. Two parts
hold it: the launcher's supervisor looks from outside, as it does for the memory, and stops the run once the tests
run more than their limit, with a line of its own and a result of its own (`_jail.OVER_PROCESSES`); and the kernel
refuses a new program at twice the limit (`RLIMIT_NPROC`), so that a flood never gets further while the supervisor
has not looked yet. Tests stopped there did not finish: "Incomplete", never a failure and never a pass, as at the
memory limit and at the clock.

Linux counts a user's programs on the whole computer, so the limit is asked for only where the tests run as a user
whom nothing else runs as; a launcher asked for it that does not change user starts nothing.

Each case stands beside its twin: a flood beside a run of a few programs that ends as it would, the launcher's line
and result together beside either alone."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_sandbox import _tiny

from lantern import _jail, release, runner, sandbox

LINUX = sys.platform.startswith("linux")
ROOT = LINUX and os.geteuid() == 0
as_root = pytest.mark.skipif(not ROOT, reason="the limit holds a user of the tests' own, which only root can give them")
TOP = Path(_jail.__file__).resolve().parent.parent
PYTEST = ["python", "-m", "pytest", "-q", "-s", "-p", "no:randomly"]
SYSTEM_PYTHON = shutil.which("python3", path="/usr/bin:/bin") or sys.executable


def QUIET(line):
    """A log nobody reads."""


# A flood: programs that wait, and one that starts more of them for as long as it is let.
FLOOD = '''
import os, time
started = 0
while started < 100000:
    try:
        pid = os.fork()
    except OSError:
        time.sleep(0.01)          # refused by the kernel's wall: tried again, as a flood does
        continue
    if pid == 0:
        time.sleep(120)
        os._exit(0)
    started += 1
'''
# Its twin: a few programs that end, each waited for.
FEW = '''
import os
for _ in range(20):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
print("twenty programs started and ended")
'''


def _launch(tmp_path: Path, code: str, **policy) -> subprocess.CompletedProcess:
    """`code` run by the launcher with `policy`, as nobody where this is root."""
    os.chmod(tmp_path, 0o755)
    rules = {"writable": [str(tmp_path)], "nobody": True, "python": True, "net": False, "must": True, **policy}
    return subprocess.run([sys.executable, "-c", "import sys; from lantern._jail import main; main(sys.argv[1:])",
                           json.dumps(rules), "--", SYSTEM_PYTHON, "-I", "-c", code], capture_output=True, text=True,
                          encoding="utf-8", timeout=180, cwd=TOP)


def _limit_lines(output: str) -> list[list[str]]:
    return [line.split() for line in output.splitlines() if line.startswith(_jail.LIMIT_MARK + " processes ")]


def _nobodys() -> list[int]:
    return _jail.processes_of(_jail.NOBODY)


# --------------------------------------------------------------------------------------------- the launcher
@as_root
def test_the_launcher_stops_a_flood_at_the_limit_and_says_so(tmp_path):
    r = _launch(tmp_path, FLOOD, processes=64)
    assert r.returncode == _jail.OVER_PROCESSES, (r.returncode, r.stderr[-2000:])
    said = _limit_lines(r.stderr)
    assert len(said) == 1 and said[0][3] == "64" and int(said[0][2]) > 64, r.stderr[-2000:]
    # never past the kernel's wall, and nothing of the flood is left
    assert int(said[0][2]) <= 2 * 64 + 2, said
    assert _nobodys() == []


@as_root
def test_a_few_programs_under_the_limit_end_as_they_would(tmp_path):
    r = _launch(tmp_path, FEW, processes=64)
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    assert "twenty programs started and ended" in r.stdout and not _limit_lines(r.stderr)


@as_root
def test_without_a_limit_the_launcher_sets_none(tmp_path):
    """The cloud service's steps and the tests on a person's computer ask for no such limit, and get none."""
    show = "import resource; print('NPROC', resource.getrlimit(resource.RLIMIT_NPROC)[0])"
    limited, unlimited = _launch(tmp_path, show, processes=64), _launch(tmp_path, show)
    assert limited.returncode == 0 and "NPROC 128" in limited.stdout, (limited.stdout, limited.stderr)
    assert unlimited.returncode == 0 and "NPROC 128" not in unlimited.stdout, (unlimited.stdout, unlimited.stderr)


@pytest.mark.skipif(not LINUX, reason="the launcher's supervisor, which counts the programs, is Linux's")
@pytest.mark.parametrize("asked", [64, 0, -3, True, "lots", 10**9])
def test_a_limit_that_is_no_whole_number_of_programs_is_no_limit(asked, tmp_path):
    assert _jail._processes({"processes": asked}) == (asked if asked == 64 else 0)


@pytest.mark.skipif(os.name != "posix", reason="the launcher of POSIX systems")
def test_a_limit_on_programs_is_refused_where_the_tests_keep_the_launchers_user(tmp_path):
    """Linux counts the programs of a user on the whole computer: held to the launcher's own user, the tests would
    be counted with every program of the person's. A launcher asked for the limit that does not change user starts
    nothing, whatever `must` says."""
    for must in (True, False):
        r = _launch(tmp_path, "print('ran')", nobody=False, processes=64, must=must)
        assert r.returncode == _jail.UNAVAILABLE and "ran" not in r.stdout, (must, r.returncode, r.stdout, r.stderr)
        assert f"{_jail.MARK} processes" in r.stderr and "processes" in _jail.REASONS
    twin = _launch(tmp_path, "print('ran')", nobody=False)
    assert twin.returncode == 0 and "ran" in twin.stdout, (twin.returncode, twin.stderr)


# ------------------------------------------------------------------------------------------------ the sandbox
@as_root
def test_tests_that_flood_the_machine_with_programs_are_stopped_and_it_is_said(tmp_path):
    repo = _tiny(tmp_path / "flood", "def test_floods():\n" + "".join("    " + line + "\n" for line in FLOOD.strip().splitlines()))
    lines: list[str] = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", processes=64)
    assert r["over_processes"] is True and r["processes_limit"] == 64, (r["returncode"], r["output_tail"][-2000:])
    assert r["returncode"] is None and r["timed_out"] is False and r["cancelled"] is False and r["over_memory"] is False
    assert r["not_ended"] == [] and _nobodys() == []
    said = [x for x in lines if "more programs at once than their limit (64" in x]
    assert said and "every process it started was ended" in said[0], lines[-8:]
    assert release._tests(True, {"trace": {"ran": True, **{k: r[k] for k in
                                           ("returncode", "over_memory", "over_processes", "processes_limit",
                                            "timed_out", "blocked")}}})["state"] == "missing"


@as_root
def test_the_same_tests_with_a_few_programs_pass(tmp_path):
    repo = _tiny(tmp_path / "few", "def test_a_few():\n" + "".join("    " + line + "\n" for line in FEW.strip().splitlines()))
    lines: list[str] = []
    r = sandbox.run(repo, PYTEST, log=lines.append, backend="subprocess", processes=64)
    assert r["returncode"] == 0 and r["over_processes"] is False and r["processes_limit"] == 64, r["output_tail"][-2000:]
    assert not any("more programs at once" in x for x in lines), lines


@as_root
def test_the_launchers_line_alone_and_its_result_alone_are_the_tests_own(tmp_path):
    """The launcher says it in a line of the run's output together with a result of its own. A test that prints
    the line and fails has failed, and so has one that ends with that result and no line."""
    repo = _tiny(tmp_path / "says", "def test_says_it():\n    print('LANTERN-SANDBOX-LIMIT: processes 99 64')\n    assert False\n")
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", processes=64)
    assert r["returncode"] == 1 and r["over_processes"] is False, r["output_tail"][-2000:]
    repo = _tiny(tmp_path / "ends", f"import os\n\ndef test_ends_with_it():\n    os._exit({_jail.OVER_PROCESSES})\n")
    r = sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", processes=64)
    assert r["returncode"] == _jail.OVER_PROCESSES and r["over_processes"] is False, r["output_tail"][-2000:]


def test_the_line_and_the_result_together_are_read_only_where_a_limit_was_asked_for():
    line = f"{_jail.LIMIT_MARK} processes 130 64"
    assert sandbox._over_processes(_jail.OVER_PROCESSES, line) is True
    assert sandbox._over_processes(_jail.OVER_PROCESSES, "nothing said") is False
    assert sandbox._over_processes(1, line) is False
    assert sandbox._over_processes(_jail.OVER_PROCESSES, f"{_jail.LIMIT_MARK} processes many 64") is False
    assert sandbox._over_processes(_jail.OVER_PROCESSES, f"{_jail.LIMIT_MARK} memory 130 64") is False
    assert sandbox._over_processes(_jail.OVER_PROCESSES, f"{_jail.LIMIT_MARK} processes 130 64 and more") is False


def test_the_launchers_line_is_read_where_the_tests_left_a_line_unfinished():
    """Found 2026-11-21 by the test machine's image: a test runner that writes a test's name and waits for its
    outcome (`unittest -v`: "test_x (...) ... ") leaves the line open, and the launcher's line, which it writes when
    it stops the run, is then the end of that line. Read only from the line's start, a run stopped at a limit read
    as tests that ended with the launcher's number, failed: for the programs and for the memory alike."""
    open_line = "test_programs_without_end (test_it.T.test_programs_without_end) ... "
    assert sandbox._over_processes(_jail.OVER_PROCESSES, open_line + f"{_jail.LIMIT_MARK} processes 8190 4096") is True
    assert sandbox._over_memory(_jail.OVER_MEMORY, open_line + f"{_jail.LIMIT_MARK} memory 300 200") is True
    # the twins: the mark with anything after its numbers, and the result alone, are still the tests' own
    assert sandbox._over_processes(_jail.OVER_PROCESSES, open_line + f"{_jail.LIMIT_MARK} processes 8190 4096 x") is False
    assert sandbox._over_memory(_jail.OVER_MEMORY, open_line + f"{_jail.LIMIT_MARK} memory 300 200 x") is False
    assert sandbox._over_memory(_jail.OVER_MEMORY, open_line + "nothing said") is False


@pytest.mark.parametrize("asked", [0, 31, 1 << 17, True, 2.5, "64"])
def test_a_limit_on_programs_is_a_whole_number_in_its_range(asked, tmp_path):
    repo = _tiny(tmp_path / "t", "def test_ok():\n    assert True\n")
    with pytest.raises(ValueError):
        sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", processes=asked)


def test_a_limit_on_programs_is_for_the_restricted_process_on_linux(tmp_path, monkeypatch):
    """A tests' container and the systems with no supervisor to count are not held to it: asked there, the run is
    refused before anything starts."""
    repo = _tiny(tmp_path / "t", "def test_ok():\n    assert True\n")
    with pytest.raises(ValueError):
        sandbox.run(repo, PYTEST, log=QUIET, backend="docker", processes=64)
    monkeypatch.setattr(sandbox, "_LINUX", False)
    with pytest.raises(ValueError):
        sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", processes=64)


# ---------------------------------------------------------------------------------------- what is said of it
def test_the_release_decision_and_the_readiness_say_the_tests_did_not_finish(tmp_path):
    from lantern import readiness
    from lantern.graph import Graph
    stopped = {"ran": True, "returncode": None, "timed_out": False, "over_memory": False, "over_processes": True,
               "processes_limit": 64, "blocked": []}
    c = release._tests(True, {"trace": stopped})
    assert c["state"] == "missing" and "more programs at once than their limit (64" in c["why"], c
    assert "not a pass and not a failure" in c["why"]
    failed = dict(stopped, returncode=1, over_processes=False)
    assert release._tests(True, {"trace": failed})["state"] == "failed"
    repo = readiness.Repo(_tiny(tmp_path / "t", "def test_ok():\n    assert True\n"))
    checks = {c["id"]: c for c in readiness.check_tests(repo, Graph(str(repo.root)), {"trace": stopped})}
    assert checks["tests-pass"]["status"] == "skip" and "programs" in checks["tests-pass"]["evidence"], checks
    checks = {c["id"]: c for c in readiness.check_tests(repo, Graph(str(repo.root)), {"trace": failed})}
    assert checks["tests-pass"]["status"] == "fail", checks


def test_the_words_for_the_limit_are_lanterns_own():
    assert sandbox.processes_words(64) == "64 programs at once, their threads counted"
    assert sandbox.processes_words(4096) == "4,096 programs at once, their threads counted"
    for odd in (None, "64", True, -1, 0, 2.5):
        assert sandbox.processes_words(odd) == ""


# ------------------------------------------------------------------------------------------------ the runner
def test_the_test_machines_program_holds_the_tests_to_its_limit_on_programs(tmp_path, monkeypatch):
    project = tmp_path / "p"
    project.mkdir()
    (project / "test_it.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    runner.pack(project, tmp_path / "c.zip", ["python", "-m", "pytest", "-q"], minutes=2, memory=512)
    monkeypatch.setattr(runner, "walls", lambda: [{"wall": "every wall", "stands": True, "why": ""}])
    seen: dict = {}

    def run(repo, words, log=print, **more):
        seen.update(more)
        return sandbox.Result(pairs=[], returncode=0, timed_out=False, over_memory=False, over_processes=False,
                              processes_limit=more.get("processes"), cancelled=False, blocked=[], not_ended=[],
                              backend="subprocess", language="python", traced=True, own_network=True,
                              off_network=True, memory_limit=512, output_tail="", stderr_tail="")
    monkeypatch.setattr(sandbox, "run", run)
    result = runner.check(tmp_path / "c.zip", tmp_path / "work", log=QUIET)
    assert result["state"] == "done", result
    assert seen["processes"] == runner.PROCESSES == 4096
    assert result["check"]["processes"] == runner.PROCESSES
