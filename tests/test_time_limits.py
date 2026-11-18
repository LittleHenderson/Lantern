"""Every check has a time limit, and the limits come in an order that lets each one say where the run stood.

On 2026-11-17 a job of CI's tests printed 89% and then nothing for 2 h 39 min, until it was cancelled by hand. No
step and no job had a limit of its own, so the only limit was GitHub's six hours, and nothing said where the run
stood. Now, from the first to the last:

1. a test that runs past `FAULTHANDLER` seconds has every thread of the test run print where it waits, while the
   test is still running (pytest's `faulthandler_timeout`, pyproject.toml);
2. the no-network runner lists every process of a run past its deadline, thread by thread, asks the tests to end
   (SIGINT, so pytest says where it stood) and ends what is left (`tools/netless.py --deadline`, result 7);
3. the step's own limit, after the runner's deadline and the time it gives a late run to end;
4. the job's limit, at least the sum of its steps' own limits and `SETUP` minutes for the steps between them, so
   that a step's own limit comes first and the steps after it (the summary) still run.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import netless  # noqa: E402

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
FAULTHANDLER = 900               # seconds a single test may run before every thread says where it waits
SETUP = 20                       # minutes a job keeps for the steps without a limit of their own (measured: about 4)
LATE_END = 60                    # seconds the runner takes, past its grace, to end what is left and write its record
RUNS_TESTS = re.compile(r"\s-m pytest\b|^\s*(?:\w+=\S*\s+)*pytest\s|tools/audit\.sh", re.M)
STEPS_THAT_RUN_TESTS = 9         # the four passes and the audit of the Linux jobs, Windows, macOS, the browsers, the wheel


def _jobs():
    for path in WORKFLOWS:
        for name, job in (yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}).items():
            yield path.name, name, job


def test_every_job_has_a_time_limit():
    jobs = list(_jobs())
    assert {wf for wf, _, _ in jobs} == {p.name for p in WORKFLOWS} and len(jobs) >= len(WORKFLOWS)
    late = [(wf, name, job.get("timeout-minutes")) for wf, name, job in jobs
            if not (type(job.get("timeout-minutes")) is int and 0 < job["timeout-minutes"] <= 300)]
    assert not late, late


def test_every_step_that_runs_tests_has_a_limit_of_its_own_below_its_jobs():
    found = []
    for wf, name, job in _jobs():
        for step in job.get("steps") or []:
            if not RUNS_TESTS.search(str(step.get("run") or "")):
                continue
            limit, what = step.get("timeout-minutes"), (wf, name, step.get("name") or step["run"][:60])
            assert type(limit) is int and 0 < limit < job["timeout-minutes"], (what, limit, job["timeout-minutes"])
            found.append(what)
    assert len(found) == STEPS_THAT_RUN_TESTS, found        # the pattern still finds the steps it is about


def test_a_jobs_limit_leaves_its_steps_their_own():
    for wf, name, job in _jobs():
        own = sum(step.get("timeout-minutes", 0) for step in job.get("steps") or [])
        assert not own or job["timeout-minutes"] >= own + SETUP, (wf, name, own, job["timeout-minutes"])


def test_the_no_network_runner_ends_a_late_run_before_the_steps_limit_and_after_a_hung_test_spoke(pytestconfig):
    seen = []
    for wf, name, job in _jobs():
        for step in job.get("steps") or []:
            run = str(step.get("run") or "")
            if "tools/netless.py" not in run:
                continue
            m = re.search(r"tools/netless\.py --watch \S+ --deadline (\d+) --", run)
            assert m, run                                   # a deadline, and the watch it needs
            deadline = int(m.group(1)) * 60
            assert float(pytestconfig.getini("faulthandler_timeout")) < deadline
            assert deadline + netless.GRACE + LATE_END <= step["timeout-minutes"] * 60, (deadline, step["timeout-minutes"])
            seen.append((wf, name))
    assert seen == [("ci.yml", "test")], seen


def test_a_test_that_runs_long_has_every_thread_say_where_it_waits(pytestconfig, tmp_path):
    assert float(pytestconfig.getini("faulthandler_timeout")) == FAULTHANDLER
    assert pytestconfig.pluginmanager.has_plugin("faulthandler")
    for path in WORKFLOWS:                                  # and no line that starts the tests sets it otherwise
        text = path.read_text(encoding="utf-8")
        assert "no:faulthandler" not in text and "faulthandler_timeout" not in text, path.name
    # what the setting does: in a run where a test may take 2 seconds, the test that takes 6 has the stack of every
    # thread printed while it runs (here, its own and a helper thread's), and the one that takes none has nothing
    test = tmp_path / "test_waits.py"
    test.write_text("import threading, time\n\n\ndef test_waits():\n"
                    "    threading.Thread(target=time.sleep, args=(30,), daemon=True).start()\n    time.sleep(6)\n\n\n"
                    "def test_quick():\n    pass\n", encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "faulthandler_timeout=2",
                        str(test)], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0 and "2 passed" in r.stdout, r.stdout + r.stderr
    assert r.stderr.count("Timeout (0:00:02)!") == 1 and "in test_waits" in r.stderr, r.stderr
    assert r.stderr.count("Thread 0x") >= 2 and "test_quick" not in r.stderr, r.stderr
