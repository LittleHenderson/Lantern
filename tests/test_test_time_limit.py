"""The time a project's tests get (2026-11-13): ten minutes unless the person sets another limit, in the app (the
sheet of "Watch my tests run"), on the command line (`--test-minutes`) or for a whole installation
(LANTERN_TEST_MINUTES). Until then the limit was fixed, and a test suite that needs eleven minutes (Lantern's own
needs more) could never get an answer: stopped by the clock is "Incomplete", never a failure.

On the command line the tests ran in the project's own folder, as the person, and still do unless `--sandbox` is
given. A run over its limit there ended the whole check with a Python error and no result, and left what the
tests had started running."""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from test_sandbox import _tiny

from lantern import _jail, cli, pipeline, release, sandbox, trace

PYTEST = ["python", "-m", "pytest", "-q", "-p", "no:randomly"]


def QUIET(line):
    """A log nobody reads."""


# ------------------------------------------------------------------------------------------------- the limit
def test_ten_minutes_unless_the_person_sets_another_limit(monkeypatch):
    monkeypatch.delenv("LANTERN_TEST_MINUTES", raising=False)
    assert sandbox.time_limit() == 600 == sandbox.WALL_CLOCK
    assert sandbox.time_limit(25) == 1500 and sandbox.time_limit("12") == 720
    monkeypatch.setenv("LANTERN_TEST_MINUTES", "30")
    assert sandbox.time_limit() == 1800
    assert sandbox.time_limit(25) == 1500                   # what is asked for this run wins over the installation's
    for junk in ("", "soon", "-5", "nan", "1e400", "0"):    # not a number of minutes: the ten minutes
        monkeypatch.setenv("LANTERN_TEST_MINUTES", junk)
        assert sandbox.time_limit() == 600, junk
    monkeypatch.setenv("LANTERN_TEST_MINUTES", "100000")    # more than four hours: four hours
    assert sandbox.time_limit() == 240 * 60


@pytest.mark.parametrize("asked", [0, -1, 241, "soon", "", 2.5, True, [10], float("nan")])
def test_a_limit_the_person_asks_for_is_a_whole_number_of_minutes_from_1_to_240(asked):
    """Said, never quietly changed into another number: the person would wait for a run that stops early."""
    with pytest.raises(ValueError, match="from 1 to 240"):
        sandbox.time_limit(asked)


def test_the_sheet_says_the_limit_the_tests_will_have(tmp_path, monkeypatch):
    monkeypatch.delenv("LANTERN_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "docker_ok", lambda: False)
    assert any(d.startswith("10 minutes, then") for d in sandbox.describe(tmp_path, "python")["details"])
    details = sandbox.describe(tmp_path, "python", minutes=25)["details"]
    assert any(d.startswith("25 minutes, then") for d in details) and not any("10 minutes" in d for d in details), details
    assert any(d.startswith("1 minute, then") for d in sandbox.describe(tmp_path, "python", minutes=1)["details"])


@pytest.mark.skipif(os.name != "posix", reason="the launcher and its limits are POSIX's")
def test_the_launcher_gives_the_tests_processor_time_for_the_whole_limit(tmp_path):
    """Each process of a run is also held to an amount of processor time, so a test that spins is ended even if the
    clock is lost sight of. It was 600 seconds whatever the limit: a longer limit would have ended at ten minutes
    of work all the same.
    A limit that is already set is never raised: where these tests themselves run under one (Lantern's own tests
    in the sandbox, whose launcher has set theirs), the launcher gives the smaller of the two. Until 2026-11-13
    this test took for granted that nothing holds it, and failed in the sandbox for that."""
    import resource
    show = [sys.executable, "-c", "import resource; print('CPU', resource.getrlimit(resource.RLIMIT_CPU)[0])"]
    held = resource.getrlimit(resource.RLIMIT_CPU)[1]         # what this process may not go over, set by who started it

    def given(policy: dict, under=None) -> str:
        policy = {"writable": [str(tmp_path)], "nobody": False, "python": True, "net": False, "must": True, **policy}
        r = subprocess.run([sys.executable, "-c", "import sys; from lantern._jail import main; main(sys.argv[1:])",
                            json.dumps(policy), "--", *show], capture_output=True, text=True, encoding="utf-8",
                           timeout=120, cwd=Path(_jail.__file__).resolve().parent.parent,
                           preexec_fn=None if under is None else lambda: resource.setrlimit(resource.RLIMIT_CPU, (under, under)))
        return r.stdout + r.stderr

    for policy, want in (({}, 600), ({"cpu": 1500}, 1500), ({"cpu": 60}, 600), ({"cpu": "many"}, 600),
                         ({"cpu": 600 * 64}, 38400),                # ten minutes on each of 64 processors
                         ({"cpu": 240 * 60 * 4096}, 58982400), ({"cpu": 240 * 60 * 4096 + 1}, 600)):
        want = want if held == resource.RLIM_INFINITY else min(want, held)
        said = given(policy)
        assert f"CPU {want}\n" in said, (policy, held, said)
    # ... and the same asked under a limit that is already there: the smaller one stands, whoever set it
    for under, policy, want in ((900, {"cpu": 1500}, 900), (900, {}, 600), (300, {}, 300), (2000, {"cpu": 1500}, 1500)):
        if held != resource.RLIM_INFINITY and under > held:
            continue                                            # this process may not set that much itself
        said = given(policy, under=under)
        assert f"CPU {want}\n" in said, (under, policy, said)


def _processors(monkeypatch, n: int) -> None:
    """This computer as one with `n` processors, for what Lantern asks about it."""
    monkeypatch.setattr(os, "cpu_count", lambda: n)
    if hasattr(os, "sched_getaffinity"):
        monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(n)))


@pytest.mark.parametrize("processors", [1, 8])
def test_a_run_given_more_time_is_started_with_it(processors, tmp_path, monkeypatch):
    """The processor time is the clock's limit on every processor the run may use: a test that works on eight at
    once has used eight seconds of it after one. Until 2026-11-13 it was the clock's limit once, so such a test
    was ended by it long before the clock, and that read as tests that failed."""
    _processors(monkeypatch, processors)
    seen = {}

    def stream(cmd, cwd, env, timeout, log, **more):
        seen["timeout"] = timeout
        if os.name == "posix":
            seen["policy"] = json.loads(cmd[cmd.index("--") - 1])
        return 0, "", False

    monkeypatch.setattr(sandbox, "_stream", stream)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess")
    assert seen["timeout"] == 600 and seen.get("policy", {"cpu": 600 * processors})["cpu"] == 600 * processors
    sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", timeout=1500)
    assert seen["timeout"] == 1500 and seen.get("policy", {"cpu": 1500 * processors})["cpu"] == 1500 * processors
    sandbox.run(repo, PYTEST, log=QUIET, backend="subprocess", timeout=60)       # never under ten minutes each
    assert seen["timeout"] == 60 and seen.get("policy", {"cpu": 600 * processors})["cpu"] == 600 * processors


# -------------------------------------------------------------------------------------------- the check's record
def _stopped_by_the_clock(seen: dict):
    def run(repo, words, log=print, timeout=sandbox.WALL_CLOCK, **more):
        seen["timeout"] = timeout
        return sandbox.Result(pairs=[], returncode=None, timed_out=True, cancelled=False, blocked=[], not_ended=[],
                              backend="subprocess", language="python", traced=True, own_network=False,
                              output_tail="", stderr_tail="")
    return run


def test_the_check_gives_the_tests_the_time_the_person_set_and_says_which_limit_stopped_them(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(sandbox, "run", _stopped_by_the_clock(seen))
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    res = pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=QUIET, test_minutes=25)
    assert seen["timeout"] == 1500
    tr = json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]
    assert tr["timed_out"] is True and tr["returncode"] is None and tr["time_limit"] == 1500, tr
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    rel = rd["release"]
    tests = next(c for c in rel["criteria"] if c["id"] == "tests")
    assert res["release"] == rel["decision"] == "Incomplete" and tests["state"] == "missing", rel
    assert "stopped at the time limit (25 minutes)" in tests["why"], tests
    assert "--test-minutes" in tests["fix"] and "more time" in tests["fix"], tests
    # the readiness check says the same: tests that did not finish have not failed (until 2026-11-13 it read "fail")
    check = next(c for cat in rd["categories"] for c in cat["checks"] if c["id"] == "tests-pass")
    assert check["status"] == "skip" and check.get("required") is True and "time limit" in check["evidence"], check


def test_without_a_word_from_the_person_the_check_gives_ten_minutes(tmp_path, monkeypatch):
    monkeypatch.delenv("LANTERN_TEST_MINUTES", raising=False)
    seen = {}
    monkeypatch.setattr(sandbox, "run", _stopped_by_the_clock(seen))
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=PYTEST, sandbox=True, offline=True, log=QUIET)
    assert seen["timeout"] == 600
    tests = release._tests(True, {"trace": {"ran": True, "returncode": None, "timed_out": True, "time_limit": 600}})
    assert tests["state"] == "missing" and "stopped at the time limit (10 minutes)" in tests["why"], tests
    # a record written before the limit was written down still reads
    older = release._tests(True, {"trace": {"ran": True, "returncode": None, "timed_out": True}})
    assert older["state"] == "missing" and "stopped at the time limit." in older["why"], older
    planted = release._tests(True, {"trace": {"ran": True, "returncode": None, "timed_out": True, "time_limit": "<b>"}})
    assert "<b>" not in planted["why"], planted


# ------------------------------------------------------------------------------------------------ the command line
SLOW = '''
import subprocess, sys, time

def test_slow():
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)  # MARK"])   # and something it started
    time.sleep(300)
'''


def _slow(folder: Path) -> tuple[Path, str]:
    """A project whose one test starts a program of its own and then sleeps, and the mark every program of a run
    on it carries: the project's folder is named with it, and so is the program the test starts."""
    mark = uuid.uuid4().hex
    return _tiny(folder / f"slow-{mark}", SLOW.replace("MARK", mark)), mark


def _marked(mark: str, also: bytes = b"") -> set[int]:
    """The processes of this computer, other than this one, whose command line carries the mark (and `also`)."""
    found = set()
    for pid in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if pid.isdigit() and int(pid) != os.getpid():
            try:
                words = Path("/proc", pid, "cmdline").read_bytes()
            except OSError:
                continue
            if mark.encode() in words and also in words:
                found.add(int(pid))
    return found


def _started(mark: str) -> set[int]:
    """The program the slow test started."""
    return _marked(mark, b"time.sleep(300)")


def _none_left(mark: str, seconds: float = 10) -> bool:
    """Whether nothing of the run with this mark is running any more: not the tests, not what they started.
    Whatever is, is ended here by its own number, so a failing test leaves nothing either."""
    deadline = time.monotonic() + seconds
    while _marked(mark) and time.monotonic() < deadline:
        time.sleep(0.1)
    left = _marked(mark)
    for pid in left:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return not left


def test_on_the_command_line_a_test_run_over_its_limit_ends_with_a_result(tmp_path, monkeypatch, capsys):
    """`lantern analyze PATH --trace -- python -m pytest -q`: the older way, in the project's folder. Over the
    limit it ended with a Python error (subprocess.TimeoutExpired), no result file, and the tests' own programs
    still running."""
    monkeypatch.setattr(trace, "DEFAULT_TIMEOUT", 3)
    repo, mark = _slow(tmp_path)
    t0 = time.monotonic()
    try:
        code = cli.main(["analyze", str(repo), "--offline", "--trace", "--", "python", "-m", "pytest", "-q"])
    except BaseException:
        _none_left(mark, 0)
        raise
    took = time.monotonic() - t0
    said = capsys.readouterr()
    assert code == 0 and took < 120, (code, took, said.err[-2000:])
    assert "stopped at the time limit" in said.out, said.out[-2000:]
    tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
    assert tr["returncode"] is None and tr["timed_out"] is True and tr["time_limit"] == 3, tr
    rel = json.loads((repo / ".lantern" / "readiness.json").read_text(encoding="utf-8"))["release"]
    assert rel["decision"] == "Incomplete", rel
    assert "stopped at the time limit" in next(c for c in rel["criteria"] if c["id"] == "tests")["why"]
    assert _none_left(mark), "what the tests started is still running"


def test_lantern_trace_over_its_limit_says_so_and_changes_nothing(tmp_path, monkeypatch, capsys):
    """`lantern trace PATH -- python -m pytest -q` ended the same way: a Python error, and the programs left."""
    repo, mark = _slow(tmp_path)
    assert cli.main(["analyze", str(repo), "--offline"]) == 0
    capsys.readouterr()
    graph = (repo / ".lantern" / "graph.json").read_bytes()
    monkeypatch.setattr(trace, "DEFAULT_TIMEOUT", 3)
    try:
        code = cli.main(["trace", str(repo), "--", "python", "-m", "pytest", "-q"])
    except BaseException:
        _none_left(mark, 0)
        raise
    said = capsys.readouterr()
    assert code == 1 and "stopped at the time limit (3 seconds)" in said.err and "--test-minutes" in said.err, said.err
    assert (repo / ".lantern" / "graph.json").read_bytes() == graph
    assert _none_left(mark), "what the command started is still running"
    with pytest.raises(SystemExit):
        cli.main(["trace", str(repo), "--test-minutes", "0", "--", "python", "-m", "pytest", "-q"])
    assert "from 1 to 240" in capsys.readouterr().err


@pytest.mark.skipif(not os.path.isdir("/proc") or os.name != "posix", reason="the programs are looked for in /proc")
@pytest.mark.parametrize("how", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_on_the_command_line_lantern_told_to_end_takes_the_tests_with_it(tmp_path, how):
    """The older way runs the tests in a group of their own, so that the whole group can be ended at the limit.
    The keyboard's Ctrl-C and a closed terminal then no longer reach the tests by themselves: Lantern has to end
    them when it is told to end, and does."""
    repo, mark = _slow(tmp_path)
    lantern = subprocess.Popen([sys.executable, "-m", "lantern.cli", "analyze", str(repo), "--offline", "--trace", "--",
                                "python", "-m", "pytest", "-q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               cwd=Path(cli.__file__).resolve().parent.parent, start_new_session=True)
    try:
        deadline = time.monotonic() + 120
        while not _started(mark) and lantern.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        assert _started(mark), "the tests never started their program"
        lantern.send_signal(getattr(signal, how))       # Lantern alone, as the terminal now does it
        assert lantern.wait(timeout=60) != 0
        assert _none_left(mark), f"Lantern ended on {how} and the tests' programs went on"
        assert not (repo / ".lantern" / "run.json").exists()        # stopped part-way: no result was written
    finally:
        if lantern.poll() is None:
            lantern.kill()
        _none_left(mark, 0)


def test_on_the_command_line_require_passed_fails_a_run_that_was_stopped_by_the_clock(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(trace, "DEFAULT_TIMEOUT", 3)
    repo = _tiny(tmp_path / "slow", "import time\n\ndef test_slow():\n    time.sleep(300)\n")
    code = cli.main(["analyze", str(repo), "--offline", "--require", "passed", "--trace", "--", "python", "-m", "pytest", "-q"])
    assert code == 1 and "the release decision is Incomplete" in capsys.readouterr().err


WRITES = '''
from pathlib import Path

def test_it_leaves_a_file_beside_itself():
    (Path(__file__).parent / "left-by-the-tests.txt").write_text("x")
'''


def test_on_the_command_line_the_tests_run_in_the_sealed_box_when_asked(tmp_path, capsys):
    """`--sandbox`: the way the app runs them, on a copy the tests may change and that is thrown away. Without it
    the older way stays: in the project's own folder."""
    repo = _tiny(tmp_path / "writes", WRITES)
    code = cli.main(["analyze", str(repo), "--offline", "--trace", "--sandbox", "--", "python", "-m", "pytest", "-q"])
    said = capsys.readouterr()
    assert code == 0, said.err[-2000:]
    tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
    assert tr["ran"] is True and tr["backend"] in ("subprocess", "docker") and tr["time_limit"] == 600, tr
    assert tr["returncode"] == 0 and tr["blocked"] == [], tr
    assert not (repo / "tests" / "left-by-the-tests.txt").exists()   # what the tests wrote went with their copy
    code = cli.main(["analyze", str(repo), "--offline", "--trace", "--", "python", "-m", "pytest", "-q"])
    capsys.readouterr()
    tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
    assert code == 0 and tr["returncode"] == 0 and "backend" not in tr, tr
    assert (repo / "tests" / "left-by-the-tests.txt").exists()        # the older way, as before


def test_on_the_command_line_the_sealed_box_takes_a_test_command_only(tmp_path, capsys):
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    code = cli.main(["analyze", str(repo), "--offline", "--trace", "--sandbox", "--", "python", "-c", "print('hello')"])
    said = capsys.readouterr()
    assert code == 2 and "only a test command can run here" in said.err, said.err
    assert not (repo / ".lantern" / "run.json").exists()
    with pytest.raises(SystemExit):                          # nothing to run in it
        cli.main(["analyze", str(repo), "--offline", "--sandbox"])
    assert "--sandbox" in capsys.readouterr().err
    with pytest.raises(SystemExit):                          # and no tests to give the time to
        cli.main(["analyze", str(repo), "--offline", "--test-minutes", "20"])
    assert "--test-minutes" in capsys.readouterr().err


def test_on_the_command_line_the_limit_is_given_in_minutes(tmp_path, monkeypatch, capsys):
    seen = []

    def analyze(repo, out, privacy="full", trace_cmd=None, no_scan=False, **more):
        seen.append(more)
        return {"counts": {}, "release": "Incomplete"}

    monkeypatch.setattr(pipeline, "analyze", analyze)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    assert cli.main(["analyze", str(repo), "--trace", "--sandbox", "--test-minutes", "25", "--", "python", "-m", "pytest"]) == 0
    assert seen[-1]["sandbox"] is True and seen[-1]["test_minutes"] == 25, seen
    assert cli.main(["analyze", str(repo), "--trace", "--", "python", "-m", "pytest"]) == 0
    assert not seen[-1].get("sandbox") and seen[-1].get("test_minutes") is None, seen
    for bad in ("0", "241", "soon"):
        with pytest.raises(SystemExit):
            cli.main(["analyze", str(repo), "--trace", "--test-minutes", bad, "--", "python", "-m", "pytest"])
        assert "from 1 to 240" in capsys.readouterr().err


def test_the_older_way_keeps_its_fifteen_minutes_unless_a_limit_is_given(tmp_path, monkeypatch):
    """Nothing that ran before is cut short: without a word, the command line's own way has the 900 seconds it had."""
    monkeypatch.delenv("LANTERN_TEST_MINUTES", raising=False)
    seen = {}

    def run_trace(repo, command, timeout=None):
        seen["timeout"] = timeout
        return {"pairs": [], "returncode": 0, "stderr_tail": ""}

    monkeypatch.setattr(trace, "run_trace", run_trace)
    repo = _tiny(tmp_path / "tiny", "def test_ok():\n    assert True\n")
    out = repo / ".lantern"
    out.mkdir()
    pipeline.analyze(repo, out, trace_cmd=PYTEST, offline=True, log=QUIET)
    assert seen["timeout"] is None and trace.DEFAULT_TIMEOUT == 900
    assert json.loads((out / "run.json").read_text(encoding="utf-8"))["trace"]["time_limit"] == 900
    pipeline.analyze(repo, out, trace_cmd=PYTEST, offline=True, log=QUIET, test_minutes=25)
    assert seen["timeout"] == 1500
    monkeypatch.setenv("LANTERN_TEST_MINUTES", "30")
    pipeline.analyze(repo, out, trace_cmd=PYTEST, offline=True, log=QUIET)
    assert seen["timeout"] == 1800


# ---------------------------------------------------------------------------------------------------- the app
def test_in_the_app_the_sheet_takes_the_limit_and_remembers_it(tmp_path, monkeypatch):
    from test_server import call, wait

    from lantern.server import App, Handler, Store
    monkeypatch.delenv("LANTERN_TEST_MINUTES", raising=False)
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
        assert code == 200 and d["minutes"] == 10 and d["minutes_range"] == [1, 240], d
        assert any(x.startswith("10 minutes, then") for x in d["sandbox"]["details"]), d
        for bad in (0, 241, "soon", 2.5):
            code, e = call(base, f"/api/projects/{pid}/trace", "POST",
                           {"command": " ".join(PYTEST), "confirm": True, "minutes": bad})
            assert code == 400 and "from 1 to 240" in e["error"], (bad, code, e)
        code, j = call(base, f"/api/projects/{pid}/trace", "POST",
                       {"command": " ".join(PYTEST), "confirm": True, "minutes": 25})
        assert code == 202, j
        done = wait(base, j["id"], timeout=180)
        assert done["status"] == "done" and done["result"]["returncode"] == 0, done
        assert done["result"]["time_limit"] == 1500, done["result"]
        tr = json.loads((repo / ".lantern" / "run.json").read_text(encoding="utf-8"))["trace"]
        assert tr["time_limit"] == 1500 and tr["returncode"] == 0, tr
        code, d = call(base, f"/api/projects/{pid}/testcmd")           # remembered for the next run, of any project
        assert d["minutes"] == 25 and any(x.startswith("25 minutes, then") for x in d["sandbox"]["details"]), d
        code, s = call(base, "/api/state")
        assert s["settings"]["test_minutes"] == 25, s["settings"]
        code, _ = call(base, "/api/settings", "POST", {"privacy": "structure"})      # saving something else keeps it
        assert code == 200 and call(base, "/api/state")[1]["settings"]["test_minutes"] == 25
    finally:
        httpd.shutdown()
        httpd.server_close()
