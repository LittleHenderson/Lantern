"""Every test runs cut off from the developer's keys, saved sign-ins and the internet.

When pytest loads this file, before any test file is imported, the whole run (and through its environment every
program it starts) gets: an empty temporary home folder, no key, token or password variable, LANTERN_OFFLINE=1,
LANTERN_NO_REAL_PROVIDERS=1, and the network guard (tools/netguard/lantern_netguard.py), which refuses and writes down
anything that is not for this computer. A set-up step shared by a whole file is covered like a test: an independent
review on 2026-11-09 found a test reaching a real model, and on 2026-11-10 a trace found 11 outside connections per
run, all from shared set-up steps, which pytest builds before any per-test fixture.

An attempt fails the test it happened in, also when the code under test hides the error. A test that is there to see
the refusal says so: `@pytest.mark.network_refused("why")`; tests/test_isolation.py lists those tests.

A run or a set of explanations a test asks the cloud service for ends with that test: it is finished before the test's
stand-ins are taken away (`_finish_work`). On 2026-11-10 CI caught one that was not: a test started a run and returned,
its stand-in for the download went with it, and the run, still going, asked github.com for the repository while the
next test ran, which was the one that failed.

CI on Linux also runs the suite with no network at all (tools/netless.py) and sets LANTERN_TESTS_NETLESS=required,
which stops the run when a route to the outside exists.

CI also sets LANTERN_TESTS_COMPLETE=required: there every test must run, and a test file or a test that is skipped
because a library is not installed fails the run. Until 2026-11-10 CI's test jobs installed neither PyJWT nor
cryptography; tests/test_cloud_github.py was skipped while it was imported, its 14 tests counted as one skipped test,
and the runs were green. A developer's own run without those libraries still skips, and says so.

LANTERN_TESTS_COMPLETE=no-skips is stricter: there no test may be skipped, whatever the reason. CI's Linux jobs run
tests/test_netguard.py a second time that way, as root and with the computer's ordinary network: four tests of the
isolation itself cannot run in the first pass (two need root, one starts the no-network runner, which cannot be
started inside itself without root, one needs a way out for the refusal to show). Until 2026-11-10 three of them
ran nowhere in CI, and the fourth only in the one-command audit of the Python 3.13 job.

Since 2026-11-13 a third pass runs tests/test_sandbox_own_network.py that way too, as the ordinary user. In the test
sandbox a project's tests get a network of their own; root makes it directly, an ordinary user through a user
namespace, and GitHub's Linux machines refuse an ordinary user that (the first pass of commit 9e6696f: "this system
does not let the tests have a network of their own (error 13)"). So in the first pass the restricted process fell
back to refusing every address, which is right there and is what that pass tests, a test's own server answered only
in Docker's container, and the one test that needs the launcher's own network was skipped with that reason. The
third pass takes the machine's rule (kernel.apparmor_restrict_unprivileged_userns) away for its one command and
puts it back after.

A run under any of these rules names them in its last lines ("rules of this run: ..."), and CI looks for them there.
That second pass, on its first run in CI, showed why: both of CI's Linux passes start through sudo, the sudo of
GitHub's machines hands a command none of the caller's variables (`-E` is ignored there, and sudo says so), and so,
wherever that sudo ran, neither LANTERN_TESTS_NETLESS=required nor LANTERN_TESTS_COMPLETE=required reached the tests
of those jobs: it printed its line in both runs whose logs were read (commits 1a2bc59 and eaf4045). The runs were
inside the no-network runner all the same (its own last line says so), but a test skipped there for a missing library
would not have failed that pass. CI now writes each rule on the sudo line itself.
"""
import functools
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402

SESSION = tempfile.mkdtemp(prefix="lantern-tests-")
GUARD = netguard.isolate(SESSION)
os.environ["LANTERN_OFFLINE"] = "1"
# This process talks to its own test servers directly; anything else it tries meets the guard itself, as a refused
# connection. (Programs it starts keep the proxy variables, which point at the guard's refusing proxy.)
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

_START = pytest.StashKey[int]()
_PHASES = {"setup": "its set-up", "call": "the test itself", "teardown": "its clean-up"}
_homes = iter(range(1, 10 ** 9))
_between: list = []                     # attempts that happened outside every test (while collecting, between tests)
_seen_to = 0
_work: list = []                        # (future, what it is) for work the cloud service was asked for and has not ended
_WORK_LIMIT = 180.0                     # seconds such work may take to end once the test that asked for it is over
_unrun: list = []                       # (test file or test, library) skipped because that library is not installed
_skipped: list = []                     # (test file or test, reason) skipped for any other reason
_whole: list = []                       # (test file, reason) skipped while it was imported, whatever the reason
_NOT_INSTALLED = re.compile(r"could not import '([^']+)'")   # pytest.importorskip's own words


def pytest_configure(config):
    config.addinivalue_line("markers", "network_refused(reason): this test tries an address outside this computer on "
                            "purpose, to see the refusal (listed in tests/test_isolation.py)")
    config.addinivalue_line("markers", "live: needs a real model provider; never part of a normal run (bench/live.py)")
    if _netless_required() and netguard.has_route_out():
        raise pytest.UsageError("LANTERN_TESTS_NETLESS=required, and this run has a route to the outside. Start it "
                                "inside the netless runner: python tools/netless.py -- python -m pytest")


def _keep_work() -> None:
    """Have the cloud service's worker tell `_work` about every run and every set of explanations it is handed (they
    run on its own threads, after the request that asked for them has been answered). Done once, as soon as a test
    file has loaded the worker; this file never loads it itself."""
    worker = sys.modules.get("lantern_cloud.worker")
    if worker is None or "_kept_for_the_tests" in vars(worker.Worker):
        return
    for name, what in (("submit", "a run"), ("submit_explain", "a run's explanations")):
        real = getattr(worker.Worker, name)

        @functools.wraps(real)
        def keep(self, *args, _real=real, _what=what, **kwargs):
            future = _real(self, *args, **kwargs)
            _work.append((future, _what))
            return future
        setattr(worker.Worker, name, keep)
    worker.Worker._kept_for_the_tests = True


def _finish_work(limit: float = _WORK_LIMIT) -> list:
    """Wait until the work asked for so far has ended, work handed out while waiting included. Returns what is still
    going after `limit` seconds, which is then forgotten: one piece of work that never ends fails one test, not every
    test after it. Work that was cancelled while it waited its turn (`Worker.shutdown`) has ended: nothing will run it.
    `concurrent.futures.wait` never hears of that and would sit out the whole limit, so each piece of work is asked to
    say when it is over, which it also does when cancelled, and at once when it is over already."""
    left, deadline = [], time.monotonic() + limit
    while _work:
        future, what = _work.pop(0)
        over = threading.Event()
        future.add_done_callback(lambda _future, over=over: over.set())
        if not over.wait(max(0.0, deadline - time.monotonic())):
            left.append(what)
    return left


def pytest_collection_finish(session):
    _keep_work()


def _complete() -> str:
    """LANTERN_TESTS_COMPLETE: `required` (a test skipped for a missing library fails the run) or `no-skips` (a test
    skipped for any reason does)."""
    return os.environ.get("LANTERN_TESTS_COMPLETE", "").strip().lower()


def _every_test_must_run() -> bool:
    return _complete() in ("required", "no-skips")


def _netless_required() -> bool:
    return os.environ.get("LANTERN_TESTS_NETLESS", "").strip().lower() == "required"


def _rules() -> list:
    """The rules this run was started under, as its last lines name them. CI looks for these words in the run's own
    output (.github/workflows/ci.yml): a rule that was set where the run was started and did not reach it is a rule
    nobody was held to, and that is how it was on CI's Linux machines until 2026-11-10 (see the top of this file)."""
    rules = []
    if _complete() == "required":
        rules.append("LANTERN_TESTS_COMPLETE=required (a test skipped for a missing library fails the run)")
    elif _complete() == "no-skips":
        rules.append("LANTERN_TESTS_COMPLETE=no-skips (a test skipped for any reason fails the run)")
    if _netless_required():
        rules.append("LANTERN_TESTS_NETLESS=required (the run starts only where there is no route to the outside)")
    return rules


def _no_test_may_be_skipped() -> bool:
    return _complete() == "no-skips"


def _keep_unrun(report) -> None:
    """Write down a test file (skipped while it was imported) or a test that was skipped: because a library is not
    installed (`_unrun`), or for any other reason, such as another operating system or a program that is not there
    (`_skipped`, which fails a run only where no test may be skipped). A test that is expected to fail did run, and is
    not kept. A file skipped while it was imported is kept in `_whole` as well, whatever the reason: pytest counts it
    as one skipped test and names the line that skipped, which is in another file when the skip came with an import
    (on Windows, tests/test_cloud_share.py and tests/test_cloud_view.py are skipped by a line of
    tests/test_cloud_runs.py), so the run's summary names each such file itself."""
    if report.skipped and isinstance(report.longrepr, tuple) and not hasattr(report, "wasxfail"):
        why = str(report.longrepr[2]).removeprefix("Skipped: ")
        missing = _NOT_INSTALLED.search(why)
        if missing:
            _unrun.append((report.nodeid, missing.group(1)))
        else:
            _skipped.append((report.nodeid, why))
        if "::" not in report.nodeid:
            _whole.append((report.nodeid, why))


def pytest_collectreport(report):
    _keep_unrun(report)


def pytest_runtest_logreport(report):
    _keep_unrun(report)


def _new_home(monkeypatch) -> str:
    home = os.path.join(SESSION, "homes", str(next(_homes)))
    for name, value in netguard.temp_home(home, {}).items():
        monkeypatch.setenv(name, value)
    return home


@pytest.fixture(autouse=True, scope="module")
def _a_home_for_each_file():
    """Set-up steps shared by a file get a home folder of their own (pytest builds them before the per-test one)."""
    patch = pytest.MonkeyPatch()
    home = _new_home(patch)
    yield
    patch.undo()
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(autouse=True)
def _a_home_for_each_test(monkeypatch):
    """An empty home folder per test: saved keys, sign-in tokens, settings and usage counts never carry over."""
    home = _new_home(monkeypatch)
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    yield
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture
def network_attempts(request):
    """A function returning what this test has tried to reach so far (refused attempts, oldest first)."""
    return lambda: GUARD.since(request.node.stash[_START])


def _watch(item, phase):
    """Around one phase of one test: whatever tried to reach the network while it ran fails that phase. The clean-up
    phase starts by finishing the cloud work the test asked for, so an attempt made by that work is the test's own."""
    global _seen_to
    start = GUARD.mark()
    if start > _seen_to:
        _between.extend(GUARD.since(_seen_to, start)[: 50])
    if phase == "setup":
        item.stash[_START] = start
        _keep_work()
    # Before anything of the test is taken away (pytest undoes its stand-ins inside this phase, after the `yield`).
    left = _finish_work() if phase == "teardown" else []
    failure = None
    try:
        result = yield
    except BaseException as e:   # noqa: BLE001 - re-raised below unless the phase is failed for the network instead
        failure, result = e, None
    _seen_to = GUARD.mark()
    tried = GUARD.since(start, _seen_to)
    expected = item.get_closest_marker("network_refused")
    problem = None
    if tried and expected is None:
        problem = (f"This test tried to reach the network during {_PHASES[phase]}; tests may not reach the network.\n"
                   f"{netguard.describe(tried)}\n"
                   "Nothing left this computer: every attempt was refused. Give the test a stand-in for the outside "
                   "service, or, if it is there to see the refusal, mark it @pytest.mark.network_refused(\"why\"). "
                   "(If this test starts nothing that asks for that address, look at the tests before it: what one of "
                   "them left running is counted where it asks.)")
    elif phase == "call" and expected is not None and failure is None and not GUARD.since(item.stash[_START], _seen_to):
        problem = ("This test is marked network_refused and did not try the network. Remove the mark, so that an "
                   "attempt would fail it like any other test.")
    if left:
        problem = (f"This test asked the cloud service for work that was still going {_WORK_LIMIT:.0f} seconds after "
                   f"the test ended ({', '.join(left)}). A test waits for what it starts, or stops it: work that "
                   "outlives its test meets the next test's stand-ins, or none at all."
                   + (f"\n\n{problem}" if problem else ""))
    if problem and (failure is None or isinstance(failure, pytest.skip.Exception)):
        raise pytest.fail.Exception(problem, pytrace=False)      # skipping afterwards does not excuse an attempt
    if failure is not None:
        if problem:
            item.add_report_section(phase, "network", problem)   # the test's own failure stays; the attempt is shown too
        raise failure
    return result


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item):
    return (yield from _watch(item, "setup"))


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item):
    return (yield from _watch(item, "call"))


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item):
    return (yield from _watch(item, "teardown"))


def pytest_sessionfinish(session, exitstatus):
    """An attempt outside every test (while test files were imported, or by a program still running between two
    tests) has no test to fail, so it fails the run."""
    _between.extend(GUARD.since(_seen_to)[: 50])
    if _between and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    # Where every test must run (CI), a test that did not run for a missing library fails the run as well; a run in
    # which the only file was skipped that way ends as "no test was collected", which is no pass either.
    # Where no test may be skipped (CI's second pass over the isolation's own tests), any skipped test does the same.
    unrun = (_unrun and _every_test_must_run()) or (_skipped and _no_test_may_be_skipped())
    if unrun and session.exitstatus in (pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter):
    if _between:
        terminalreporter.section("network attempts outside any test", sep="=", red=True, bold=True)
        terminalreporter.write_line("Something tried to reach the network while no test was running (every attempt "
                                    "was refused). The run fails for it:")
        terminalreporter.write_line(netguard.describe(_between))
    if _unrun and _every_test_must_run():
        terminalreporter.section("tests that did not run", sep="=", red=True, bold=True)
        terminalreporter.write_line("LANTERN_TESTS_COMPLETE=required: every test must run here, and these did not run "
                                    "because a library is not installed. The run fails for it:")
        for where, library in _unrun:
            terminalreporter.write_line(f"  {where}{'' if '::' in where else ' (the whole file)'}: {library}")
        terminalreporter.write_line('Install what the tests need (pip install -e ".[scan,dev]"). A library a new test '
                                    "needs belongs in the `dev` list in pyproject.toml.")
    if _whole:
        terminalreporter.section("test files skipped whole", sep="=", yellow=True)
        terminalreporter.write_line("Skipped while they were imported. pytest counts each of these files as 1 skipped "
                                    "test, whatever it holds:")
        for where, why in _whole:
            terminalreporter.write_line(f"  {where}: {why}")
    if _skipped and _no_test_may_be_skipped():
        terminalreporter.section("tests that were skipped", sep="=", red=True, bold=True)
        terminalreporter.write_line("LANTERN_TESTS_COMPLETE=no-skips: no test may be skipped here, whatever the reason, "
                                    "and these were. The run fails for it:")
        for where, why in _skipped:
            terminalreporter.write_line(f"  {where}{'' if '::' in where else ' (the whole file)'}: {why}")
    ran = getattr(terminalreporter.config, "_lantern_ran_against", None)      # a test file says what it started
    if ran:
        terminalreporter.write_line("programs these tests started: " + "; ".join(f"{k} {v}" for k, v in sorted(ran.items())))
    if _rules():
        terminalreporter.write_line("rules of this run: " + "; ".join(_rules()))


def pytest_unconfigure(config):
    shutil.rmtree(SESSION, ignore_errors=True)
