"""Every test runs cut off from the developer's keys, saved sign-ins and the internet.

When pytest loads this file, before any test file is imported, the whole run (and through its environment every
program it starts) gets: an empty temporary home folder, no key, token or password variable, LANTERN_OFFLINE=1,
LANTERN_NO_REAL_PROVIDERS=1, and the network guard (tools/netguard/lantern_netguard.py), which refuses and writes down
anything that is not for this computer. A set-up step shared by a whole file is covered like a test: an independent
review on 2026-11-09 found a test reaching a real model, and on 2026-11-10 a trace found 11 outside connections per
run, all from shared set-up steps, which pytest builds before any per-test fixture.

An attempt fails the test it happened in, also when the code under test hides the error. A test that is there to see
the refusal says so: `@pytest.mark.network_refused("why")`; tests/test_isolation.py lists those tests.

CI on Linux also runs the suite with no network at all (tools/netless.py) and sets LANTERN_TESTS_NETLESS=required,
which stops the run when a route to the outside exists.
"""
import os
import shutil
import sys
import tempfile
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


def pytest_configure(config):
    config.addinivalue_line("markers", "network_refused(reason): this test tries an address outside this computer on "
                            "purpose, to see the refusal (listed in tests/test_isolation.py)")
    config.addinivalue_line("markers", "live: needs a real model provider; never part of a normal run (bench/live.py)")
    if os.environ.get("LANTERN_TESTS_NETLESS", "").strip().lower() == "required" and netguard.has_route_out():
        raise pytest.UsageError("LANTERN_TESTS_NETLESS=required, and this run has a route to the outside. Start it "
                                "inside the netless runner: python tools/netless.py -- python -m pytest")


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
    """Around one phase of one test: whatever tried to reach the network while it ran fails that phase."""
    global _seen_to
    start = GUARD.mark()
    if start > _seen_to:
        _between.extend(GUARD.since(_seen_to, start)[: 50])
    if phase == "setup":
        item.stash[_START] = start
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
                   "service, or, if it is there to see the refusal, mark it @pytest.mark.network_refused(\"why\").")
    elif phase == "call" and expected is not None and failure is None and not GUARD.since(item.stash[_START], _seen_to):
        problem = ("This test is marked network_refused and did not try the network. Remove the mark, so that an "
                   "attempt would fail it like any other test.")
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


def pytest_terminal_summary(terminalreporter):
    if _between:
        terminalreporter.section("network attempts outside any test", sep="=", red=True, bold=True)
        terminalreporter.write_line("Something tried to reach the network while no test was running (every attempt "
                                    "was refused). The run fails for it:")
        terminalreporter.write_line(netguard.describe(_between))


def pytest_unconfigure(config):
    shutil.rmtree(SESSION, ignore_errors=True)
