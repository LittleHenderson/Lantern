"""Tests and benchmarks never reach a real model provider or the internet, and never see the developer's keys.

Most of this file starts a second pytest the way a developer would start it (keys in the environment, a saved sign-in
in the home folder, no offline switch) on `tests/probe_isolation.py`, and reads what each probe could see. The rest
tests the guard's own rules, with near-misses that must stay untouched.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as ng  # noqa: E402

# Names a developer's shell or CI may hold. The values are made here and are not keys.
PLANTED = ["ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "LANTERN_TOKEN", "LANTERN_MODEL",
           "LANTERN_GATEWAY_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GH_TOKEN",
           "GITHUB_TOKEN", "FLY_API_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
           "STRIPE_SECRET_KEY", "DATABASE_URL", "SSH_AUTH_SOCK", "LANTERN_ADMIN_SECRET", "NPM_CONFIG__AUTH"]
GIT_PLANTED = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.https://rewritten.invalid/.insteadOf",
               "GIT_CONFIG_VALUE_0": "https://192.0.2.1/"}       # a developer's shell that rewrites git addresses
ISOLATION_VARS = ("LANTERN_OFFLINE", "LANTERN_NO_REAL_PROVIDERS", "LANTERN_HOME", "LANTERN_CONFIG_DIR",
                  "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA",
                  "GIT_CONFIG_NOSYSTEM", "PIP_CONFIG_FILE", "NPM_CONFIG_USERCONFIG",
                  ng.LOG_ENV, ng.ALLOW_ENV, ng.DENY_ENV, "LANTERN_TESTS_NETLESS", "LANTERN_TESTS_COMPLETE")


def developer_env(tmp: Path, forwarder: int) -> dict:
    """This process's environment turned back into a developer's: none of the test run's protection, a home folder
    with a saved sign-in and saved keys, keys in the environment, git settings in variables, and a forwarding proxy
    on this computer (`forwarder` is its port) that every proxy variable points at."""
    home = tmp / "dev-home"
    (home / ".config" / "lantern").mkdir(parents=True)
    (home / ".config" / "lantern" / "token").write_text("saved-sign-in-of-the-developer\n", encoding="utf-8")
    (home / ".lantern").mkdir()
    (home / ".lantern" / "keys.json").write_text('{"anthropic": "saved-key-of-the-developer"}', encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k not in ISOLATION_VARS}
    env["PYTHONPATH"] = os.pathsep.join(p for p in env.get("PYTHONPATH", "").split(os.pathsep)
                                        if p and not ng.holds_the_guard(p))      # the checkout's, or a copy of it
    env.update({"HOME": str(home), "USERPROFILE": str(home), "PROBE_DEV_HOME": str(home),
                "PROBE_PLANTED": ",".join(PLANTED)})
    for name in PLANTED:
        env[name] = "planted-" + name.lower()
    env["DATABASE_URL"] = "postgres://someone:planted@db.invalid/app"
    env["LANTERN_MODEL"] = "anthropic/claude-haiku-5-5"
    env.update(GIT_PLANTED)
    for name in [*ng.PROXY_VARS, "YARN_HTTPS_PROXY", "npm_config_https_proxy"]:
        env[name] = f"http://127.0.0.1:{forwarder}"
    env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1"
    env["PROBE_FORWARDER"] = str(forwarder)
    return env


class Forwarder:
    """Stands in for a forwarding proxy on the developer's computer. It forwards nothing: it writes down the first
    line of whatever reaches it and answers 502."""

    def __init__(self):
        self.heard: list = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            try:
                conn.settimeout(3)
                self.heard.append(conn.recv(300).decode("latin-1", "replace").split("\r\n")[0])
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                self.heard.append("(a connection that sent nothing)")
            finally:
                conn.close()


@pytest.fixture(scope="module")
def probes(tmp_path_factory):
    """One run of every probe; returns {probe name: 'PASSED' | 'FAILED' | 'ERROR' | 'SKIPPED'} and the whole output."""
    tmp = tmp_path_factory.mktemp("probes")
    forwarder = Forwarder()
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider",
                            str(ROOT / "tests" / "probe_isolation.py")],
                           cwd=ROOT, env=developer_env(tmp, forwarder.port), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=600)
    finally:
        forwarder.listener.close()
    out = r.stdout + r.stderr + f"\nheard by the developer's forwarding proxy: {forwarder.heard}"
    result = {"(heard)": forwarder.heard}
    for word, name in re.findall(r"^(PASSED|FAILED|ERROR|SKIPPED)\s+\S*probe_isolation\.py(?:::|:\d+: )(\w+)?", out, re.M):
        if name:
            result.setdefault(name, word)
    return result, out


def _passed(probes, name):
    result, out = probes
    assert result.get(name) == "PASSED", f"{name}: {result.get(name)}\n{out[-6000:]}"


def test_a_set_up_step_shared_by_a_file_is_isolated_like_a_test(probes):
    """pytest builds module-scoped fixtures before any per-test fixture. 24 of them ran outside the protection, and
    one let a real package-audit program reach the Python package index."""
    _passed(probes, "test_probe_shared_setup_is_isolated")


def test_a_test_sees_no_key_no_saved_sign_in_and_no_way_out(probes):
    _passed(probes, "test_probe_test_body_is_isolated")


def test_a_python_program_a_test_starts_is_isolated_too(probes):
    _passed(probes, "test_probe_python_child_is_isolated")


def test_another_program_a_test_starts_ends_at_the_refusing_proxy(probes):
    if not shutil.which("git"):
        pytest.skip("git is not installed")
    _passed(probes, "test_probe_other_program_ends_at_the_refusing_proxy")


def test_a_real_provider_is_refused_before_anything_is_sent(probes):
    _passed(probes, "test_probe_real_provider_is_switched_off")


def test_a_forwarding_proxy_on_the_developers_computer_hears_nothing(probes):
    """Measured on 2026-11-10 before this change: five requests per run to a vulnerability database went out through
    a forwarding proxy on 127.0.0.1, from set-up steps shared by a file."""
    result, out = probes
    _passed(probes, "test_probe_forwarding_proxy_on_this_computer_is_not_used")
    assert result["(heard)"] == [], out[-3000:]                 # across every probe, also the ones that try on purpose


def test_git_settings_from_the_developers_shell_do_not_reach_a_test(probes):
    if not shutil.which("git"):
        pytest.skip("git is not installed")
    _passed(probes, "test_probe_git_settings_from_the_shell_are_gone")


@pytest.mark.parametrize("probe, says", [
    ("test_probe_FAILS_swallowed_attempt", "192.0.2.1"),
    ("test_probe_FAILS_swallowed_attempt_in_a_child", "192.0.2.1"),
    ("test_probe_FAILS_attempt_in_shared_setup", "192.0.2.1"),
    ("test_probe_FAILS_name_lookup", "lantern-probe.example"),
    ("test_probe_FAILS_marked_without_an_attempt", "did not try"),
    ("test_probe_FAILS_skipping_after_an_attempt", "192.0.2.1"),
    ("test_probe_FAILS_through_the_proxy_variables", "lantern-probe.example"),
])
def test_an_attempt_fails_the_test_even_when_the_code_hides_the_error(probes, probe, says):
    result, out = probes
    assert result.get(probe) in ("FAILED", "ERROR"), f"{probe}: {result.get(probe)}\n{out[-6000:]}"
    m = re.search(rf"^_+ (?:ERROR at \w+ of )?{probe} _+$(.*?)(?=^_+ .* _+$|^=+ )", out, re.M | re.S)
    assert m and says in m.group(1), out[-6000:]              # the failure names what was tried


def test_a_test_that_fails_by_itself_keeps_its_own_failure_and_shows_the_attempt(probes):
    result, out = probes
    assert result.get("test_probe_FAILS_by_itself_after_an_attempt") == "FAILED"
    m = re.search(r"^_+ test_probe_FAILS_by_itself_after_an_attempt _+$(.*?)(?=^_+ .* _+$|^=+ )", out, re.M | re.S)
    assert m and "its own reason" in m.group(1) and "192.0.2.1" in m.group(1), out[-6000:]


def test_an_attempt_outside_every_test_fails_the_run(tmp_path):
    """Nothing to pin it on (it happens while a test file is imported), so the run itself fails and says why."""
    forwarder = Forwarder()
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                            str(ROOT / "tests" / "probe_outside_tests.py")], cwd=ROOT,
                           env=developer_env(tmp_path, forwarder.port), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
    finally:
        forwarder.listener.close()
    assert "1 passed" in r.stdout and r.returncode == 1, r.stdout + r.stderr
    assert "network attempts outside any test" in r.stdout and "192.0.2.1:9" in r.stdout
    assert forwarder.heard == []


def test_work_a_test_leaves_going_ends_with_that_test(tmp_path):
    """CI, 2026-11-10: tests/test_cloud_runs.py::test_limits_answer_429_with_a_sentence started a run and returned.
    Its stand-in for the download was taken away with the test; the run, still going, then asked github.com for the
    repository, and the test that was running by then failed for it. (Measured that day: 3 of the 1,046 tests that
    ran left a run going.) The probe walks away from two runs the same way: both must end before the next test
    begins, each on the stand-in of the test that started it."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if os.name != "posix":
        pytest.skip("the cloud worker runs on Linux (its restricted process is POSIX)")
    forwarder = Forwarder()
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider",
                            str(ROOT / "tests" / "probe_leftover_work.py")], cwd=ROOT,
                           env=developer_env(tmp_path, forwarder.port), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
    finally:
        forwarder.listener.close()
    out = r.stdout + r.stderr
    assert "2 passed" in r.stdout and r.returncode == 0, out[-6000:]
    assert "tried to reach the network" not in out and forwarder.heard == [], out[-6000:]


def _harness(request):
    """tests/conftest.py as this run loaded it, whatever name the import mode gave the module."""
    here = (ROOT / "tests" / "conftest.py").resolve()
    return next(p for p in request.config.pluginmanager.get_plugins()
                if getattr(p, "__file__", None) and Path(p.__file__).resolve() == here)


def test_work_that_never_ends_fails_one_test_and_not_every_test_after_it(request):
    """What is still going when the time is up is named once and then forgotten (the test it belongs to fails)."""
    import concurrent.futures
    harness = _harness(request)
    assert harness._work == []                                  # nothing is carried from one test into the next
    ended, stuck = concurrent.futures.Future(), concurrent.futures.Future()
    ended.set_result(None)
    harness._work.extend([(ended, "a run"), (stuck, "a run's explanations")])
    try:
        assert harness._finish_work(limit=0.05) == ["a run's explanations"]
        assert harness._work == [] and harness._finish_work(limit=0.05) == []
    finally:
        stuck.cancel()
        harness._work.clear()


def test_work_that_was_cancelled_while_it_waited_its_turn_has_ended(request):
    """A worker that is shut down cancels what was still waiting for a free thread (`Worker.shutdown`). Nothing will
    ever run that, so it has ended: waiting for it would hold the test up for the whole limit and then fail it."""
    import concurrent.futures
    import time
    harness = _harness(request)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    go = threading.Event()
    first = pool.submit(go.wait, 30)
    second = pool.submit(lambda: None)                          # waits behind the first
    pool.shutdown(wait=False, cancel_futures=True)              # what Worker.shutdown does
    go.set()
    harness._work.extend([(first, "a run"), (second, "a run")])
    began = time.monotonic()
    try:
        assert harness._finish_work(limit=10) == [] and first.done() and second.cancelled()
        assert time.monotonic() - began < 8
    finally:
        harness._work.clear()


def test_work_handed_out_while_the_harness_waits_is_finished_too(request):
    """Work that is handed out while the harness waits for the work before it is waited for as well, not dropped."""
    import concurrent.futures
    import time
    harness = _harness(request)
    one, two = concurrent.futures.Future(), concurrent.futures.Future()

    def later():
        time.sleep(0.2)
        harness._work.append((two, "a run"))
        one.set_result(None)
        time.sleep(0.3)
        two.set_result(None)

    harness._work.append((one, "a run"))
    thread = threading.Thread(target=later)
    thread.start()
    try:
        assert harness._finish_work(limit=10) == [] and two.done()
    finally:
        thread.join()
        harness._work.clear()


# ----------------------------------------------------------------------------- this run itself
def _missing_library_run(tmp: Path, where: str, complete: bool | str, **more):
    """A second pytest on tests/probe_missing_library.py, in which `where` (`file`, `test` or nothing) needs a library
    that is not installed. `complete` starts it the way CI does, with LANTERN_TESTS_COMPLETE=required (True), or with
    the value given (`no-skips`: CI's second pass over the isolation's own tests). `more` are further variables."""
    forwarder = Forwarder()
    env = developer_env(tmp, forwarder.port)
    env["PROBE_MISSING_AT"] = where
    env.update(more)
    if complete:
        env["LANTERN_TESTS_COMPLETE"] = "required" if complete is True else complete
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                            str(ROOT / "tests" / "probe_missing_library.py")], cwd=ROOT, env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=300)
    finally:
        forwarder.listener.close()
    return r.returncode, (r.stdout + r.stderr).replace("\\", "/")


@pytest.mark.parametrize("where, counted, named", [
    ("file", "1 skipped", "tests/probe_missing_library.py (the whole file)"),
    ("test", "1 passed, 2 skipped", "tests/probe_missing_library.py::test_that_needs_the_library"),
])
def test_where_every_test_must_run_a_missing_library_fails_the_run(tmp_path, where, counted, named):
    """Found on 2026-11-10 while counting skipped tests: CI's test jobs installed neither PyJWT nor cryptography, so
    tests/test_cloud_github.py was skipped while it was imported. Its 14 tests counted as 1 skipped test, in a log that
    named no skipped test, and every run was green. Where LANTERN_TESTS_COMPLETE=required (CI), a test file or a test
    that is skipped because a library is not installed fails the run, and the run says which and what is missing."""
    code, out = _missing_library_run(tmp_path / "ci", where, complete=True)
    assert code == 1 and counted in out, out[-4000:]
    assert "did not run because a library is not installed" in out, out[-4000:]
    assert f"{named}: a_library_nobody_installed_for_lantern" in out, out[-4000:]
    # a developer's own run, without the switch, stays as it was: skipped, named with the reason, not failed
    code, out = _missing_library_run(tmp_path / "dev", where, complete=False)
    assert code in (0, 5) and counted in out, out[-4000:]          # 5: pytest's "no test was collected"
    assert "could not import 'a_library_nobody_installed_for_lantern'" in out, out[-4000:]
    assert "did not run because a library is not installed" not in out, out[-4000:]
    # a file skipped whole counts as one skipped test whatever it holds: every run names such a file itself
    whole = "tests/probe_missing_library.py: could not import 'a_library_nobody_installed_for_lantern'"
    assert ("test files skipped whole" in out and whole in out) == (where == "file"), out[-4000:]


def test_a_test_skipped_for_another_reason_is_no_missing_library(tmp_path):
    """The safe twin: a test that is skipped because it needs another kind of computer stays skipped, also in CI."""
    code, out = _missing_library_run(tmp_path, "", complete=True)
    assert code == 0 and "2 passed, 1 skipped" in out, out[-4000:]
    assert "this needs a kind of computer that is not here" in out, out[-4000:]
    assert "did not run because a library is not installed" not in out, out[-4000:]


def test_where_no_test_may_be_skipped_any_skipped_test_fails_the_run(tmp_path):
    """Found on 2026-11-10, the first time CI's log named what it skips: four tests of the isolation itself did not
    run in CI's test pass. Two need root, one starts the no-network runner (which cannot be started inside itself
    without root), one needs a way out for the refusal to show; CI's tests run as the ordinary user inside the
    no-network runner. Three of the four ran nowhere in CI, the fourth only in the one-command audit of one job. CI
    now runs tests/test_netguard.py a second time, as root, with LANTERN_TESTS_COMPLETE=no-skips: there a test that
    is skipped, whatever the reason, fails the run and is named with the reason, so these four cannot go unrun again
    without a red run. (With `required`, the same skipped test passes:
    test_a_test_skipped_for_another_reason_is_no_missing_library.)"""
    code, out = _missing_library_run(tmp_path / "skipped", "", complete="no-skips")
    assert code == 1 and "2 passed, 1 skipped" in out, out[-4000:]
    assert "no test may be skipped here" in out, out[-4000:]
    assert ("tests/probe_missing_library.py::test_that_needs_another_computer: "
            "this needs a kind of computer that is not here") in out, out[-4000:]
    assert "did not run because a library is not installed" not in out, out[-4000:]
    # a missing library fails that run too, and both lists are shown
    code, out = _missing_library_run(tmp_path / "library", "test", complete="no-skips")
    assert code == 1 and "1 passed, 2 skipped" in out, out[-4000:]
    assert "tests/probe_missing_library.py::test_that_needs_the_library: a_library_nobody_installed_for_lantern" in out
    assert "tests/probe_missing_library.py::test_that_needs_another_computer: this needs" in out, out[-4000:]


def _rules_gates() -> list:
    """The lines of CI that look in a run's own words for the rules it ran under: (what must be found, in which file)."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    return re.findall(r"""grep -q '(\^rules of this run: [^']+)' (\S+)""", ci)


def test_a_run_names_the_rules_it_ran_under_and_ci_looks_for_them(tmp_path):
    """Found on 2026-11-10, when CI's second pass failed on its first run: the sudo of GitHub's Linux machines (sudo-rs)
    hands a command none of the caller's variables, `-E` or not ("preserving the entire environment is not supported,
    '-E' is ignored"), so wherever that sudo ran, LANTERN_TESTS_NETLESS=required and LANTERN_TESTS_COMPLETE=required
    did not reach the tests of the Linux jobs, which run through sudo: a run there was held to neither rule, and
    nothing showed it.
    A run now ends by naming the rules it ran under, CI writes each rule on the sudo line itself, and CI looks for
    the rule in the run's own words afterwards, so a rule that did not arrive is a red run."""
    gates = _rules_gates()
    assert [where for _, where in gates] == ["pytest.log", '"$RUNNER_TEMP/second-pass.log"'], gates
    first, second = (re.compile(what, re.M) for what, _ in gates)       # nothing in them that grep and Python read apart
    code, out = _missing_library_run(tmp_path / "required", "", complete=True)
    assert code == 0 and "\nrules of this run: LANTERN_TESTS_COMPLETE=required (" in out, out[-3000:]
    assert not first.search(out) and not second.search(out), out[-3000:]       # one rule is not both; nor the other one
    code, out = _missing_library_run(tmp_path / "no-skips", "", complete="no-skips")
    assert code == 1 and second.search(out) and not first.search(out), out[-3000:]
    code, out = _missing_library_run(tmp_path / "none", "", complete=False)
    assert code == 0 and "rules of this run" not in out, out[-3000:]      # a developer's own run: no rule, no line
    if ng.has_route_out():
        # the dangerous shape: the rule arrives where there is a way out, and the run does not start
        code, out = _missing_library_run(tmp_path / "out", "", complete=True, LANTERN_TESTS_NETLESS="required")
        assert code == 4 and "LANTERN_TESTS_NETLESS=required" in out and "passed" not in out, out[-3000:]
    else:
        # inside the no-network runner (CI's first pass): both rules, in the words CI looks for
        code, out = _missing_library_run(tmp_path / "both", "", complete=True, LANTERN_TESTS_NETLESS="required")
        assert code == 0 and first.search(out), out[-3000:]


def test_where_the_tests_give_a_verdict_every_test_must_run_and_every_skip_is_named():
    """CI and the release build: every pytest line carries -rs (the log names each skipped test with its reason) and
    runs with LANTERN_TESTS_COMPLETE=required; the audit script shows its skipped tests also when the run passed; and
    the libraries the tests need are what CI installs (`dev`), PyJWT with cryptography among them: the 14 Connect
    GitHub tests need both. CI's Linux jobs run the isolation's own tests a second time, as root and outside the
    no-network runner, where no test may be skipped. Each of those two passes is handed its rules on the sudo line
    and is checked to have run under them."""
    import tomllib
    runs = []
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        mine = [line.strip() for line in text.splitlines()
                if re.search(r"\bpython -m pytest\b", line) and not line.lstrip().startswith("#")]
        assert all(" -rs" in line for line in mine), (path.name, mine)
        assert not mine or "LANTERN_TESTS_COMPLETE: required" in text, path.name
        runs += [(path.name, line) for line in mine]
    assert sorted({name for name, _ in runs}) == ["ci.yml", "release.yml"] and len(runs) == 4, runs
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "LANTERN_TESTS_COMPLETE: required" in ci[: ci.index("\njobs:")]        # for every job of the workflow
    first = next(line for name, line in runs if name == "ci.yml" and "--cov" in line)     # the pass without a network
    again = [line for name, line in runs if name == "ci.yml" and "tests/test_netguard.py" in line]
    assert again == ['python -m pytest -q -rs -p no:cacheprovider tests/test_netguard.py | tee '
                     '"$RUNNER_TEMP/second-pass.log"'], again
    between = ci[ci.index(first): ci.index(again[0])]              # after the first pass, in the second pass's own step
    assert ci.count("LANTERN_TESTS_COMPLETE: no-skips") == 1 and "LANTERN_TESTS_COMPLETE: no-skips" in between
    assert "LANTERN_TESTS_NETLESS" not in between[between.index("LANTERN_TESTS_COMPLETE: no-skips"):]
    assert "set -o pipefail" in between[between.index("LANTERN_TESTS_COMPLETE: no-skips"):]    # it pipes into tee too
    # Both passes start through sudo, which hands a command only what is written on its own line (the sudo of GitHub's
    # machines ignores -E): each rule is written there, and each step then looks for it in the run's own words
    # (test_a_run_names_the_rules_it_ran_under_and_ci_looks_for_them).
    through_sudo = [line.strip() for line in ci.replace("\\\n", " ").splitlines()
                    if re.search(r"^\s*sudo\b.*\bpython\b", line)]
    assert len(through_sudo) == 2 and not any(re.search(r"\bsudo\s+-E\b", line) for line in through_sudo), through_sudo
    handed = [line[: line.index(" python ")] for line in through_sudo]
    assert all('"LANTERN_TESTS_COMPLETE=$LANTERN_TESTS_COMPLETE"' in words for words in handed), handed
    assert '"LANTERN_TESTS_NETLESS=$LANTERN_TESTS_NETLESS"' in handed[0] and "netless.py" in through_sudo[0], through_sudo
    assert "LANTERN_TESTS_NETLESS" not in handed[1] and "netless.py" not in through_sudo[1], through_sudo
    assert [what for what, _ in _rules_gates()] == [
        "^rules of this run: LANTERN_TESTS_COMPLETE=required.*LANTERN_TESTS_NETLESS=required",
        "^rules of this run: LANTERN_TESTS_COMPLETE=no-skips"]
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    step = release[release.index("Tests against the built wheel"):]
    assert "LANTERN_TESTS_COMPLETE: required" in step[: step.index("python -m pytest")]
    audit = (ROOT / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert 'check "pytest" "$PY" -m pytest -q -rs\nsaid \'^SKIPPED \\[\'' in audit
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert any(d.lower().startswith("pyjwt[crypto]") for d in project["optional-dependencies"]["dev"])


def test_this_run_is_isolated():
    from lantern import providers
    assert os.environ.get("LANTERN_OFFLINE") == "1" and os.environ.get("LANTERN_NO_REAL_PROVIDERS") == "1"
    assert ng.installed()
    assert [k for k in os.environ if ng.is_credential(k, os.environ[k]) and k not in ng.SET_BY_TEMP_HOME] == []
    home = Path.home()
    assert Path(os.environ["LANTERN_HOME"]).is_relative_to(home) and providers.config_dir().is_relative_to(home)
    assert "lantern-tests-" in str(home)                       # the run's own temp folder, not the developer's
    assert providers.load_token() is None


def test_each_test_gets_its_own_empty_home():
    assert "lantern-tests-" in str(Path.home())                 # checked first: never write into a real home folder
    marker = Path.home() / "left-by-a-test.txt"
    assert not marker.exists() and list(Path.home().glob(".lantern/*")) == []
    marker.write_text("x", encoding="utf-8")


def test_each_test_gets_its_own_empty_home_again():
    assert not (Path.home() / "left-by-a-test.txt").exists()


# ----------------------------------------------------------------------------- only declared tests may try
EXPECTED_TO_TRY = {
    "tests/test_netguard.py::test_a_refusal_is_an_ordinary_connection_error_with_a_plain_reason",
    "tests/test_netguard.py::test_every_way_to_name_an_outside_address_is_refused",
}


def test_only_these_tests_may_try_the_network(request):
    """A test that tries the network on purpose (to see the refusal) says so with `network_refused` and is listed
    here, so adding one is a visible change. Run with the whole suite collected; a partial run checks what it has."""
    marked = {item.nodeid for item in request.session.items if item.get_closest_marker("network_refused")}
    assert marked <= EXPECTED_TO_TRY, sorted(marked - EXPECTED_TO_TRY)
    for item in request.session.items:
        m = item.get_closest_marker("network_refused")
        assert m is None or (m.args and len(str(m.args[0])) > 20), f"{item.nodeid}: give the reason"


# ----------------------------------------------------------------------------- benchmarks and the audit script
BENCHMARKS = ("bench/run_bench.py", "bench/mobile/run_mobile.py", "bench/heldout/run_heldout.py", "bench/fuzz.py",
              "bench/manifests.py", "bench/links.py", "bench/behaviour/run_behaviour.py", "tools/large_apps.py",
              "tools/mutation.py", "tools/load_test.py", "bench/speed.py")
LIVE_SUITE = ("bench/explain_eval.py", "bench/ask_eval.py")          # they go through bench/live.py's gate instead


def _calls_in(path: Path, function: str) -> list[str]:
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function)
    calls = sorted((c.lineno, c.col_offset, ast.unparse(c.func)) for c in ast.walk(fn) if isinstance(c, ast.Call))
    return [name for _line, _col, name in calls]                  # in the order they are written


@pytest.mark.parametrize("script", BENCHMARKS)
def test_every_benchmark_starts_isolated_and_says_what_was_refused(script):
    calls = _calls_in(ROOT / script, "main")
    assert "netguard.begin" in calls and "netguard.end" in calls, script


@pytest.mark.parametrize("script", LIVE_SUITE)
def test_the_live_suite_starts_through_its_gate_and_ends_with_the_same_count(script):
    calls = _calls_in(ROOT / script, "main")
    assert "live.gate" in calls and "live.finish" in calls, script
    gate = _calls_in(ROOT / "bench" / "live.py", "gate")
    assert "netguard.begin" in gate and gate.index("providers.make_provider") < gate.index("netguard.begin")
    assert "resolve_default" not in (ROOT / script).read_text(encoding="utf-8")       # no falling back to a default


def test_no_benchmark_is_left_out():
    """Every script under bench/ that can be started is a benchmark listed above or part of the live suite."""
    started = {p.relative_to(ROOT).as_posix() for p in (ROOT / "bench").rglob("*.py")
               if "__main__" in p.read_text(encoding="utf-8")}
    assert started == {s for s in (*BENCHMARKS, *LIVE_SUITE) if s.startswith("bench/")}, started


def _bare_isolated(text: str) -> list[str]:
    """The lines that start Python in isolated mode (`-I`) the plain way, which leaves the guard out of that program."""
    return [line.strip() for line in text.splitlines() if re.search(r"""sys\.executable,\s*["']-I["']""", line)]


def test_a_benchmark_starts_python_in_isolated_mode_only_through_the_guard():
    """`python -I` reads nothing from PYTHONPATH, and PYTHONPATH is how the guard gets into a Python program a
    benchmark starts. `netguard.python_isolated` starts the same thing with the guard switched on first
    (tests/test_netguard.py runs both)."""
    assert _bare_isolated('cmd = [sys.executable, "-I", "-m", "lantern.cli", "analyze", str(src)]') != []
    assert _bare_isolated('cmd = netguard.python_isolated("-m", "lantern.cli", "analyze", str(src))') == []
    assert _bare_isolated('cmd = [sys.executable, "-m", "lantern.cli", "analyze", str(src)]') == []
    for folder in ("bench", "tools"):
        for p in sorted((ROOT / folder).rglob("*.py")):
            if p.parent.name != "netguard":                       # the guard itself is what builds that command line
                assert _bare_isolated(p.read_text(encoding="utf-8")) == [], p.relative_to(ROOT).as_posix()
    assert "netguard.python_isolated(" in (ROOT / "bench" / "heldout" / "run_heldout.py").read_text(encoding="utf-8")


def test_the_load_test_is_never_pointed_at_another_computer(network_attempts, tmp_path, capsys):
    sys.path.insert(0, str(ROOT / "tools"))
    import load_test
    token = tmp_path / "token"
    token.write_text("not-a-token", encoding="utf-8")
    for base in ("https://lantern-cloud.fly.dev", "http://192.0.2.1:8872", "https://example.org/"):
        assert load_test.main([base, str(token)]) == 2
        assert "only runs against a website on this computer" in capsys.readouterr().err
    assert network_attempts() == []                               # refused before anything was sent


def test_the_dependency_audit_asks_only_the_addresses_it_names():
    from lantern import depaudit
    host = lambda url: urllib.parse.urlsplit(url).hostname      # noqa: E731
    assert host(depaudit.NPM_REGISTRY) in depaudit.AUDIT_HOSTS and host(depaudit.OSV_API) in depaudit.AUDIT_HOSTS
    source = Path(depaudit.__file__).read_text(encoding="utf-8")   # the module Python loaded, wherever it is installed
    named = {host(u) for u in re.findall(r"https://[A-Za-z0-9.-]+", source)}
    assert named <= {*depaudit.AUDIT_HOSTS, "osv.dev"}, named      # osv.dev: the link a finding shows, never requested
    assert '"--disable-pip"' in source and '"--no-deps"' in source  # pip-audit downloads no package: pypi.org only


def test_the_audit_script_and_ci_run_isolated_and_name_the_same_addresses():
    from lantern import depaudit
    hosts = ",".join(depaudit.AUDIT_HOSTS)
    audit = (ROOT / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert f"tools/netguard/lantern_netguard.py --allow {hosts} -- bash" in audit
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert ci.count(f"tools/netguard/lantern_netguard.py --allow {hosts} --") == 2     # the self-audits, Linux and Windows
    assert f'"tools/netguard/lantern_netguard.py", "--allow", "{hosts}", "--"]' in ci   # the Windows sample, as a list
    for line in ci.splitlines():                   # and no analysis in CI is left that could reach anything else
        if "lantern analyze" in line and not line.lstrip().startswith(("#", "echo")):
            assert "--offline" in line or "lantern_netguard.py" in line, line
        if '"lantern", "analyze"' in line:
            assert "*isolated" in line, line
    tests = ci[ci.index("Tests, measuring"):ci.index("Lantern audits itself")]
    assert "LANTERN_TESTS_NETLESS: required" in tests and "tools/netless.py --watch" in tests
    assert "set -o pipefail" in tests              # the step pipes into tee: without this a failing run would pass


def _checkouts(workflow: str) -> list[str]:
    """The steps of a workflow that fetch the code (actions/checkout), each as its own text."""
    steps = re.split(r"(?m)^(?=[ \t]*-[ \t])", workflow)           # one piece per list item: in a workflow, a step
    return [step for step in steps if re.search(r"(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*actions/checkout@", step)]


def _keeps_the_sign_in(workflow: str) -> list[str]:
    """The first line of every step that fetches the code and leaves the run's own GitHub sign-in in the checkout's
    git settings, which is what actions/checkout does unless it is told `persist-credentials: false`."""
    return [step.strip().splitlines()[0] for step in _checkouts(workflow)
            if not re.search(r"(?m)^[ \t]*persist-credentials:[ \t]*false[ \t]*(?:#.*)?$", step)]


def test_no_workflow_leaves_its_github_sign_in_in_the_checkout():
    """Found in CI on 2026-11-10: a test listed git's settings in the checkout and met the run's own sign-in there
    (tests/test_netguard.py looks in the checkout the tests run in; this reads every workflow, also the ones that
    run on a tag, weekly or by hand)."""
    # the shapes that leave it are caught: nothing said, said the other way, said in a comment only
    assert _keeps_the_sign_in("steps:\n  - uses: actions/checkout@abc  # v4\n  - run: pytest\n") == ["- uses: actions/checkout@abc  # v4"]
    assert _keeps_the_sign_in("steps:\n  - name: code\n    uses: actions/checkout@abc\n    with:\n      ref: main\n") == ["- name: code"]
    assert _keeps_the_sign_in("  - uses: actions/checkout@abc\n    with:\n      persist-credentials: true\n") == ["- uses: actions/checkout@abc"]
    assert _keeps_the_sign_in("  - uses: actions/checkout@abc\n    # persist-credentials: false\n  - run: x\n") == ["- uses: actions/checkout@abc"]
    # one step's setting does not cover the next step's checkout
    assert _keeps_the_sign_in("  - uses: actions/checkout@abc\n    with:\n      persist-credentials: false\n"
                              "  - uses: actions/checkout@abc\n    with:\n      path: other\n") == ["- uses: actions/checkout@abc"]
    # the safe shapes are not: the setting is there (with or without a note), or the step fetches no code
    assert _keeps_the_sign_in("  - uses: actions/checkout@abc  # v4\n    with:\n      persist-credentials: false   # why\n      ref: x\n") == []
    assert _keeps_the_sign_in("  - name: code\n    uses: actions/checkout@abc\n    with:\n      persist-credentials: false\n") == []
    assert _keeps_the_sign_in("  - uses: actions/setup-python@abc\n    with:\n      python-version: '3.12'\n  - run: pytest\n") == []
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    fetched = 0
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        mentions = [line for line in text.splitlines() if "actions/checkout@" in line and not line.lstrip().startswith("#")]
        assert len(_checkouts(text)) == len(mentions), f"{workflow.name}: a checkout is written in a shape this test does not read"
        assert _keeps_the_sign_in(text) == [], workflow.name
        fetched += len(mentions)
    assert workflows and fetched                                 # the pattern still finds the steps it is about


# ---- browser checks: a page under test never reaches the internet (tools/outside.js)

SMOKES = ("tools/viewer_smoke.js", "tools/cloud_site_smoke.js")
BROWSER_CHECKS = (*SMOKES, "tools/report_perf.js")


def _unwatched(text: str) -> list[str]:
    """The lines of a browser check that open a page or a context without handing it to outside.watch (same line or next)."""
    lines = text.splitlines() + [""]
    return [line.strip() for i, line in enumerate(lines[:-1])
            if re.search(r"\bb\.new(?:Page|Context)\(", line) and "outside.watch(" not in line + lines[i + 1]]


def _own_way_out(text: str) -> list[str]:
    """The lines of a browser check that start a browser any other way than outside.launch, which gives it a proxy on
    this computer that refuses as its only way out."""
    return [line.strip() for line in text.splitlines() if re.search(r"(?<!outside)\.launch\w*\(", line)]


def test_every_page_a_browser_check_opens_is_kept_off_the_internet():
    # the shape that lets a page out is caught; the two safe shapes are not
    assert _unwatched("const p = await b.newPage({ viewport });\nawait p.goto(url);\n") == ["const p = await b.newPage({ viewport });"]
    assert _unwatched("const p = await b.newPage();\nawait outside.watch(p, errs);\n") == []
    assert _unwatched("const c = await b.newContext(); await outside.watch(c, errs, outside.FONTS);\n") == []
    for name in SMOKES:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "require('./outside.js')" in text, name
        assert _unwatched(text) == [], name
    # nothing else in tools/ drives a browser, except the helper's own check and the speed check: report_perf.js times
    # a report on a slowed phone, answering its requests would change what it measures, and viewer_smoke.js already
    # checks that the same report asks the outside for nothing (its browser has no way out either: next test)
    drivers = sorted(p.name for p in (ROOT / "tools").glob("*.js") if ".launch(" in p.read_text(encoding="utf-8"))
    assert drivers == ["cloud_site_smoke.js", "outside.js", "report_perf.js", "viewer_smoke.js"], drivers
    helper = (ROOT / "tools" / "outside.js").read_text(encoding="utf-8")
    assert "const FONTS = ['fonts.googleapis.com'];" in helper   # the one thing a page may ask for; adding to it is a decision
    assert "watch(p, errs);" in (ROOT / "tools" / "viewer_smoke.js").read_text(encoding="utf-8")   # a report: nothing at all
    audit = (ROOT / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert audit.count("node tools/outside.js") == 2   # the helper is checked in a real browser, in every engine


def test_every_browser_a_check_starts_has_no_way_out_but_a_proxy_here_that_refuses():
    """A page's requests are not a browser's only way out (a connection hint, a page nobody watched, the browser's own
    housekeeping): each check starts its browser through outside.launch and closes it through outside.close, which
    turns anything that reached the proxy, other than a try for the pages' font host, into a failure."""
    assert _own_way_out("const b = await chromium.launch();") == ["const b = await chromium.launch();"]
    assert _own_way_out("const b = await pw[engine].launchPersistentContext(dir);") != []
    assert _own_way_out("const b = await outside.launch(chromium);   // its only way out") == []
    for name in BROWSER_CHECKS:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert _own_way_out(text) == [], name
        assert text.count("outside.launch(") == text.count("outside.close(") >= 1, name
        assert "b.close()" not in text, name                   # closing any other way would skip the count
    helper = (ROOT / "tools" / "outside.js").read_text(encoding="utf-8")
    # Only this computer's own two addresses go round the proxy. For Chromium "<-loopback>" comes first: Playwright up
    # to 1.48 (the version CI installs) writes it after the list when it is missing, where it sends this computer's
    # own pages to the proxy (CI, 2026-11-10: the app got the proxy's 403; 1.63 on a developer's computer did not).
    assert "proxy: { server: await proxy(), bypass: BYPASS[browserType.name()] || 'localhost,127.0.0.1' }" in helper
    assert "const BYPASS = { chromium: '<-loopback>,localhost,127.0.0.1' };" in helper
    assert "socket.end('HTTP/1.1 403 Forbidden" in helper and "net.connect(" not in helper.split("if (require.main === module)")[0]


def test_the_audit_shows_what_each_browser_tried_also_when_its_check_passed():
    """Firefox and WebKit run only in CI, so CI's log is the one place their counts can be read. The audit prints the
    helper's own line and the `outside:` count for every engine when the check passed (a failed check shows its last
    lines anyway), and each browser check ends by printing that count."""
    audit = (ROOT / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert audit.count("said '^outside\\.js in '") == 2           # the helper's own check: Chromium, then each other engine
    assert audit.count("said '^outside: '") == 3                  # the first report (Chromium, each other engine), the website
    for program in ("viewer_smoke.js", "cloud_site_smoke.js"):
        assert "console.log(await outside.close(b, errs));" in (ROOT / "tools" / program).read_text(encoding="utf-8")


def _console_handlers(text: str) -> list[str]:
    """The lines of a browser check that decide what a line in a page's console means."""
    return [line.strip() for line in text.splitlines() if re.search(r"\.on\('console',", line)]


def test_what_ends_at_the_proxy_is_counted_only_where_it_is_known_and_fails_the_check_anywhere_else():
    """CI, 2026-11-10, the first run with the proxy as every browser's only way out, on the website check: 39 tries
    by WebKit for the website's font host that the watcher never saw ended at the proxy, and WebKit told the page so
    in 17 console lines; 17 tries by Firefox did, with no console line, and Firefox asked its maker for a newer
    Firefox twice. All of it is stopped at this computer and counted. Nothing else is let off: a console line about
    any other address stays an error, a report (which may ask for nothing) gets no such allowance, and an address a
    browser asks for that is not listed fails the check."""
    assert _console_handlers("p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });\np.on('pageerror', e => 1);") \
        == ["p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });"]
    app, report = _console_handlers((ROOT / "tools" / "viewer_smoke.js").read_text(encoding="utf-8"))
    (site,) = _console_handlers((ROOT / "tools" / "cloud_site_smoke.js").read_text(encoding="utf-8"))
    assert "!outside.refusedFont(m)" in app and "!outside.refusedFont(m)" in site
    assert "refusedFont" not in report and "if (m.type() === 'error') errs.push(" in report
    for line in (app, report, site):
        assert "${outside.where(m)}" in line                   # an error line says which address it is about
    assert _console_handlers((ROOT / "tools" / "report_perf.js").read_text(encoding="utf-8")) == []
    helper = (ROOT / "tools" / "outside.js").read_text(encoding="utf-8")
    assert "const OWN = { firefox: ['aus5.mozilla.org'] };" in helper   # adding an address here is a decision
    assert "if (!asked.mayTry.has(host) && !asked.own.has(host)) errs.push(" in helper
