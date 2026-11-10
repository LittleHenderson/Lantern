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
                  ng.LOG_ENV, ng.ALLOW_ENV, ng.DENY_ENV, "LANTERN_TESTS_NETLESS")


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
                                        if p and Path(p).resolve() != (ROOT / "tools" / "netguard").resolve())
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


# ----------------------------------------------------------------------------- this run itself
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
BENCHMARKS = ("bench/run_bench.py", "bench/mobile/run_mobile.py", "bench/fuzz.py", "tools/large_apps.py",
              "tools/mutation.py", "tools/load_test.py")
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
    source = (ROOT / "lantern" / "depaudit.py").read_text(encoding="utf-8")
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


# ---- browser checks: a page under test never reaches the internet (tools/outside.js)

SMOKES = ("tools/viewer_smoke.js", "tools/cloud_site_smoke.js")


def _unwatched(text: str) -> list[str]:
    """The lines of a browser check that open a page or a context without handing it to outside.watch (same line or next)."""
    lines = text.splitlines() + [""]
    return [line.strip() for i, line in enumerate(lines[:-1])
            if re.search(r"\bb\.new(?:Page|Context)\(", line) and "outside.watch(" not in line + lines[i + 1]]


def test_every_page_a_browser_check_opens_is_kept_off_the_internet():
    # the shape that lets a page out is caught; the two safe shapes are not
    assert _unwatched("const p = await b.newPage({ viewport });\nawait p.goto(url);\n") == ["const p = await b.newPage({ viewport });"]
    assert _unwatched("const p = await b.newPage();\nawait outside.watch(p, errs);\n") == []
    assert _unwatched("const c = await b.newContext(); await outside.watch(c, errs, outside.FONTS);\n") == []
    for name in SMOKES:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "require('./outside.js')" in text and "outside.summary()" in text, name
        assert _unwatched(text) == [], name
    # nothing else in tools/ drives a browser, except the helper's own check and the speed check: report_perf.js times
    # a report on a slowed phone, answering its requests would change what it measures, and viewer_smoke.js already
    # checks that the same report asks the outside for nothing
    drivers = sorted(p.name for p in (ROOT / "tools").glob("*.js") if ".launch(" in p.read_text(encoding="utf-8"))
    assert drivers == ["cloud_site_smoke.js", "outside.js", "report_perf.js", "viewer_smoke.js"], drivers
    helper = (ROOT / "tools" / "outside.js").read_text(encoding="utf-8")
    assert "const FONTS = ['fonts.googleapis.com'];" in helper   # the one thing a page may ask for; adding to it is a decision
    assert "watch(p, errs);" in (ROOT / "tools" / "viewer_smoke.js").read_text(encoding="utf-8")   # a report: nothing at all
    audit = (ROOT / "tools" / "audit.sh").read_text(encoding="utf-8")
    assert audit.count("node tools/outside.js") == 2   # the helper is checked in a real browser, in every engine

