"""The network guard's own parts (tools/netguard/lantern_netguard.py, tools/netless.py), each with the near-miss that
must keep working. Where a test has to switch the guard on from scratch, it does so in a program of its own, because a
guard cannot be taken off again."""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NETGUARD = ROOT / "tools" / "netguard"
sys.path.insert(0, str(NETGUARD))
sys.path.insert(0, str(ROOT / "tools"))
import lantern_netguard as ng  # noqa: E402
import netless  # noqa: E402

GUARD_VARS = (ng.LOG_ENV, ng.ALLOW_ENV, ng.DENY_ENV, "PYTHONPATH", "NO_PROXY", "no_proxy", *ng.PROXY_VARS)


def _bare_env(**extra) -> dict:
    """This run's environment without its guard: what a program started from an ordinary shell would see."""
    env = {k: v for k, v in os.environ.items() if k not in GUARD_VARS and k not in ng.proxy_variables()}
    env.update(extra)
    return env


def _program(code: str, *args, env=None, **kw):
    head = "import json, os, socket, sys, tempfile, threading\nsys.path.insert(0, %r)\nimport lantern_netguard as ng\n" % str(NETGUARD)
    return subprocess.run([sys.executable, "-c", head + textwrap.dedent(code), *args], env=env or _bare_env(),
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, **kw)


def _json(r):
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def _kept_as(name: str) -> str:
    """A variable's name the way this system keeps it. Windows has one variable whatever the case it is written in
    (`https_proxy` and `HTTPS_PROXY` are the same one) and Python shows it in capitals; elsewhere they are two."""
    return name.upper() if os.name == "nt" else name


# ----------------------------------------------------------------------------- a forwarding proxy on this computer
FORWARDER = """
    seen = []
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(8)
    port = listener.getsockname()[1]
    def serve():
        while True:
            c, _ = listener.accept()
            seen.append(c.recv(300).decode("latin-1").split("\\r\\n")[0]); c.close()
    threading.Thread(target=serve, daemon=True).start()
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "YARN_HTTPS_PROXY", "npm_config_https_proxy", "GLOBAL_AGENT_HTTPS_PROXY"):
        os.environ[name] = f"http://127.0.0.1:{port}"
    os.environ["ELECTRON_GET_USE_PROXY"] = "1"
    os.environ["NO_PROXY"] = "localhost,internal.example"
    guard = ng.isolate(tempfile.mkdtemp())
    out = {"forwarder": port, "ours": guard.proxy_port, "vars": {k: v for k, v in os.environ.items() if "PROXY" in k.upper()}}
    try:
        socket.create_connection(("127.0.0.1", port), timeout=3); out["direct"] = "connected"
    except OSError as e:
        out["direct"] = str(e)
    import urllib.request
    try:
        urllib.request.urlopen("https://lantern-probe.example/x", timeout=5); out["url"] = "answered"
    except OSError as e:
        out["url"] = str(e)
    import time; time.sleep(0.2)
    out["seen"] = seen
    out["attempts"] = [[a["kind"], a["host"], a["port"]] for a in guard.since(0)]
    print(json.dumps(out))
"""


def test_a_forwarding_proxy_on_this_computer_is_a_way_out_and_is_refused():
    """Found on 2026-11-10: five requests per test run went to api.osv.dev through a forwarding proxy listening on
    127.0.0.1, which the old protection let through as "this computer"."""
    out = _json(_program(FORWARDER))
    ours = f"http://127.0.0.1:{out['ours']}"
    v = out["vars"]
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "YARN_HTTPS_PROXY", "GLOBAL_AGENT_HTTPS_PROXY", "ALL_PROXY"):
        assert v[_kept_as(name)] == ours, name                    # every tool's proxy setting now ends at the guard
    assert _kept_as("npm_config_https_proxy") not in v            # npm's own settings are taken out with the keys
    assert v["ELECTRON_GET_USE_PROXY"] == "1"                     # a switch is not an address: untouched
    assert v["NO_PROXY"] == ng.NO_PROXY
    assert ng.MARK in out["direct"]                               # the address itself is refused, though it is local
    assert "403" in out["url"]                                    # the request ended at the guard's own proxy
    assert out["seen"] == []                                      # the forwarding proxy heard nothing
    assert ["connect", "127.0.0.1", out["forwarder"]] in out["attempts"]
    assert ["proxy", "lantern-probe.example", 443] in out["attempts"]


@pytest.mark.parametrize("name, value, address", [
    ("HTTPS_PROXY", "http://127.0.0.1:3128", ("http", "127.0.0.1", 3128, "")),
    ("https_proxy", "http://Proxy.Example:8080/", ("http", "proxy.example", 8080, "")),
    ("npm_config_https_proxy", "http://user:pw@proxy.example:8080", ("http", "proxy.example", 8080, "user:pw")),
    ("YARN_HTTPS_PROXY", "proxy.example:8080", ("http", "proxy.example", 8080, "")),
    ("ALL_PROXY", "socks5://proxy.example", ("socks5", "proxy.example", 1080, "")),
    ("HTTP_PROXY", "http://[::1]:3128", ("http", "::1", 3128, "")),
    ("DOCKER_HTTPS_PROXY", "https://proxy.example", ("https", "proxy.example", 443, "")),
    # not a proxy's address
    ("ELECTRON_GET_USE_PROXY", "1", None), ("CCR_AGENT_PROXY_ENABLED", "true", None), ("HTTP_PROXY", "", None),
    ("NO_PROXY", "localhost,127.0.0.1", None), ("GLOBAL_AGENT_NO_PROXY", "internal.example:8080", None),
    ("npm_config_noproxy", "internal.example:8080", None), ("PROXY_NOTES", "see the wiki page", None),
    ("HTTPS_PORT", "http://127.0.0.1:3128", None),
])
def test_which_variables_hold_a_proxy_address(name, value, address):
    assert ng.proxy_variables({name: value}).get(name) == address


DECLARED = """
    seen, auth = [], []
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(8)
    port = listener.getsockname()[1]
    def one(c):
        head = b""
        while b"\\r\\n\\r\\n" not in head:
            chunk = c.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.decode("latin-1").split("\\r\\n")
        seen.append(lines[0]); auth.extend(x for x in lines if x.lower().startswith("proxy-authorization"))
        c.sendall(b"HTTP/1.1 200 OK\\r\\n\\r\\n")
        c.sendall(c.recv(100).upper()); c.close()
    def serve():
        while True:
            c, _ = listener.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    os.environ["HTTPS_PROXY"] = f"http://someone:pass%20word@127.0.0.1:{port}"
    guard = ng.isolate(tempfile.mkdtemp(), allow=["declared.example"])
    def through(target):
        s = socket.create_connection(("127.0.0.1", guard.proxy_port), timeout=5)
        s.sendall(f"CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n".encode())
        status = s.recv(4096).decode("latin-1").split("\\r\\n")[0]
        reply = ""
        if " 200" in status:
            s.sendall(b"hello"); reply = s.recv(100).decode()
        s.close()
        return [status, reply]
    out = {"declared": through("declared.example:443"), "sub": through("api.declared.example:8443"),
           "other": through("other.example:443"), "lookalike": through("declared.example.evil.example:443")}
    out["seen"], out["auth"] = seen, auth
    out["attempts"] = [[a["kind"], a["host"], a["port"]] for a in guard.since(0)]
    out["through"] = [[r["host"], r["port"], r["how"]] for r in guard.let_through()]
    out["proxy_var"] = os.environ["HTTPS_PROXY"]
    print(json.dumps(out))
"""


def test_a_benchmark_reaches_a_declared_host_and_nothing_else_also_through_this_computers_proxy():
    out = _json(_program(DECLARED))
    assert out["declared"] == ["HTTP/1.1 200 Connection established", "HELLO"]
    assert out["sub"] == ["HTTP/1.1 200 Connection established", "HELLO"]
    assert out["other"][0].startswith("HTTP/1.1 403") and out["lookalike"][0].startswith("HTTP/1.1 403")
    assert out["seen"] == ["CONNECT declared.example:443 HTTP/1.1", "CONNECT api.declared.example:8443 HTTP/1.1"]
    expected = "Basic " + base64.b64encode(b"someone:pass word").decode("ascii")
    assert out["auth"] == [f"Proxy-Authorization: {expected}"] * 2            # the forwarding proxy's own sign-in is kept
    assert "someone" not in out["proxy_var"]                                  # ...in memory, not in what programs inherit
    assert out["attempts"] == [["proxy", "other.example", 443], ["proxy", "declared.example.evil.example", 443]]
    assert out["through"] == [["declared.example", 443, "proxy"], ["api.declared.example", 8443, "proxy"]]


LOCAL = """
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(8)
    port = listener.getsockname()[1]
    def serve():
        while True:
            c, _ = listener.accept()
            data = c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok" if data.startswith(b"GET ") else data.upper())
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    guard = ng.isolate(tempfile.mkdtemp())
    def ask(first):
        s = socket.create_connection(("127.0.0.1", guard.proxy_port), timeout=5)
        s.sendall(first)
        got = s.recv(4096)
        if b" 200 Connection established" in got:
            s.sendall(b"hello"); got = s.recv(100)
        s.close()
        return got.decode("latin-1")
    out = {"tunnel": ask(f"CONNECT 127.0.0.1:{port} HTTP/1.1\\r\\n\\r\\n".encode()),
           "plain": ask(f"GET http://localhost:{port}/x HTTP/1.1\\r\\nHost: localhost:{port}\\r\\n\\r\\n".encode()),
           "attempts": guard.since(0)}
    print(json.dumps(out))
"""


def test_a_program_that_sends_everything_to_its_proxy_still_reaches_this_computer():
    out = _json(_program(LOCAL))
    assert out["tunnel"] == "HELLO" and out["plain"].endswith("ok") and out["attempts"] == []


# ----------------------------------------------------------------------------- the rules
@pytest.mark.network_refused("checks what the refusal looks like to the code that is refused")
def test_a_refusal_is_an_ordinary_connection_error_with_a_plain_reason(network_attempts):
    with pytest.raises(OSError, match="LANTERN-NETGUARD-REFUSED: connect 192.0.2.1:9"):
        socket.create_connection(("192.0.2.1", 9), timeout=1)
    with pytest.raises(OSError, match="lookup lantern-probe.example"):
        socket.getaddrinfo("lantern-probe.example", 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(OSError, match="send 192.0.2.1:53"):
            s.sendto(b"x", ("192.0.2.1", 53))
    finally:
        s.close()
    kinds = [(a["kind"], a["host"]) for a in network_attempts()]
    assert kinds == [("connect", "192.0.2.1"), ("lookup", "lantern-probe.example"), ("send", "192.0.2.1")]


def test_this_computer_stays_reachable():
    """By address and by name. The listener takes each caller in before the next one calls: a caller left waiting
    fills a short queue, and Windows refuses the next one where Linux lets it wait (found in CI on 2026-11-10, where
    the second call was refused by the listener's full queue, not by the guard)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(5)
    try:
        for host in ("127.0.0.1", "localhost"):
            c = socket.create_connection((host, server.getsockname()[1]), timeout=5)
            taken, _ = server.accept()
            taken.close()
            c.close()
        assert socket.getaddrinfo("localhost", 80) and socket.getaddrinfo(None, 80)
        socket.getfqdn()                                       # looks this computer's own name up; must not count
    finally:
        server.close()


@pytest.mark.parametrize("host, local", [
    ("127.0.0.1", True), ("127.8.9.10", True), ("::1", True), ("localhost", True), ("LOCALHOST.", True),
    ("0.0.0.0", True), ("::", True), ("::ffff:127.0.0.1", True), ("", True), (None, True), (b"localhost", True),
    ("fe80::1%lo", False), ("192.0.2.1", False), ("10.0.0.5", False), ("169.254.169.254", False),
    ("localhost.evil.example", False), ("127.0.0.1.evil.example", False), ("api.anthropic.com", False),
    ("::ffff:192.0.2.1", False), ("2001:db8::1", False), ("0x7f.1", False),
])
def test_what_counts_as_this_computer(host, local):
    assert ng.is_local(host) is local


@pytest.mark.parametrize("name, value, removed", [
    ("ANTHROPIC_API_KEY", "x", True), ("ANTHROPIC_BASE_URL", "https://x", True), ("OPENAI_ORG", "x", True),
    ("LANTERN_TOKEN", "x", True), ("LANTERN_MODEL", "x", True), ("LANTERN_GATEWAY_URL", "x", True),
    ("LANTERN_ADMIN_SECRET", "x", True), ("LANTERN_GITHUB_APP_KEY", "x", True), ("GITHUB_CLIENT_SECRET", "x", True),
    ("AWS_PROFILE", "x", True), ("AWS_SECRET_ACCESS_KEY", "x", True), ("GOOGLE_APPLICATION_CREDENTIALS", "x", True),
    ("CLOUDSDK_AUTH_ACCESS_TOKEN", "x", True), ("FLY_API_TOKEN", "x", True), ("KUBECONFIG", "x", True),
    ("GH_TOKEN", "x", True), ("GITHUB_TOKEN", "x", True), ("NPM_TOKEN", "x", True), ("SSH_AUTH_SOCK", "x", True),
    ("GIT_ASKPASS", "x", True), ("PGPASSWORD", "x", True), ("DB_PASSWORD", "x", True), ("SENTRY_DSN", "x", True),
    ("MYSQL_PWD", "x", True), ("CLIENT_SECRETS_FILE", "x", True), ("OPENAIAPIKEY", "x", True),
    ("DATABASE_URL", "sqlite:///x.db", True), ("SOME_URL", "https://user:pw@host.example/x", True),
    ("api_key", "x", True), ("My_Secret", "x", True),
    # near-misses that must stay
    ("PATH", "/usr/bin", False), ("HOME", "/home/x", False), ("MAX_THINKING_TOKENS", "1", False),
    ("TOKENIZERS_PARALLELISM", "false", False), ("KEYBOARD_LAYOUT", "us", False), ("MONKEY", "x", False),
    ("GITHUB_ACTIONS", "true", False), ("GITHUB_STEP_SUMMARY", "/tmp/x", False), ("GITHUB_SHA", "abc", False),
    ("LANTERN_SANDBOX", "subprocess", False), ("LANTERN_BROWSERS", "firefox", False),
    ("LANTERN_BUDGET_SCALE", "2", False), ("DOCKER_HOST", "unix:///var/run/docker.sock", False),
    ("SOME_URL", "https://host.example/x?a=b@c", False), ("PYTHONPATH", "/x", False), ("CI", "true", False),
    ("LANTERN_NETGUARD_LOG", "/tmp/x", False), ("AUTHOR", "x", False), ("PWD", "/x", False), ("OLDPWD", "/", False),
    ("TMPDIR", "/tmp", False), ("VIRTUAL_ENV", "/v", False), ("NODE_PATH", "/n", False), ("SSL_CERT_FILE", "/c", False),
])
def test_which_variables_are_taken_out_of_the_run(name, value, removed):
    assert ng.is_credential(name, value) is removed


def test_scrub_removes_and_reports_and_leaves_the_rest():
    env = {"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "x", "GH_TOKEN": "y", "LANG": "C", "MAX_THINKING_TOKENS": "5"}
    assert ng.scrub(env) == ["ANTHROPIC_API_KEY", "GH_TOKEN"]
    assert env == {"PATH": "/usr/bin", "LANG": "C", "MAX_THINKING_TOKENS": "5"}


def test_a_benchmark_reaches_only_the_hosts_it_declared(monkeypatch):
    monkeypatch.setattr(ng._S, "allow", frozenset({"github.com", "api.osv.dev"}))
    monkeypatch.setattr(ng._S, "allow_ips", {"140.82.112.3"})
    assert ng.is_declared("github.com") and ng.is_declared("codeload.github.com") and ng.is_declared("API.OSV.DEV.")
    assert ng.is_declared("140.82.112.3")                       # an address a declared name resolved to
    assert not ng.is_declared("github.com.evil.example") and not ng.is_declared("notgithub.com")
    assert not ng.is_declared("api.anthropic.com") and not ng.is_declared("140.82.112.4")


# ----------------------------------------------------------------------------- keys carried in git's own variables
def test_git_settings_in_variables_go_together_or_git_stops_working():
    """`GIT_CONFIG_COUNT` with `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` can rewrite addresses and carry sign-in headers
    (Lantern's own cloud worker hands a token to git this way). The key names contain KEY, the others do not: removing
    only those leaves git refusing to start."""
    planted = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraheader", "GIT_CONFIG_VALUE_0": "Authorization: x",
               "GIT_CONFIG_PARAMETERS": "'user.name=x'", "GIT_CONFIG_GLOBAL": "/somewhere/else"}
    env = {"PATH": os.environ.get("PATH", ""), **planted}
    assert ng.scrub(env) == sorted(planted) and env == {"PATH": os.environ.get("PATH", "")}
    git = shutil.which("git")
    if not git:
        pytest.skip("git is not installed")
    base = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
    half = {**base, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_VALUE_0": "Authorization: x"}       # the key was taken, the rest left
    assert subprocess.run([git, "config", "--list"], env=half, capture_output=True).returncode != 0
    assert subprocess.run([git, "config", "--list"], env=base, capture_output=True).returncode == 0


# What a git setting can carry. A test's message names the kind and nothing else: a setting's value can be a sign-in
# (`http.<address>.extraheader`), and so can its name (`url.https://me:TOKEN@host/.insteadof`).
HEADER = "a sign-in sent with every request (extraheader)"
PASSWORD = "an address with a password in it"
REWRITE = "an address rewritten to another (insteadof)"
IDENTITY = "the developer's own name on commits (user.email, signingkey)"


def _git_carries(folder, *scope):
    """What the settings carry that git reads when it is started in `folder`: every setting, or with `--local` the
    checkout's own. None when git is not installed or cannot say (`--local` outside a checkout). Looking for a
    checkout stops at `folder`, so a temporary folder that happens to sit inside one shows only what the shell and
    the home folder hand to git. The settings themselves stay in here: a test that fails shows its own variables
    when pytest is asked to (`-l`), and only the kinds are among them."""
    git = shutil.which("git")
    if not git:
        return None
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(folder).parent)}
    r = subprocess.run([git, "config", *scope, "--list", "-z"], cwd=folder, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return None
    return _carried(tuple(item.partition("\n")[::2]) for item in r.stdout.split("\0") if item)


def _carried(settings) -> list:
    """The kinds of thing these git settings, (name, value) pairs, carry that a test must not be handed."""
    kinds = set()
    for name, value in settings:
        section, _, key = name.lower().rpartition(".")
        if key == "extraheader":
            kinds.add(HEADER)
        if key in ("insteadof", "pushinsteadof"):
            kinds.add(REWRITE)
        if ng._URL_PASSWORD.search(name) or ng._URL_PASSWORD.search(value):
            kinds.add(PASSWORD)
        if (section, key) == ("user", "email") or key == "signingkey":
            kinds.add(IDENTITY)
    return sorted(kinds)


def test_what_a_git_setting_can_carry():
    """Made-up settings: the ones that carry a sign-in, send git somewhere else or name the developer, each next to
    the ordinary setting that must stay clean."""
    header = "AUTHORIZATION: basic " + base64.b64encode(b"x-access-token:made-up").decode("ascii")
    assert _carried([("http.https://github.com/.extraheader", header)]) == [HEADER]
    assert _carried([("http.extraHeader", header)]) == [HEADER]
    assert _carried([("remote.origin.url", "https://me:made-up@git.example/app.git")]) == [PASSWORD]
    assert _carried([("url.https://me:made-up@git.example/.insteadOf", "https://git.example/")]) == sorted([PASSWORD, REWRITE])
    assert _carried([("url.git@git.example:.pushInsteadOf", "https://git.example/")]) == [REWRITE]
    assert _carried([("user.email", "me@example.com")]) == [IDENTITY]
    assert _carried([("user.signingkey", "ABCD1234")]) == [IDENTITY]
    assert _carried([
        ("remote.origin.url", "https://github.com/LittleHenderson/Lantern.git"),      # no password: an address
        ("remote.origin.url", "http://someone@127.0.0.1:8080/git/app"),               # a name before the @, no password
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
        ("branch.main.remote", "origin"), ("core.bare", "false"), ("core.autocrlf", "true"), ("gc.auto", "0"),
        ("user.name", "Someone"), ("alias.email", "log --format=%ae"), ("http.sslverify", "true"),
        ("safe.directory", "/home/someone/app"),
    ]) == []


def test_a_git_setting_from_the_developers_shell_does_not_reach_a_test(tmp_path):
    """Asked in a folder that is no checkout, git shows what the shell and the home folder hand it: nothing of the
    developer's. (Asked in the checkout it also shows the checkout's own settings: the next test.)"""
    assert [k for k in os.environ if k.upper().startswith("GIT_CONFIG") and k.upper() != "GIT_CONFIG_NOSYSTEM"] == []
    carried = _git_carries(tmp_path)
    assert carried in (None, [])                 # None: git is not installed here


def test_the_checkout_the_tests_run_in_holds_no_sign_in():
    """Found in CI on 2026-11-10: the step that fetches the code had left that run's own GitHub sign-in in the
    checkout's git settings, where every test, and every program a test starts there, could read it. The workflows
    no longer leave it (`persist-credentials: false`, tests/test_isolation.py); this looks where the tests run.
    A developer whose own checkout fails here has a password or token saved in it (`git config --local --list`
    shows where): a credential helper keeps it out of the folder."""
    carried = _git_carries(ROOT, "--local")
    if carried is None:
        pytest.skip("git cannot list this folder's own settings: no git here, or not a checkout it accepts")
    assert [kind for kind in carried if kind in (HEADER, PASSWORD)] == []


# ----------------------------------------------------------------------------- what the guard refuses, and what it does not
def test_an_address_written_out_is_not_a_name_lookup():
    assert socket.getaddrinfo("192.0.2.1", 443)[0][4][0] == "192.0.2.1"       # nothing is asked of any name server
    assert socket.gethostbyname("192.0.2.1") == "192.0.2.1"
    assert socket.getaddrinfo("::1", 80) and socket.getaddrinfo(None, 80)


def test_datagrams_on_this_computer_pass():
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        a.bind(("127.0.0.1", 0))
        b.sendto(b"x", a.getsockname())
        a.settimeout(5)
        assert a.recv(10) == b"x"
    finally:
        a.close()
        b.close()


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no local sockets on this system")
def test_local_sockets_pass(tmp_path):
    path = str(tmp_path / "s")
    server = socket.socket(socket.AF_UNIX)
    client = socket.socket(socket.AF_UNIX)
    try:
        server.bind(path)
        server.listen(1)
        client.connect(path)
    except OSError as e:                      # some systems limit the path's length; that is not what is tested here
        if ng.MARK in str(e):
            raise
        pytest.skip(str(e))
    finally:
        server.close()
        client.close()


@pytest.mark.network_refused("checks every way a Python program can name an outside address")
def test_every_way_to_name_an_outside_address_is_refused(network_attempts):
    tries = [lambda: socket.gethostbyname("lantern-probe.example"),
             lambda: socket.gethostbyname_ex("lantern-probe.example"),
             lambda: socket.gethostbyaddr("192.0.2.1"),
             lambda: socket.getnameinfo(("192.0.2.1", 80), 0),
             lambda: socket.create_connection(("192.0.2.1", 80), timeout=1),
             lambda: socket.socket().connect_ex(("192.0.2.1", 80))]
    try:
        six = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        six = None                               # this system has no IPv6 at all
    if six is not None:
        tries.append(lambda: six.connect(("2001:db8::1", 80)))
    for attempt in tries:
        with pytest.raises(OSError, match=ng.MARK):
            attempt()
    assert len(network_attempts()) == len(tries)
    if six is not None:
        six.close()


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root to start a program as another user")
def test_a_program_under_another_user_cannot_write_the_record_so_it_stops_and_says_why(network_attempts):
    """The record of attempts is its owner's alone: nobody else on the computer can add to it or empty it. A program
    of the run that has become another user therefore cannot write there. It must not carry on as if nothing happened."""
    code = ("import socket\ntry:\n    socket.create_connection(('192.0.2.1', 9), timeout=1)\n"
            "except OSError as e:\n    print('hidden:', e)\nprint('carried on')\n")
    r = subprocess.run([sys.executable, "-c", code], user=65534, group=65534, extra_groups=[], cwd="/",
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == ng.UNRECORDED and "carried on" not in r.stdout, r.stdout + r.stderr
    assert ng.MARK + ": could not be written down" in r.stderr and '"host": "192.0.2.1"' in r.stderr
    assert network_attempts() == []                       # and the record was not touched by the other user


def test_the_record_and_its_folder_are_the_owners_alone():
    import stat
    log = os.environ[ng.LOG_ENV]
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(log).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(log)).st_mode) == 0o700


# ----------------------------------------------------------------------------- a Python program a test starts
def test_a_program_that_cannot_be_guarded_does_not_run(tmp_path):
    lonely = tmp_path / "path"
    lonely.mkdir()
    shutil.copy(NETGUARD / "sitecustomize.py", lonely / "sitecustomize.py")       # the guard itself is not beside it
    log = tmp_path / "log.jsonl"
    env = _bare_env(PYTHONPATH=str(lonely), **{ng.LOG_ENV: str(log)})
    r = subprocess.run([sys.executable, "-c", "print('ran')"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 97 and "ran" not in r.stdout and ng.MARK in r.stderr
    assert json.loads(log.read_text(encoding="utf-8").splitlines()[0])["kind"] == "guard-failed"


def test_another_start_up_file_on_the_path_still_runs(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import os\nos.environ['OTHER_STARTUP_RAN'] = 'yes'\n", encoding="utf-8")
    env = _bare_env(PYTHONPATH=os.pathsep.join([str(NETGUARD), str(other)]), **{ng.LOG_ENV: str(tmp_path / "log")})
    code = "import os, sys; print(os.environ.get('OTHER_STARTUP_RAN'), sys.modules['lantern_netguard'].installed())"
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
    assert r.stdout.split() == ["yes", "True"], r.stdout + r.stderr


def test_without_the_guards_variable_the_start_up_file_does_nothing(tmp_path):
    env = _bare_env(PYTHONPATH=str(NETGUARD))
    r = subprocess.run([sys.executable, "-c", "import sys; print('lantern_netguard' in sys.modules)"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "False", r.stdout + r.stderr


# ----------------------------------------------------------------------------- a Python program in isolated mode
REPORTS = ("import json, socket, sys\n"
           "guard = sys.modules.get('lantern_netguard')\n"
           "tried = None\n"
           "if 'try' in sys.argv:\n"
           "    try:\n        socket.create_connection(%r, timeout=1); tried = 'connected'\n"
           "    except OSError as e:\n        tried = str(e)\n"
           "print(json.dumps({'guarded': bool(guard and guard.installed()), 'isolated': sys.flags.isolated, 'tried': tried,\n"
           "                  'argv': sys.argv[1:], 'name': __name__}))\n"
           "if 'seven' in sys.argv:\n    raise SystemExit(7)\n" % (ng.PROBE,))


def test_a_python_program_in_isolated_mode_is_guarded_when_started_through_the_guard(tmp_path):
    """`python -I` reads nothing from PYTHONPATH, so the start-up file beside the guard is never loaded: started the
    plain way, such a program has no guard in it (only the proxy and, on Linux, the netless runner stand in its way).
    Started through the guard (`python_isolated`, as the held-out benchmark starts its analyses) it is refused and
    written down like any other program."""
    script = tmp_path / "reports.py"
    script.write_text(REPORTS, encoding="utf-8")
    log = tmp_path / "log.jsonl"
    env = _bare_env(PYTHONPATH=str(NETGUARD), **{ng.LOG_ENV: str(log)})
    run = lambda cmd, e=env: subprocess.run(cmd, env=e, capture_output=True, text=True, encoding="utf-8", timeout=60)  # noqa: E731
    # the dangerous shape: the plain way, the guard is not in the program (it tries nothing here)
    plain = run([sys.executable, "-I", str(script)])
    assert json.loads(plain.stdout) == {"guarded": False, "isolated": 1, "tried": None, "argv": [], "name": "__main__"}
    # the same program, same mode, through the guard
    cmd = ng.python_isolated(str(script), "try", "b")
    assert cmd[:2] == [sys.executable, "-I"] and cmd[-3:] == [str(script), "try", "b"]
    through = run(cmd)
    seen = json.loads(through.stdout)
    assert through.returncode == 0 and ng.MARK in seen.pop("tried"), through.stdout + through.stderr
    assert seen == {"guarded": True, "isolated": 1, "argv": ["try", "b"], "name": "__main__"}
    attempts = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [(a["kind"], a["host"], a["port"]) for a in attempts] == [("connect", *ng.PROBE)]
    # the program's own result is passed on, and a program that tries nothing leaves nothing in the record
    assert run(ng.python_isolated(str(script), "seven")).returncode == 7
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1
    # a module, the way the held-out benchmark starts `lantern.cli`
    module = run(ng.python_isolated("-m", "json.tool", "--help"))
    assert module.returncode == 0 and "usage" in module.stdout.lower(), module.stdout + module.stderr
    # with no guarded run around it, nothing is started
    for wrong, e in ((ng.python_isolated(str(script)), _bare_env()), (ng.python_isolated(), env), (ng.python_isolated("-m"), env)):
        r = run(wrong, e)
        assert r.returncode == 97 and r.stdout == "" and ng.MARK in r.stderr, wrong


# ----------------------------------------------------------------------------- from a shell
RUNNER = [sys.executable, str(NETGUARD / "lantern_netguard.py")]
SEES = ("import json, os, socket\n"
        "try:\n    socket.create_connection(('192.0.2.1', 9), timeout=1); r = 'connected'\n"
        "except OSError as e:\n    r = str(e)\n"
        "print(json.dumps({'home': os.path.expanduser('~'), 'key': os.environ.get('ANTHROPIC_API_KEY'), 'tried': r,\n"
        "                  'offline': os.environ.get('LANTERN_OFFLINE'), 'no_real': os.environ.get('LANTERN_NO_REAL_PROVIDERS')}))\n")


def test_any_command_can_be_run_isolated(tmp_path):
    env = _bare_env(HOME=str(tmp_path), ANTHROPIC_API_KEY="planted-" + "k" * 6)
    r = subprocess.run([*RUNNER, "--offline", "--", sys.executable, "-c", SEES], env=env, capture_output=True, text=True,
                       encoding="utf-8", timeout=120)
    seen = json.loads(r.stdout)
    assert seen["key"] is None and seen["offline"] == "1" and seen["no_real"] == "1"
    assert not seen["home"].startswith(str(tmp_path)) and "lantern-isolated-" in seen["home"]
    assert ng.MARK in seen["tried"]
    assert r.returncode == 4                                       # the command hid the error; the run fails for it
    assert "1 attempt(s) to reach anything else" in r.stderr and "connect 192.0.2.1:9" in r.stderr
    assert not Path(seen["home"]).exists()                         # the temporary home is gone afterwards


def test_the_isolated_runner_passes_the_commands_own_result_on():
    quiet = subprocess.run([*RUNNER, "--", sys.executable, "-c", "print('fine')"], env=_bare_env(), capture_output=True,
                           text=True, timeout=120)
    assert quiet.returncode == 0 and quiet.stdout.strip() == "fine" and ng.MARK not in quiet.stderr
    assert "0 attempt(s) to reach anything else" in quiet.stderr
    assert subprocess.run([*RUNNER, "--", sys.executable, "-c", "raise SystemExit(7)"], env=_bare_env(),
                          timeout=120).returncode == 7
    for wrong in ([], ["--allow"], ["--", ], ["--nonsense", "--", "true"], [sys.executable, "-c", "pass"]):
        r = subprocess.run([*RUNNER, *wrong], env=_bare_env(), capture_output=True, text=True, timeout=60)
        assert r.returncode == 2 and "usage" in r.stderr, wrong
    missing = subprocess.run([*RUNNER, "--", "no-such-program-here"], env=_bare_env(), capture_output=True, text=True,
                             timeout=60)
    assert missing.returncode == 127 and "cannot start" in missing.stderr


def test_browsers_and_python_packages_installed_for_the_user_stay_usable(tmp_path):
    """They are software, not sign-ins: the browser smokes (tools/audit.sh --browser) run in the temporary home."""
    real = tmp_path / "real"
    cache = real / "Library" / "Caches" if sys.platform == "darwin" else real / ".cache"
    (cache / "ms-playwright").mkdir(parents=True)
    env = {"HOME": str(real), "LOCALAPPDATA": str(cache)}
    ng.temp_home(str(tmp_path / "home"), env)
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == str(cache / "ms-playwright") and env["HOME"] == str(tmp_path / "home")
    assert env["PYTHONUSERBASE"] and not env["PYTHONUSERBASE"].startswith(str(tmp_path / "home"))
    chosen = {"HOME": str(real), "PLAYWRIGHT_BROWSERS_PATH": "/somewhere/else"}
    ng.temp_home(str(tmp_path / "home2"), chosen)
    assert chosen["PLAYWRIGHT_BROWSERS_PATH"] == "/somewhere/else"                 # already chosen: left alone
    none = {"HOME": str(tmp_path / "empty")}
    ng.temp_home(str(tmp_path / "home3"), none)
    assert "PLAYWRIGHT_BROWSERS_PATH" not in none                                  # nothing installed: nothing set


# ----------------------------------------------------------------------------- no network at all (Linux)
NETLESS = ROOT / "tools" / "netless.py"
INSIDE = ("import socket, sys\n"
          "srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1)\n"
          "socket.create_connection(('127.0.0.1', srv.getsockname()[1]), timeout=5).close()\n"
          "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
          "try:\n    s.connect(%r); print('ROUTE')\n"
          "except OSError as e:\n    print('NO-ROUTE', e.errno)\n" % (ng.PROBE,))


def _netless(*cmd, **kw):
    env = {k: v for k, v in os.environ.items() if k not in (ng.LOG_ENV, "PYTHONPATH")}   # see the system, not the guard
    return subprocess.run([sys.executable, str(NETLESS), "--", *cmd], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120, env=env, **kw)


def test_no_network_at_all_inside_the_netless_runner():
    """The child runs without the guard, so what it meets is the operating system's own answer: no route."""
    if not ng.has_route_out():       # this whole run is already inside the netless runner (CI): check it from here
        env = {k: v for k, v in os.environ.items() if k not in (ng.LOG_ENV, "PYTHONPATH")}
        r = subprocess.run([sys.executable, "-c", INSIDE], capture_output=True, text=True, timeout=60, env=env)
        assert r.returncode == 0 and r.stdout.split()[0] == "NO-ROUTE", r.stdout + r.stderr
        return
    probe = _netless(sys.executable, "-c", "print('in')")
    if probe.returncode == 3:
        pytest.skip("this system cannot start a command without a network: " + probe.stderr.strip()[-200:])
    assert probe.returncode == 0 and probe.stdout.strip() == "in", probe.stderr
    r = _netless(sys.executable, "-c", INSIDE)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[0] == "NO-ROUTE", r.stdout          # this computer answers, nothing else has a route
    assert _netless(sys.executable, "-c", "raise SystemExit(7)").returncode == 7   # the command's own result comes back


def test_the_netless_runner_says_what_it_needs():
    r = subprocess.run([sys.executable, str(NETLESS)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 2 and "usage" in r.stderr.lower()


# ----------------------------------------------------------------------------- inside a benchmark
BENCHMARK = """
    def answer(host, port, *more, **kw):
        # A name server's answer without a name server. A declared host is let through, and a real lookup of one
        # would leave this computer; the guard is still asked first, the way the real function asks it.
        sys.audit("socket.getaddrinfo", host, port, 0, 0, 0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port or 0))]
    socket.getaddrinfo = answer
    os.environ["ANTHROPIC_API_KEY"] = "planted-1"
    os.environ["LANTERN_TOKEN"] = "planted-2"
    guard = ng.begin(allow=sys.argv[2].split(",") if sys.argv[2] else [], live=sys.argv[3] == "live")
    seen = {"key": os.environ.get("ANTHROPIC_API_KEY"), "token": os.environ.get("LANTERN_TOKEN"),
            "no_real": os.environ.get("LANTERN_NO_REAL_PROVIDERS"), "home": os.path.expanduser("~"),
            "again": ng.begin() is None}
    for host in ("declared.example", "other.example"):
        try:
            socket.getaddrinfo(host, 443); seen[host] = "looked up"
        except OSError as e:
            seen[host] = str(e)
    folder = guard.folder
    seen["result"] = ng.end(guard)
    seen["folder_left"] = os.path.exists(folder)
    print(json.dumps(seen))
"""


def _plain_env() -> dict:
    """An ordinary shell: nothing of this test run's own isolation is left in it, so the counts below are exact."""
    return {k: v for k, v in _bare_env().items() if k != ng.NO_REAL_ENV and not ng.is_credential(k, v)}


def test_a_benchmark_starts_isolated_and_fails_when_something_else_was_tried():
    r = _program(BENCHMARK, str(NETGUARD), "", "", env=_plain_env())
    seen = _json(r)
    assert seen["key"] is None and seen["token"] is None and seen["no_real"] == "1"
    assert "lantern-isolated-" in seen["home"] and seen["again"] is True          # a second `begin` leaves it alone
    assert ng.MARK in seen["declared.example"] and ng.MARK in seen["other.example"]     # nothing was declared
    assert seen["result"] == 1 and seen["folder_left"] is False
    assert "2 key and sign-in variables taken out" in r.stderr and "network refused except for: nothing" in r.stderr
    assert "2 attempt(s) to reach anything else" in r.stderr and "lookup other.example:443" in r.stderr


def test_the_live_suite_reaches_one_host_and_leaves_no_key_in_the_environment():
    """bench/live.py makes its one approved provider first (the key is then in that object), so even a live run
    hands no key to the programs it starts."""
    r = _program(BENCHMARK, str(NETGUARD), "declared.example", "live", env=_plain_env())
    seen = _json(r)
    assert seen["token"] is None and seen["key"] is None
    assert seen["no_real"] is None                                                # a live run: not switched off
    assert "2 key and sign-in variables taken out" in r.stderr
    assert ng.MARK in seen["other.example"] and ng.MARK not in seen["declared.example"]
    assert seen["result"] == 1                                                    # the other host was tried: it fails
    assert "real model providers ON, for this live run only" in r.stderr
    assert "network refused except for: declared.example" in r.stderr


def test_a_live_run_never_switches_real_providers_back_on_where_they_are_off():
    """Inside a test or benchmark run the switch is on; a live run started there must not take it off."""
    r = _program(BENCHMARK, str(NETGUARD), "declared.example", "live", env={**_plain_env(), ng.NO_REAL_ENV: "1"})
    assert _json(r)["no_real"] == "1" and "real model providers off" in r.stderr     # and it says what is true


def test_inside_a_test_run_a_benchmark_does_not_switch_the_guard_again(capsys):
    assert ng.begin() is None and ng.end(None) == 0
    assert "already inside one" in capsys.readouterr().err


# ----------------------------------------------------------------------------- the operating system's own record
TRACE = """\
100 execve("/usr/bin/python3", ["python3", "-m", "pytest", "-q"], 0x7ffd /* 40 vars */) = 0
100 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
100 connect(5, {sa_family=AF_INET, sin_port=htons(40123), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
100 sendto(5, "GET / HTTP/1.1\\r\\n", 16, 0, NULL, 0) = 16
100 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 101
101 execve("/usr/bin/pip-audit", ["pip-audit", "-r", "/tmp/x/requirements.txt"], 0x55 /* 41 vars */) = 0
101 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0
101 connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.0.223")}, 16 <unfinished ...>
100 connect(7, {sa_family=AF_INET6, sin6_port=htons(8080), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
101 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)
101 connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.0.223")}, 16) = -1 ENETUNREACH (Network is unreachable)
100 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f, stack_size=0x9000}, 88 <unfinished ...>
100 <... clone3 resumed>) = 102
102 execve("/usr/bin/git", ["git", "ls-remote", "https://example.invalid/x.git"], 0x55 /* 41 vars */) = 0
102 connect(5, {sa_family=AF_INET, sin_port=htons(3128), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)
102 sendto(8, "\\0", 1, 0, {sa_family=AF_INET6, sin6_port=htons(5353), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "ff02::fb", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)
100 connect(9, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 23) = 0
100 connect(9, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
100 connect(4, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("203.0.113.254")}, 16) = -1 ENETUNREACH (Network is unreachable)
103 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.9")}, 16 <unfinished ...>
"""


def test_the_operating_systems_record_is_read_for_every_program(tmp_path):
    trace = tmp_path / "trace"
    trace.write_text(TRACE, encoding="utf-8")
    s = netless.summarize(str(trace), forwarder_ports={3128})
    got = {(e["kind"], e["address"], e["port"], e["program"], e["count"], e["result"]) for e in s["outside"]}
    assert got == {
        ("lookup", "127.0.0.53", 53, "pip-audit -r /tmp/x/requirements.txt", 1, "ok"),      # a question to a name server
        ("connect", "151.101.0.223", 443, "pip-audit -r /tmp/x/requirements.txt", 2, "ENETUNREACH"),
        ("forwarding proxy", "127.0.0.1", 3128, "git ls-remote https://example.invalid/x.git", 1, "ECONNREFUSED"),
        ("send", "ff02::fb", 5353, "git ls-remote https://example.invalid/x.git", 1, "ENETUNREACH"),
        ("connect", "192.0.2.9", 443, "?", 1, ""),                                             # never came back: counted
    }
    assert s["connections_on_this_computer"] == 2                    # 127.0.0.1:40123 and [::1]:8080
    assert s["checks_that_there_is_no_route"] == 1                   # the guard's own "is there a route?" address
    assert s["services_on_this_computer_with_their_own_way_out"] == {"/var/run/docker.sock": 1}
    assert netless.summarize(str(trace))["connections_on_this_computer"] == 3        # no forwarder named: 3128 is local


def test_a_record_with_clock_times_reads_the_same(tmp_path):
    """`strace -ttt` puts the time after the process number; the baseline record of this work was taken that way."""
    trace = tmp_path / "trace"
    trace.write_text('7 1794275812.302250 execve("/usr/bin/curl", ["curl", "https://example.org"], 0x7f /* 9 vars */) = 0\n'
                     '7 1794275812.402250 connect(5, {sa_family=AF_INET, sin_port=htons(443), '
                     'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS (Operation now in progress)\n',
                     encoding="utf-8")
    assert netless.summarize(str(trace))["outside"] == [
        {"kind": "connect", "address": "93.184.216.34", "port": 443, "program": "curl https://example.org", "count": 1,
         "result": "EINPROGRESS"}]


def _being_recorded() -> bool:
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    return any(line.startswith("TracerPid:") and line.split()[1] != "0" for line in status.splitlines())


def _can_go_netless() -> str | None:
    if not sys.platform.startswith("linux"):
        return "only Linux can give a command a network of its own"
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "netless.py"), "--", sys.executable, "-c", "pass"],
                       env=_bare_env(), capture_output=True, text=True, timeout=60)
    return None if r.returncode == 0 else (r.stderr.strip()[-200:] or "cannot")


def test_the_netless_runner_writes_down_what_was_tried_and_fails_the_run(tmp_path):
    why = _can_go_netless()
    if why or not shutil.which("strace"):
        pytest.skip(why or "the strace program is not installed")
    if _being_recorded():
        pytest.skip("this run is itself being recorded by the operating system; a recording cannot hold another one")
    code = ("import socket\n"
            "srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1)\n"
            "socket.create_connection(srv.getsockname(), timeout=5).close()\n"
            "try:\n    socket.create_connection(('192.0.2.1', 443), timeout=1)\nexcept OSError:\n    pass\n")
    out = tmp_path / "watch.json"
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "netless.py"), "--watch", str(out), "--", sys.executable,
                        "-c", code], env=_bare_env(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 4, r.stderr                              # the program hid the error; the run fails for it
    seen = json.loads(out.read_text(encoding="utf-8"))
    assert [(e["kind"], e["address"], e["port"], e["result"]) for e in seen["outside"]] == [
        ("connect", "192.0.2.1", 443, "ENETUNREACH")]
    assert seen["connections_on_this_computer"] >= 1 and seen["result"] == 0
    quiet = subprocess.run([sys.executable, str(ROOT / "tools" / "netless.py"), "--watch", str(out), "--", sys.executable,
                            "-c", "raise SystemExit(5)"], env=_bare_env(), capture_output=True, text=True, timeout=120)
    assert quiet.returncode == 5 and json.loads(out.read_text(encoding="utf-8"))["outside"] == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root, as when CI starts the runner with sudo")
def test_started_with_sudo_the_command_runs_as_the_caller_not_as_root():
    if _can_go_netless():
        pytest.skip(_can_go_netless())
    env = _bare_env(SUDO_UID="65534", SUDO_GID="65534", SUDO_USER="nobody")
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "netless.py"), "--", sys.executable, "-c",
                        "import os; print(os.getuid(), os.getgid(), os.environ.get('SUDO_UID'))"], env=env, cwd="/",
                       capture_output=True, text=True, timeout=60)
    assert r.stdout.split() == ["65534", "65534", "None"], r.stdout + r.stderr


def test_the_run_can_be_required_to_have_no_network(tmp_path):
    """CI sets LANTERN_TESTS_NETLESS=required: started outside the netless runner, the suite stops before any test."""
    if not ng.has_route_out():
        pytest.skip("this run has no route to the outside, so the refusal cannot be shown from here")
    probe = tmp_path / "test_nothing.py"
    probe.write_text("def test_nothing():\n    pass\n", encoding="utf-8")
    env = _bare_env(LANTERN_TESTS_NETLESS="required")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        str(ROOT / "tests" / "probe_isolation.py"), "-k", "test_probe_test_body_is_isolated"],
                       cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    assert r.returncode == 4 and "LANTERN_TESTS_NETLESS=required" in (r.stdout + r.stderr), r.stdout + r.stderr
    assert "passed" not in r.stdout


def test_nothing_listens_for_the_guard_on_other_addresses():
    """The guard's proxy is for programs of this run: it listens on 127.0.0.1 only."""
    listener, port = ng._S.proxy
    assert listener.getsockname()[0] == "127.0.0.1" and port == listener.getsockname()[1]


def test_threads_started_by_a_test_are_guarded_too():
    seen = []

    def work():
        try:
            socket.getaddrinfo("192.0.2.1", 80)
            seen.append("address ok")
            socket.create_connection(("127.0.0.1", 9), timeout=1)
        except ConnectionError:
            seen.append("local refused by the system, not by the guard")
        except OSError as e:
            seen.append(str(e))
    t = threading.Thread(target=work)
    t.start()
    t.join(30)
    assert seen[0] == "address ok" and ng.MARK not in seen[-1]
