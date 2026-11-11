"""Probes run only by tests/test_isolation.py, inside a second pytest that is started the way a developer would start
it: real-looking keys in the environment, a saved sign-in and saved keys in the home folder, no offline switch. Each
probe says what a test (or a set-up step shared by a whole file, or a program a test starts) can still see or reach.

Not collected in the normal run: the file name does not start with `test_`. Some probes are meant to FAIL; the outer
test checks that they do.
"""
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from lantern import providers

OUTSIDE = ("192.0.2.1", 9)     # a documentation address (RFC 5737): never a real machine
PLANTED = [k for k in os.environ.get("PROBE_PLANTED", "").split(",") if k]   # names the outer test planted
DEV_HOME = os.environ.get("PROBE_DEV_HOME", "")
FORWARDER = int(os.environ.get("PROBE_FORWARDER") or 0)   # a forwarding proxy on the developer's computer (its port)


def _try_outside() -> str:
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(OUTSIDE)
        return "connected"
    except OSError as e:
        return str(e)
    finally:
        s.close()


def _snapshot() -> dict:
    return {"offline": os.environ.get("LANTERN_OFFLINE"),
            "planted_still_here": sorted(k for k in PLANTED if k in os.environ),
            "home": str(Path.home()),
            "config_dir": str(providers.config_dir()),
            "lantern_home": os.environ.get("LANTERN_HOME", ""),
            "token": providers.load_token(),
            "outside": _try_outside()}


def _clean(seen: dict) -> None:
    assert seen["offline"] == "1"
    assert seen["planted_still_here"] == []
    assert DEV_HOME and not seen["home"].startswith(DEV_HOME), seen["home"]
    assert not seen["config_dir"].startswith(DEV_HOME), seen["config_dir"]
    assert seen["lantern_home"] and not seen["lantern_home"].startswith(DEV_HOME)
    assert seen["token"] is None
    assert "LANTERN-NETGUARD-REFUSED" in seen["outside"], seen["outside"]


@pytest.fixture(scope="module")
def shared():
    """A set-up step shared by the whole file. pytest runs these before any per-test fixture."""
    return _snapshot()


@pytest.mark.network_refused("the shared set-up step tries an outside address on purpose, to prove it is refused")
def test_probe_shared_setup_is_isolated(shared):
    _clean(shared)


@pytest.mark.network_refused("tries an outside address on purpose, to prove it is refused")
def test_probe_test_body_is_isolated():
    _clean(_snapshot())


CHILD = ("import json, os, socket, sys\n"
         "s = socket.socket(); s.settimeout(1)\n"
         "try:\n    s.connect(('192.0.2.1', 9)); r = 'connected'\n"
         "except OSError as e:\n    r = str(e)\n"
         "print(json.dumps({'outside': r, 'planted': sorted(k for k in sys.argv[1].split(',') if k in os.environ),\n"
         "                  'home': os.path.expanduser('~'), 'offline': os.environ.get('LANTERN_OFFLINE')}))\n")


@pytest.mark.network_refused("starts a Python program that tries an outside address, to prove it is refused there too")
def test_probe_python_child_is_isolated(network_attempts):
    import json
    r = subprocess.run([sys.executable, "-c", CHILD, ",".join(PLANTED)], capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    seen = json.loads(r.stdout)
    assert "LANTERN-NETGUARD-REFUSED" in seen["outside"], seen
    assert seen["planted"] == [] and seen["offline"] == "1" and not seen["home"].startswith(DEV_HOME)
    mine = [a for a in network_attempts() if a["kind"] == "connect" and a["host"] == "192.0.2.1"]
    assert mine and mine[0]["pid"] != os.getpid()            # written down by the child, read here


@pytest.mark.network_refused("has git ask for an outside address, to prove the request ends at the refusing proxy")
def test_probe_other_program_ends_at_the_refusing_proxy(network_attempts, tmp_path):
    git = shutil.which("git")
    if not git:
        pytest.skip("git is not installed")
    r = subprocess.run([git, "ls-remote", "https://192.0.2.1/nothing.git"], cwd=tmp_path, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode != 0
    asked = [a for a in network_attempts() if a["kind"] == "proxy" and a["host"] == "192.0.2.1"]
    assert asked and asked[0]["port"] == 443, network_attempts()


def test_probe_real_provider_is_switched_off(network_attempts):
    p = providers.make_provider("anthropic/claude-haiku-5-5", api_key="not-a-key")
    with pytest.raises(providers.ProviderError, match="switched off"):
        p.complete("system", "user")
    assert network_attempts() == []                           # refused before anything was sent or looked up


@pytest.mark.network_refused("tries the forwarding proxy this computer was set up with, to prove it is refused")
def test_probe_forwarding_proxy_on_this_computer_is_not_used(network_attempts):
    assert FORWARDER
    with pytest.raises(OSError, match="LANTERN-NETGUARD-REFUSED"):
        socket.create_connection(("127.0.0.1", FORWARDER), timeout=2)          # by its address, though it is local
    assert [k for k, v in os.environ.items() if "PROXY" in k.upper() and str(FORWARDER) in v] == []
    code = "import os; print([k for k, v in os.environ.items() if 'PROXY' in k.upper() and %r in v])" % str(FORWARDER)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "[]", r.stdout + r.stderr                       # nor does a program a test starts
    assert [a["port"] for a in network_attempts() if a["kind"] == "connect"] == [FORWARDER]


def test_probe_git_settings_from_the_shell_are_gone():
    git = shutil.which("git")
    if not git:
        pytest.skip("git is not installed")
    r = subprocess.run([git, "config", "--list"], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr                 # git still starts (it stops when only some of them are removed)
    assert "rewritten.invalid" not in r.stdout


# ----------------------------------------------------------------------------- probes that must FAIL
def test_probe_FAILS_swallowed_attempt():
    """The code under test tries the network and hides the error. The test must fail all the same."""
    try:
        socket.create_connection(OUTSIDE, timeout=1)
    except OSError:
        pass


def test_probe_FAILS_swallowed_attempt_in_a_child():
    code = ("import socket\ntry:\n    socket.create_connection(('192.0.2.1', 9), timeout=1)\n"
            "except OSError:\n    pass\n")
    assert subprocess.run([sys.executable, "-c", code], timeout=60).returncode == 0


@pytest.fixture(scope="module")
def shared_that_reaches_out():
    try:
        socket.create_connection(OUTSIDE, timeout=1)
    except OSError:
        pass
    return True


def test_probe_FAILS_attempt_in_shared_setup(shared_that_reaches_out):
    assert shared_that_reaches_out


@pytest.mark.network_refused("says it tries the network, and does not")
def test_probe_FAILS_marked_without_an_attempt():
    assert True


def test_probe_FAILS_name_lookup():
    """Looking a name up already tells a name server which service is being contacted."""
    try:
        socket.getaddrinfo("lantern-probe.example", 443)
    except OSError:
        pass


def test_probe_FAILS_through_the_proxy_variables():
    """A program that follows the proxy variables (a Python child using urllib) ends at the guard's own proxy."""
    code = ("import urllib.request\ntry:\n    urllib.request.urlopen('https://lantern-probe.example/x', timeout=5)\n"
            "except OSError:\n    pass\n")
    assert subprocess.run([sys.executable, "-c", code], timeout=60).returncode == 0


def test_probe_FAILS_skipping_after_an_attempt():
    """"No network here, skip" is how an attempt usually hides."""
    try:
        socket.create_connection(OUTSIDE, timeout=1)
    except OSError:
        pytest.skip("no network here")


def test_probe_FAILS_by_itself_after_an_attempt():
    try:
        socket.create_connection(OUTSIDE, timeout=1)
    except OSError:
        pass
    raise AssertionError("its own reason")
