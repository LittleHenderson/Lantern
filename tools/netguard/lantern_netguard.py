"""Keeps a test or benchmark run, and the programs it starts, off the internet, and writes down every attempt.

Layers, each for what the others cannot see:

  1. an audit hook in this Python process (`install`): a connection, a datagram or a name lookup that is not for this
     computer is refused before it is made, and recorded. An audit hook cannot be removed, and it also sees code that
     uses `_socket` directly.
  2. the same hook in every Python child: `activate` puts this folder first on PYTHONPATH, and `sitecustomize.py`
     beside this file installs the hook when the child starts. Every process appends its attempts to one log file.
     A child in isolated mode (`python -I`) reads nothing from PYTHONPATH: a benchmark starts one through
     `python_isolated`, which switches the hook on first. A child that root starts under another user must be able
     to read this folder, or Python leaves it out of the path without a word: where others may not read it, root's
     run puts a copy every user can read on the path instead (`guard_folder`), and leaves it there when it ends,
     because Python leaves a folder that is gone out of the path just as quietly.
  3. a proxy on 127.0.0.1 for programs that are not Python (git, npm, curl): every proxy variable points at it. It
     writes down what was asked for and answers 403; a host a benchmark declared is passed through instead.
  4. a forwarding proxy this computer was already configured with (a company proxy, a container's own) is a way out
     even when it listens on 127.0.0.1: its address is refused like any outside address, and the proxy variables
     that named it are pointed at 3.

What these cannot stop (a program that ignores the proxy variables, a child started with a clean environment or in
isolated mode by code that does not use `python_isolated`, such as the test sandbox's own jail) is stopped on Linux by
running the whole command without a network: `tools/netless.py`.

`scrub` and `temp_home` take the developer's keys, tokens and saved sign-ins out of the run; `isolate` does all of it
in the right order.

Only the standard library and nothing from Lantern: children that do not have Lantern installed load this file at
start-up.
"""
from __future__ import annotations

import base64
import errno
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse

LOG_ENV = "LANTERN_NETGUARD_LOG"       # every refused attempt, one JSON object per line, from every process
ALLOW_ENV = "LANTERN_NETGUARD_ALLOW"   # host names a benchmark has declared (comma-separated); tests leave it empty
DENY_ENV = "LANTERN_NETGUARD_DENY"     # ports on this computer where a forwarding proxy listens (comma-separated)
NO_REAL_ENV = "LANTERN_NO_REAL_PROVIDERS"   # read by lantern/providers.py: nothing is sent to a real model provider
MARK = "LANTERN-NETGUARD-REFUSED"
UNGUARDED, UNRECORDED = 97, 97    # a program ends with this when the guard cannot start in it, or cannot write down
                                  # what it refused
HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_FILES = ("lantern_netguard.py", "sitecustomize.py")    # all a program needs to load the guard
# Where a copy of the guard goes when root's programs need one that every user can read (`guard_folder`): the first
# of these that is safe to load a program from. Named places, not the temporary folder the run's environment points
# at: that one is its user's alone. /run first: only root can write there, and nothing clears it while the computer
# is running (it starts empty at every boot).
PUBLIC_PLACES = ("/run", "/tmp", "/var/tmp")   # nosec B108: named on purpose, each checked before use (guard_folder)
NO_PROXY = "localhost,127.0.0.1,::1"
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
LOCAL_NAMES = frozenset({"", "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})
# The address `has_route_out` points a socket at, and the one tests use when they check from outside the guard that
# there is no route: a documentation address (RFC 5737), never a real machine. tools/netless.py --watch lists
# attempts to it apart from the rest, because they are the check itself.
PROBE = ("203.0.113.254", 9)


class Refused(OSError):
    """A connection, datagram or name lookup that would have left this computer."""


class _State:
    installed = False
    log: str | None = None
    allow: frozenset = frozenset()
    allow_ips: set = set()
    hostname = ""
    deny_ports: frozenset = frozenset()   # forwarding proxies on this computer: a way out, refused like one
    attempts: list = []          # this process's own refused attempts, oldest first
    proxy = None                 # (listening socket, port) once the proxy runs
    upstream = None              # (host, port, authorization) of the forwarding proxy declared hosts are reached through
    public: str | None = None    # the copy of the guard every user can read, once asked for ("" when there is none)


_S = _State()
_busy = threading.local()
_lock = threading.Lock()


# ------------------------------------------------------------------------------------------------ what counts as local
def _text(host) -> str:
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    return str(host).strip().lower().rstrip(".").split("%")[0]


def is_local(host) -> bool:
    """This computer: no host at all, `localhost`, its own name, a loopback or unspecified address."""
    if host is None:
        return True
    h = _text(host)
    if h in LOCAL_NAMES or (_S.hostname and h == _S.hostname):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_unspecified


def is_declared(host) -> bool:
    """A host a benchmark declared with `allow=`: the name itself, a subdomain of it, or an address it resolved to."""
    h = _text(host)
    if h in _S.allow_ips:
        return True
    return any(h == a or h.endswith("." + a) for a in _S.allow)


def _is_address(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _learn(host) -> None:
    """A declared name is being looked up: remember its addresses, because the connection that follows names only
    the address."""
    h = _text(host)
    if _is_address(h):
        return
    try:
        for info in socket.getaddrinfo(h, None):
            _S.allow_ips.add(_text(info[4][0]))
    except OSError:
        pass


# ------------------------------------------------------------------------------------------------ the audit hook
_IP_FAMILIES = {int(socket.AF_INET), int(socket.AF_INET6)}
_LOCAL_FAMILIES = {int(getattr(socket, "AF_UNIX", -1)), int(getattr(socket, "AF_NETLINK", -2))}


def _target(event: str, args: tuple):
    """(kind, host, port) for a socket event that names a destination, else None."""
    if event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
        sock, address = args[0], args[1]
        if address is None:
            return None
        family = int(getattr(sock, "family", socket.AF_INET))
        if family in _LOCAL_FAMILIES:
            return None
        kind = "connect" if event == "socket.connect" else "send"
        if family in _IP_FAMILIES and isinstance(address, tuple) and address:
            return kind, address[0], address[1] if len(address) > 1 else None
        return kind, f"<{getattr(family, 'name', family)} {address!r}>"[:120], None   # raw packets, Bluetooth, ...
    if event in ("socket.getaddrinfo", "socket.gethostbyname"):
        host = args[0]
        if host is None or _is_address(_text(host)):
            return None            # an address written out is not looked up anywhere; the connection is judged
        return "lookup", host, args[1] if len(args) > 1 else None
    if event == "socket.gethostbyaddr":
        return "lookup", args[0], None      # a reverse lookup asks a name server about the address
    if event == "socket.getnameinfo":
        addr = args[0]
        return ("lookup", addr[0], None) if isinstance(addr, tuple) and addr else None
    return None


def _argv() -> list:
    argv = getattr(sys, "orig_argv", None) or getattr(sys, "argv", None) or []
    return [str(a)[:120] for a in argv[:6]]


def _append(path: str, rec: dict) -> bool:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (json.dumps(rec) + "\n").encode("utf-8"))    # one short write: lines never interleave
        finally:
            os.close(fd)
        return True
    except OSError:
        return False


def record(kind: str, host, port=None, note: str = "", argv=None) -> dict:
    """Write a refused attempt down, here and in the log every process of the run shares."""
    rec = {"kind": kind, "host": _text(host) if not str(host).startswith("<") else str(host), "port": port,
           "pid": os.getpid(), "argv": _argv() if argv is None else argv, "time": round(time.time(), 3)}
    if note:
        rec["note"] = note[:200]
    with _lock:
        _S.attempts.append(rec)
        written = bool(_S.log) and _append(_S.log, rec)
        if not written and os.environ.get(LOG_ENV):
            # The log is the owner's alone (nobody else on this computer can add to it or empty it), so a program
            # the run started under another user cannot write there. It says so and stops on the spot: an attempt
            # nobody can count must not be followed by the program carrying on as if nothing had happened.
            try:
                os.write(2, (MARK + ": could not be written down: " + json.dumps(rec) + "\n").encode("utf-8"))
            except OSError:
                pass
            if _S.proxy is None:                      # not the process that owns the run: that one keeps its list
                os._exit(UNRECORDED)
    return rec


def _let_through(host, port, how: str) -> None:
    """A declared host was reached: kept beside the log (`<log>.allowed`), so a benchmark can say what it contacted."""
    if _S.log:
        _append(_S.log + ".allowed", {"host": _text(host), "port": port, "how": how, "pid": os.getpid(),
                                      "time": round(time.time(), 3)})


def _hook(event: str, args: tuple) -> None:
    if not event.startswith("socket.") or getattr(_busy, "on", False):
        return
    target = _target(event, args)
    if target is None:
        return
    kind, host, port = target
    forwarder = is_local(host) and kind != "lookup" and port in _S.deny_ports
    if is_local(host) and not forwarder:
        return
    _busy.on = True
    try:
        if not forwarder and is_declared(host):
            if kind == "lookup":
                _learn(host)
            else:
                _let_through(host, port, "direct")
            return
        record(kind, host, port, note="a forwarding proxy on this computer" if forwarder else "")
    finally:
        _busy.on = False
    where = f"{_text(host)}:{port}" if port not in (None, 0, "") else _text(host)
    raise Refused(errno.ENETUNREACH, f"{MARK}: {kind} {where} (tests and benchmarks may not reach the network)")


def install(log: str | None = None, allow=None, deny_ports=None) -> None:
    """Start refusing in this process. Safe to call again: the log, the declared hosts and the forwarding proxies'
    ports are updated, the hook is added once."""
    if log is None:
        log = os.environ.get(LOG_ENV) or None
    if allow is None:
        allow = [a for a in os.environ.get(ALLOW_ENV, "").split(",") if a.strip()]
    if deny_ports is None:
        deny_ports = [p for p in os.environ.get(DENY_ENV, "").split(",") if p.strip().isdigit()]
    _S.log = log
    _S.allow = frozenset(_text(a) for a in allow)
    _S.deny_ports = frozenset(int(p) for p in deny_ports)
    if not _S.installed:
        try:
            _S.hostname = socket.gethostname().strip().lower()
        except OSError:
            _S.hostname = ""
        sys.addaudithook(_hook)
        _S.installed = True


def installed() -> bool:
    return _S.installed


# ------------------------------------------------------------------------------------------------ the proxy
_REQUEST = re.compile(r"^([A-Z]+)\s+(\S+)")
_REFUSAL = (MARK + ": tests and benchmarks may not reach the network\n").encode("ascii")
_BY_PROXY = ["(a program that asked the proxy: its request is in the note)"]


def _proxy_target(line: str):
    """(host, port, whether it asks for a tunnel) for the first line of a request to a proxy, else None."""
    m = _REQUEST.match(line)
    if not m:
        return None
    method, what = m.group(1), m.group(2)
    if method == "CONNECT":
        host, _, port = what.rpartition(":")
        return host.strip("[]"), int(port) if port.isdigit() else None, True
    m2 = re.match(r"^([a-z][a-z0-9+.-]*)://(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?", what, re.I)
    if m2:
        default = 443 if m2.group(1).lower() in ("https", "wss") else 80
        return m2.group(2).strip("[]"), int(m2.group(3)) if m2.group(3) else default, False
    return what[:120], None, False


def _reply(conn, status: str, body: bytes = b"") -> None:
    conn.sendall((f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body)


def _dial(host: str, port: int, tunnel: bool, forwarder):
    """The proxy's own connection for a request it lets through: straight to `host`, or by way of the forwarding
    proxy this computer was configured with. The audit hook stands aside for this thread while it dials."""
    _busy.on = True
    try:
        if not forwarder:
            return socket.create_connection((host, port), timeout=30)
        far = socket.create_connection(forwarder[:2], timeout=30)
        if not tunnel:
            return far                      # a plain request is handed to the forwarding proxy as it came
        try:
            name = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            auth = f"Proxy-Authorization: {forwarder[2]}\r\n" if forwarder[2] else ""
            far.sendall(f"CONNECT {name} HTTP/1.1\r\nHost: {name}\r\n{auth}\r\n".encode("latin-1"))
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = far.recv(4096)
                if not chunk:
                    break
                head += chunk
            status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if not re.match(r"^HTTP/\d\.\d 2\d\d", status):
                raise OSError(f"the forwarding proxy answered: {status[:100] or 'nothing'}")
            return far
        except BaseException:
            far.close()
            raise
    finally:
        _busy.on = False


def _relay(a, b) -> None:
    import select
    a.settimeout(None)
    b.settimeout(None)
    while True:
        ready, _, broken = select.select([a, b], [], [a, b], 600)
        if not ready or broken:
            return
        for s in ready:
            data = s.recv(65536)
            if not data:
                return
            (b if s is a else a).sendall(data)


def _answer(conn) -> None:
    """One request to the proxy. An address on this computer is passed through (a program that sends everything to
    its proxy still reaches a test server), a declared host is passed through and noted, everything else is written
    down and answered 403."""
    far = None
    try:
        conn.settimeout(10)
        data = b""
        while b"\n" not in data and len(data) < 8192:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\n", 1)[0].decode("latin-1", "replace").strip()
        target = _proxy_target(line) if line else None
        if target is None:
            return
        host, port, tunnel = target
        local = port is not None and is_local(host) and port not in _S.deny_ports
        declared = port is not None and not is_local(host) and is_declared(host)
        if not (local or declared):
            record("proxy", host, port, note=line, argv=_BY_PROXY)
            _reply(conn, "403 Forbidden", _REFUSAL)
            return
        if tunnel:                              # the rest of the CONNECT request is for the proxy, not for the far end
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            data = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        try:
            far = _dial(host, port, tunnel, _S.upstream if declared else None)
        except OSError as e:
            _reply(conn, "502 Bad Gateway", (str(e)[:200] + "\n").encode("utf-8", "replace"))
            return
        if declared:
            _let_through(host, port, "proxy")
        if tunnel:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if data:
            far.sendall(data)
        _relay(conn, far)
    except OSError:
        pass
    finally:
        for sock in (conn, far):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def _serve(listener) -> None:
    while True:
        try:
            conn, _peer = listener.accept()
        except OSError:
            return
        threading.Thread(target=_answer, args=(conn,), daemon=True, name="netguard-proxy").start()


def start_proxy() -> int:
    """The proxy's port on 127.0.0.1 (started once per process)."""
    if _S.proxy is None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        threading.Thread(target=_serve, args=(listener,), daemon=True, name="netguard-proxy").start()
        _S.proxy = (listener, listener.getsockname()[1])
    return _S.proxy[1]


_PROXY_ADDRESS = re.compile(r"^(?:([a-z][a-z0-9+.-]*)://)?(?:([^/@\s]*)@)?(\[[0-9a-f:.]+\]|[^/:@\s]+)(?::(\d+))?/?$", re.I)
_PROXY_PORTS = {"https": 443, "socks": 1080, "socks4": 1080, "socks4a": 1080, "socks5": 1080, "socks5h": 1080}


def _proxy_address(value: str):
    """(scheme, host, port, user and password) when `value` is a proxy's address (`http://127.0.0.1:3128`,
    `proxy.example:8080`), else None. A switch such as `1` or `true` is not an address."""
    m = _PROXY_ADDRESS.match((value or "").strip())
    if not m or not (m.group(1) or m.group(4)):
        return None
    scheme = (m.group(1) or "http").lower()
    port = int(m.group(4)) if m.group(4) else _PROXY_PORTS.get(scheme, 80)
    return scheme, m.group(3).strip("[]").lower(), port, m.group(2) or ""


def proxy_variables(environ=None) -> dict:
    """Every variable that holds a proxy's address, whichever tool reads it (`HTTPS_PROXY`, `npm_config_https_proxy`,
    `YARN_HTTPS_PROXY`, ...): {name: (scheme, host, port, user and password)}."""
    env = os.environ if environ is None else environ
    found = {}
    for name, value in env.items():
        n = name.upper()
        if "PROXY" in n and "NO_PROXY" not in n and "NOPROXY" not in n:
            address = _proxy_address(value)
            if address:
                found[name] = address
    return found


# ------------------------------------------------------------------------------------------------ keys and the home folder
# A variable is removed when its name contains a password word, when one of the words in its name (split at "_") is
# a key word (so `MAX_THINKING_TOKENS`, `KEYBOARD_LAYOUT` and `AUTHOR` stay), when its name starts like a model
# provider's or a cloud's, or when its value is an address with a password in it.
CREDENTIAL_PARTS = ("PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "CREDENTIAL", "APIKEY")
CREDENTIAL_WORDS = frozenset({"KEY", "TOKEN", "AUTH", "ASKPASS", "COOKIE", "DSN"})
CREDENTIAL_PREFIXES = (
    # model providers and what the gateway reads
    "ANTHROPIC_", "OPENAI_", "DEEPSEEK_", "OPENROUTER_", "MISTRAL_", "GEMINI_", "GROQ_", "XAI_", "COHERE_",
    "TOGETHER_", "PERPLEXITY_", "FIREWORKS_", "REPLICATE_", "HF_", "HUGGINGFACE", "OLLAMA_", "AZURE_OPENAI",
    # clouds and hosts
    "AWS_", "AZURE_", "GOOGLE_", "GCP_", "GCLOUD_", "CLOUDSDK_", "FLY_", "VERCEL_", "NETLIFY_", "SUPABASE_",
    "CLOUDFLARE_", "DIGITALOCEAN_", "HEROKU_", "KUBE",
    # paid services an app under test may call
    "STRIPE_", "TWILIO_", "SENDGRID_", "RESEND_", "PINECONE_", "ELEVENLABS_",
    # package registries
    "NPM_CONFIG_", "TWINE_", "PYPI_", "CARGO_REGISTRY", "GEM_HOST",
    # git settings handed over in variables (GIT_CONFIG_COUNT with its KEY_n/VALUE_n, GIT_CONFIG_PARAMETERS,
    # GIT_CONFIG_GLOBAL): they can rewrite addresses and carry sign-in headers. All of them go, never only some:
    # git stops with an error when the count is there and a key is not.
    "GIT_CONFIG",
)
CREDENTIAL_NAMES = frozenset({
    # Lantern's own: which model, which gateway, whose allowance, the services' secrets
    "LANTERN_MODEL", "LANTERN_GATEWAY_URL", "LANTERN_PRIMARY", "LANTERN_CONFIG_DIR", "LANTERN_HOME",
    "UPSTREAM_URL", "ANTHROPIC_URL", "DATABASE_URL", "REDIS_URL", "MONGODB_URI", "MONGO_URL", "DOCKER_CONFIG",
    "NETRC", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "GH_CONFIG_DIR", "GNUPGHOME", "MYSQL_PWD",
})
KEEP = frozenset({LOG_ENV, ALLOW_ENV, DENY_ENV})
# What `temp_home` itself sets (some of these names would otherwise count as pointing at a saved sign-in).
SET_BY_TEMP_HOME = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                    "APPDATA", "LOCALAPPDATA", "LANTERN_HOME", "LANTERN_CONFIG_DIR", "GIT_CONFIG_NOSYSTEM",
                    "GIT_TERMINAL_PROMPT", "PIP_CONFIG_FILE", "NPM_CONFIG_USERCONFIG")
_URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@", re.I)


def is_credential(name: str, value: str = "") -> bool:
    """Whether a variable is a key, token, password or saved sign-in, or points a tool at one."""
    n = name.upper()
    if n in KEEP:
        return False
    if n in CREDENTIAL_NAMES or n.startswith(CREDENTIAL_PREFIXES):
        return True
    if any(part in n for part in CREDENTIAL_PARTS) or CREDENTIAL_WORDS.intersection(n.split("_")):
        return True
    return bool(value and _URL_PASSWORD.search(value))


def scrub(environ=None) -> list:
    """Remove every credential variable from `environ` (default: this process). Returns the names removed."""
    env = os.environ if environ is None else environ
    gone = sorted(k for k in list(env) if is_credential(k, env.get(k) or ""))
    for k in gone:
        env.pop(k, None)
    return gone


GIT_IDENTITY = "[user]\n\tname = Lantern tests\n\temail = tests@localhost\n"


def temp_home(home: str, environ=None) -> dict:
    """Point the home folder, the settings folders and Lantern's own folders at `home` (an empty folder). Tools that
    look under the home folder for saved sign-ins (git, npm, pip, docker, cloud command lines, Lantern) find none.
    Software installed for the user is not a sign-in and stays usable: Python packages (`PYTHONUSERBASE`) and the
    browsers Playwright downloaded (`PLAYWRIGHT_BROWSERS_PATH`). Returns the home and settings values it set."""
    env = os.environ if environ is None else environ
    j = os.path.join
    if "PYTHONUSERBASE" not in env:
        try:
            import site
            base = site.getuserbase()
        except Exception:   # noqa: BLE001 - no user base on this interpreter
            base = None
        if base:
            env["PYTHONUSERBASE"] = base
    if "PLAYWRIGHT_BROWSERS_PATH" not in env:      # so do the browsers Playwright installed for the user
        was = env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")
        if sys.platform == "darwin":
            cache = j(was, "Library", "Caches")
        elif os.name == "nt":
            cache = env.get("LOCALAPPDATA") or j(was, "AppData", "Local")
        else:
            cache = env.get("XDG_CACHE_HOME") or j(was, ".cache")
        if os.path.isdir(j(cache, "ms-playwright")):
            env["PLAYWRIGHT_BROWSERS_PATH"] = j(cache, "ms-playwright")
    values = {
        "HOME": home, "USERPROFILE": home,
        "XDG_CONFIG_HOME": j(home, ".config"), "XDG_CACHE_HOME": j(home, ".cache"),
        "XDG_DATA_HOME": j(home, ".local", "share"), "XDG_STATE_HOME": j(home, ".local", "state"),
        "APPDATA": j(home, "AppData", "Roaming"), "LOCALAPPDATA": j(home, "AppData", "Local"),
        "LANTERN_HOME": j(home, ".lantern"), "LANTERN_CONFIG_DIR": j(home, ".config", "lantern"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
        "PIP_CONFIG_FILE": os.devnull, "NPM_CONFIG_USERCONFIG": j(home, ".npmrc"),
    }
    if set(values) != set(SET_BY_TEMP_HOME):       # the two lists are one fact written twice; keep them equal
        raise RuntimeError("SET_BY_TEMP_HOME does not list what temp_home sets")
    for k in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA"):
        os.makedirs(values[k], exist_ok=True)
    git_settings = j(home, ".gitconfig")
    if not os.path.exists(git_settings):
        # A name and an address for git to write in its records. Without them git makes one up from this computer's
        # name, and asks the network what that name is in full: a name lookup on every clone, branch and reset (git
        # 2.56.1 on GitHub's Linux machines, 2026-11-12), which the no-network run counts as reaching outside.
        with open(git_settings, "w", encoding="utf-8") as f:
            f.write(GIT_IDENTITY)
    env.update(values)
    return values


# ------------------------------------------------------------------------------------------------ switching it all on
class Guard:
    """What `activate` and `isolate` return: where the log is, and what was refused since a mark."""

    def __init__(self, log: str, proxy_port: int | None):
        self.log, self.proxy_port = log, proxy_port
        self.folder = self.home = None          # set by `isolate`
        self.removed: list = []                 # the variables `isolate` took out
        self.allow: list = []                   # the declared hosts

    def mark(self) -> int:
        try:
            return os.path.getsize(self.log)
        except OSError:
            return 0

    def _read(self, path: str, mark: int, end: int | None = None) -> list:
        try:
            with open(path, "rb") as f:
                f.seek(mark)
                data = f.read() if end is None else f.read(max(0, end - mark))
        except OSError:
            return []
        out = []
        for line in data.decode("utf-8", "replace").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"kind": "unreadable", "host": line[:120], "port": None, "pid": None, "argv": []})
        return out

    def since(self, mark: int = 0, end: int | None = None) -> list:
        """Every refused attempt written after `mark` (and before `end`, another mark), by any process of the run."""
        return self._read(self.log, mark, end)

    def let_through(self) -> list:
        """Every connection to a declared host that was let through."""
        return self._read(self.log + ".allowed", 0)


def describe(attempts: list) -> str:
    """One line per distinct attempt, for a test's failure message or a benchmark's last lines."""
    seen: dict = {}
    for a in attempts:
        where = f"{a.get('host')}:{a.get('port')}" if a.get("port") not in (None, 0, "") else str(a.get("host"))
        who = " ".join(a.get("argv") or []) or "?"
        if a.get("note"):
            who += f"   [{a['note']}]"
        key = (a.get("kind"), where, who)
        seen[key] = seen.get(key, 0) + 1
    return "\n".join(f"  {n}x {kind} {where}   by: {who}" for (kind, where, who), n in seen.items())


def _everyone_passes(folder: str) -> bool:
    """Every user of this computer may pass through `folder` and through every folder above it."""
    path = os.path.realpath(folder)
    while True:
        if not os.stat(path).st_mode & 0o001:
            return False
        parent = os.path.dirname(path)
        if parent == path:
            return True
        path = parent


def open_to_every_user(folder: str) -> bool:
    """Whether a program under any user of this computer could load the guard from `folder`: everyone may read its
    two files, read the folder, and pass through every folder above it. Read from the permission bits."""
    if os.name != "posix":
        return True
    try:
        if os.stat(folder).st_mode & 0o005 != 0o005 or \
                not all(os.stat(os.path.join(folder, name)).st_mode & 0o004 for name in GUARD_FILES):
            return False
        return _everyone_passes(folder)
    except OSError:
        return False


def holds_the_guard(folder: str) -> bool:
    """A folder on the path that the guard would be loaded from: this one, or a copy of it."""
    return os.path.abspath(folder) == HERE or os.path.isfile(os.path.join(folder, GUARD_FILES[0]))


def _is_root() -> bool:
    return os.name == "posix" and os.geteuid() == 0


def _mine_alone(st, kind) -> bool:
    """What `st` describes is of the kind asked for (a real folder or file, not a link to one), belongs to this user,
    and nobody else may change it."""
    return kind(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022


def _a_copy_to_trust(folder: str, files: dict) -> bool:
    """`folder` can be loaded from by any program of any user, and holds what this folder holds: it is this user's
    own, nobody else may change it or the guard's files in it, everybody may read them, and they are the same, byte
    for byte. Nobody but this user can have put anything into such a folder."""
    import stat
    try:
        st = os.lstat(folder)
        if not _mine_alone(st, stat.S_ISDIR) or st.st_mode & 0o005 != 0o005:
            return False
        for name, ours in files.items():
            st = os.lstat(os.path.join(folder, name))
            if not _mine_alone(st, stat.S_ISREG) or not st.st_mode & 0o004:
                return False
            with open(os.path.join(folder, name), "rb") as f:
                if f.read() != ours:
                    return False
        return True
    except OSError:
        return False


def _copy_for_every_user() -> str:
    """A copy of the guard's two files that every user of this computer can read and only this one can change, in the
    first of PUBLIC_PLACES that is safe to load a program from: the place is root's or this user's own, and if others
    may write there, nobody can rename or remove what is not theirs. Returns "" when this computer has no such place.

    The copy is kept, under a name made from what is in it, and the next run uses it again. It does not go when this
    program ends: a program of the run that is still going then would start its next program from a path whose first
    folder is gone, and Python leaves a folder that is gone out of the path as quietly as one it cannot read. A copy
    found under that name is used only if it can be trusted (`_a_copy_to_trust`); anything else there is left alone,
    and this run gets a copy of its own beside it."""
    import hashlib
    import shutil
    import stat
    import tempfile
    files = {}
    for name in GUARD_FILES:
        with open(os.path.join(HERE, name), "rb") as f:
            files[name] = f.read()
    what = hashlib.sha256(b"".join(name.encode("utf-8") + b"\0" + files[name] + b"\0" for name in GUARD_FILES))
    for place in PUBLIC_PLACES:
        new = ""
        try:
            st = os.stat(place)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or \
                    (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX) or not _everyone_passes(place):
                continue
            kept = os.path.join(place, "lantern-netguard-" + what.hexdigest()[:20])
            if _a_copy_to_trust(kept, files):
                for path in (*(os.path.join(kept, name) for name in files), kept):
                    try:
                        os.utime(path)       # in use again: a system that clears old temporary files leaves it be
                    except OSError:
                        pass
                return kept
            new = tempfile.mkdtemp(prefix="lantern-netguard-new-", dir=place)
            for name, ours in files.items():
                with open(os.path.join(new, name), "wb") as f:
                    f.write(ours)
                os.chmod(os.path.join(new, name), 0o644)
            os.chmod(new, 0o755)     # nosec B103 - a folder every user must be able to enter and read: what it is for
            try:
                os.rename(new, kept)         # in one step: no program finds half a copy under that name
                return kept
            except OSError:
                if _a_copy_to_trust(kept, files):          # another run put the same copy there a moment ago
                    shutil.rmtree(new, ignore_errors=True)
                    return kept
                return new                   # the name is taken by something that cannot be trusted: a copy beside it
        except OSError:
            if new:
                shutil.rmtree(new, ignore_errors=True)
            continue
    return ""


def guard_folder() -> str:
    """The folder the programs of a run load the guard from: the first entry of their PYTHONPATH. This one, as a rule.

    Root is the exception, where other users may not read this folder (a checkout under a home folder that others
    cannot enter: CI's is one). Root can start a program under another user; Python leaves a folder it cannot read
    out of the path without a word; that program would start with no guard in it and carry on. So there the programs
    of the run load a copy that every user can read. Where this computer has no place for one, root is told."""
    if not _is_root() or open_to_every_user(HERE):
        return HERE
    if _S.public is None:
        _S.public = _copy_for_every_user()
        if not _S.public:
            sys.stderr.write(f"network guard: a program this run starts under another user could not read the guard "
                             f"({HERE}), and this computer has no folder that every user can read for a copy of it "
                             f"(looked at: {', '.join(PUBLIC_PLACES) or 'nothing'}): such a program would start "
                             f"without the guard\n")
    return _S.public or HERE


def activate(log: str, allow=(), environ=None, forwarders=None) -> Guard:
    """Switch the guard on for this process and everything it starts. `allow` are the host names a benchmark declares
    it needs (a test declares none). `forwarders` is `proxy_variables()` as it was before anything was removed from
    the environment (default: as it is now)."""
    env = os.environ if environ is None else environ
    allow = [a for a in allow if a]
    found = proxy_variables(env) if forwarders is None else forwarders
    upstream = None                              # declared hosts are reached the way this computer reaches the outside
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        scheme, host, port, userinfo = found.get(name) or ("", "", 0, "")
        if scheme == "http":
            auth = "Basic " + base64.b64encode(urllib.parse.unquote(userinfo).encode("utf-8")).decode("ascii") \
                if userinfo else ""
            upstream = (host, port, auth)
            break
    deny = sorted({address[2] for address in found.values() if is_local(address[1])})
    try:
        os.close(os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))    # the owner's alone, like its folder
    except OSError:
        pass
    env[LOG_ENV] = log
    env[ALLOW_ENV] = ",".join(allow)
    env[DENY_ENV] = ",".join(str(p) for p in deny)
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and not holds_the_guard(p)]
    env["PYTHONPATH"] = os.pathsep.join([guard_folder(), *paths])    # one folder with the guard, and it comes first
    port = start_proxy()
    ours = f"http://127.0.0.1:{port}"
    for name in [*PROXY_VARS, *(k for k in list(env) if k in found or k in proxy_variables({k: env[k]}))]:
        env[name] = ours
    for name in ["NO_PROXY", "no_proxy", *(k for k in list(env) if "NO_PROXY" in k.upper() or "NOPROXY" in k.upper())]:
        env[name] = NO_PROXY
    _S.upstream = upstream
    from urllib.request import install_opener    # here, not at the top: every guarded program imports this module
    install_opener(None)                         # urllib keeps the proxies it saw at its first request: forget them
    install(log=log, allow=allow, deny_ports=deny)
    return Guard(log, port)


def isolate(folder: str, allow=(), environ=None, live: bool = False) -> Guard:
    """Everything a test or benchmark run needs, in the order that matters: note the forwarding proxies, take the
    keys out, move the home folder into `folder`, switch real model providers off, switch the guard on.

    `live` is for the live suite only (bench/live.py), which has already made its one approved provider (the key is
    in that object's memory): real providers are not switched off, and `allow` is the one approved destination.
    Everything else is the same. The keys still leave the environment, so no program the run starts has one."""
    env = os.environ if environ is None else environ
    forwarders = proxy_variables(env)             # before `scrub`, which removes some of the variables that name them
    removed = scrub(env)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    home = os.path.join(folder, "home")
    temp_home(home, env)
    if not live:
        env[NO_REAL_ENV] = "1"
    guard = activate(os.path.join(folder, "network-attempts.jsonl"), allow=allow, environ=env, forwarders=forwarders)
    guard.folder, guard.home, guard.removed, guard.allow = folder, home, removed, sorted(a for a in allow if a)
    return guard


def begin(allow=(), live: bool = False, out=None):
    """First line of a benchmark's `main`: isolate this process, unless whoever started it already has (a test, the
    isolated runner below, CI). Says in one line what was done. Returns the Guard, or None when already isolated."""
    out = out or sys.stderr
    if installed():
        out.write("isolated run: already inside one (started by a test or by the isolated runner)\n")
        return None
    import tempfile
    guard = isolate(tempfile.mkdtemp(prefix="lantern-isolated-"), allow=allow, live=live)
    off = os.environ.get(NO_REAL_ENV, "").strip().lower() not in ("", "0", "false", "no")
    out.write(f"isolated run: temporary home folder; {len(guard.removed)} key and sign-in variables taken out; real "
              f"model providers {'off' if off else 'ON, for this live run only'}; network refused except for: "
              f"{', '.join(guard.allow) or 'nothing'}\n")
    return guard


def end(guard, out=None) -> int:
    """Last lines of a benchmark's `main`: which declared hosts were reached and what was refused. Removes the
    temporary folder. Returns 1 when something was refused (the benchmark then fails), else 0."""
    if guard is None:
        return 0
    import shutil
    out = out or sys.stderr
    refused, through = guard.since(0), guard.let_through()
    hosts = sorted({f"{r.get('host')}:{r.get('port')}" for r in through})
    out.write(f"isolated run: {len(through)} connection(s) to declared hosts ({', '.join(hosts) or 'none'}); "
              f"{len(refused)} attempt(s) to reach anything else\n")
    if refused:
        out.write(f"{MARK}: refused:\n{describe(refused)}\n")
    if guard.folder:
        shutil.rmtree(guard.folder, ignore_errors=True)
    return 1 if refused else 0


def python_isolated(*arguments: str) -> list:
    """The command line that starts a Python program in isolated mode (`-I`: nothing from PYTHONPATH, the user's own
    packages or the current folder) inside a guarded run, with the guard in it. `-I` also keeps the start-up file
    beside this one from being loaded, so the program is started through this file, which switches the guard on first
    and then runs `-m MODULE ARGUMENT...` or `SCRIPT ARGUMENT...` as the program."""
    return [sys.executable, "-I", os.path.join(guard_folder(), GUARD_FILES[0]), "--inside", *arguments]


def _inside(argv: list) -> int:
    """`--inside -m MODULE ARGUMENT...` or `--inside SCRIPT ARGUMENT...`: what `python_isolated` starts."""
    if not os.environ.get(LOG_ENV) or not argv or (argv[0] == "-m" and len(argv) < 2):
        sys.stderr.write(f"{MARK}: --inside starts a program inside a guarded run: no guarded run is around this one, "
                         f"or no program was named, so nothing was started\n")
        return UNGUARDED
    import runpy
    sys.modules.setdefault("lantern_netguard", sys.modules[__name__])   # one guard, whatever name the program asks by
    install()
    if argv[0] == "-m":
        sys.argv = argv[1:]
        runpy.run_module(argv[1], run_name="__main__", alter_sys=True)
    else:
        sys.argv = argv
        runpy.run_path(argv[0], run_name="__main__")
    return 0


def has_route_out() -> bool:
    """Whether this process has any route to the outside (false inside `tools/netless.py`). Nothing is sent: a
    datagram socket is only pointed at a documentation address, which fails at once when there is no route."""
    _busy.on = True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(PROBE)
            return True
        except OSError:
            return False
        finally:
            s.close()
    finally:
        _busy.on = False


# ------------------------------------------------------------------------------------------------ from a shell
USAGE = """usage:
  python lantern_netguard.py [--allow HOST,HOST...] [--offline] -- COMMAND [ARGUMENT...]
      Run COMMAND with a temporary home folder, without the keys and saved sign-ins of this shell, with real model
      providers switched off, and with the network refused except for the hosts named with --allow. --offline also
      sets LANTERN_OFFLINE=1. Every refused attempt is listed at the end; the result is COMMAND's own, or 4 when
      COMMAND succeeded and something was refused.
  python -I lantern_netguard.py --inside -m MODULE [ARGUMENT...]      (or: --inside SCRIPT [ARGUMENT...])
      What python_isolated() starts: a Python program in isolated mode inside a guarded run. -I ignores PYTHONPATH,
      so the guard is switched on here first, from what the run's environment says, and then the program runs.
"""


def _run(allow: list, offline: bool, command: list) -> int:
    import subprocess
    import tempfile
    guard = isolate(tempfile.mkdtemp(prefix="lantern-isolated-"), allow=allow)
    try:
        if offline:
            os.environ["LANTERN_OFFLINE"] = "1"
        try:
            code = subprocess.call(command)
        except OSError as e:
            sys.stderr.write(f"{MARK}: cannot start {command[0]}: {e}\n")
            code = 127
    finally:
        refused = end(guard)
    return code or (4 if refused else 0)


def main(argv: list) -> int:
    if argv[:1] == ["--inside"]:
        return _inside(argv[1:])
    allow, offline, i = [], False, 0
    while i < len(argv) and argv[i] != "--":
        if argv[i] == "--allow" and i + 1 < len(argv):
            allow += [h.strip() for h in argv[i + 1].split(",") if h.strip()]
            i += 2
        elif argv[i] == "--offline":
            offline = True
            i += 1
        else:
            break
    if i >= len(argv) or argv[i] != "--" or i + 1 >= len(argv):
        sys.stderr.write(USAGE)
        return 2
    return _run(allow, offline, argv[i + 1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
