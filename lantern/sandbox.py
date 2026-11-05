"""Test sandbox for "Watch my tests run" (and the terminal's `trace`).

Lantern reads code and never runs it, with one exception the user asks for: running the project's own tests so the
map can mark the calls that really happen. Those tests run here, never in the project folder as the user:

* **Docker** when the daemon answers (`docker info`) on a Linux computer: a per-language image pinned by digest, the
  project mounted read-only at `/app`, a writable tmpfs at `/tmp`, `--network none`, `--cpus 2 --memory 2g`, a
  non-root user, no capabilities, a 10-minute wall clock. Python tests use the packages already installed in the
  Python that runs Lantern (mounted read-only), so nothing is downloaded. On macOS and Windows those packages are
  not Linux packages, so the restricted subprocess below is used instead.
* **Restricted subprocess** otherwise: a fresh, read-only temp copy of the project; the environment rebuilt from an
  allow-list (PATH, HOME=a temp folder, locale, the runtime's own variables) so no secrets are inherited; resource
  limits on POSIX (CPU, file size, memory for Python) and a Job Object on Windows (memory, kill on close); on Linux a
  Landlock rule set that allows writes only inside the sandbox's temp folder and denies TCP connect/bind; for Python a
  start-up audit hook that refuses writes outside the temp folder and any network socket, on every OS; when Lantern
  runs as root the tests run as `nobody`. The whole process tree is killed at the wall clock.

Both backends print `LANTERN-SANDBOX-BLOCKED: <what>` when a test tries to write outside its temp folder or open a
network connection; `blocked` in the result lists them so the app can say why the tests failed.

Python tests run under `lantern.tracehook`; their call pairs are mapped back to the project's own paths and merged
by `trace.merge_trace` exactly as `lantern trace` does. JavaScript, Go, Rust and Java tests run in the same sandbox,
but their calls are not recorded yet: the map upgrades for Python only for now.
Nothing here can create, close or re-rank a finding: the result is call pairs and an exit code.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import site
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

WALL_CLOCK = 600          # seconds; the directive's 10 minutes
MARK = "LANTERN-SANDBOX-BLOCKED:"
JS_NOTE = "Tests run; your map upgrades for Python only for now."

# Images pinned by digest (multi-arch index digests, Docker Hub). Bump together with a check that they still pull.
IMAGES = {
    "python3.11": "python:3.11-slim-bookworm@sha256:94a8fee35252d06ab75856f15f12c7bae67b10e8a6da93c7fded82b2610926cd",
    "python3.12": "python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337",
    "python3.13": "python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f",
    "node": "node:22-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da",
    "go": "golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db",
    "rust": "rust:1-slim-bookworm@sha256:24707e70a4f1e23d9a7b25202ec43126d28a52294b96aad5c670df1fd1f1d400",
    "java": "maven:3-eclipse-temurin-21@sha256:__MAVEN__",
}

# What the copy leaves out: version control, Lantern's own results, caches and virtualenvs (absolute paths inside a
# venv would point back at the original anyway).
SKIP = {".git", ".hg", ".svn", ".lantern", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv",
        "venv", ".tox", ".nox", "target", ".gradle", ".next", ".turbo", ".cache"}


# ---------------------------------------------------------------------------- which command
def _read_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _js_command(pkg: Path) -> tuple[str, str] | None:
    d = _read_json(pkg)
    script = (d.get("scripts") or {}).get("test") if isinstance(d.get("scripts"), dict) else None
    deps = {**(d.get("dependencies") or {}), **(d.get("devDependencies") or {})} if isinstance(d.get("devDependencies") or {}, dict) else {}
    root = pkg.parent
    pm = "pnpm" if (root / "pnpm-lock.yaml").exists() else "yarn" if (root / "yarn.lock").exists() else "npm"
    if isinstance(script, str) and script.strip() and "no test specified" not in script:
        return f"{pm} test", f"{pkg.parent.name}/package.json scripts.test" if pkg.parent.name else "package.json scripts.test"
    for tool, cmd in (("vitest", "npx vitest run"), ("jest", "npx jest"), ("mocha", "npx mocha")):
        if tool in deps:
            return cmd, f"{tool} in package.json"
    return None


def detect(repo: Path) -> dict:
    """The command the sheet shows first: read from the project, editable before it runs.
    `language` decides the image and whether calls are recorded (`traced`: Python only for now)."""
    repo = Path(repo)
    py = any((repo / f).exists() for f in ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "requirements.txt"))
    has_py_tests = (any(d.is_dir() for d in (repo / "tests", repo / "test")) and any(repo.glob("test*/**/*.py"))) \
        or any(repo.glob("test_*.py")) or any(repo.glob("*/tests/*.py"))
    if py or has_py_tests:
        return {"command": "python -m pytest -q", "how": "pyproject.toml / tests folder", "language": "python",
                "supported": True, "traced": True,
                "note": "Python tests are recorded function by function: calls they make turn solid on the map."}
    for pkg in [repo / "package.json", *sorted(repo.glob("*/package.json"))]:
        if pkg.exists() and "node_modules" not in pkg.parts:
            js = _js_command(pkg)
            if js:
                cmd, how = js
                if pkg.parent != repo:
                    how += f" (runs in {pkg.parent.name}/)"
                return {"command": cmd, "how": how, "language": "node", "cwd": pkg.parent.relative_to(repo).as_posix(),
                        "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "go.mod").exists():
        return {"command": "go test ./...", "how": "go.mod", "language": "go", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "Cargo.toml").exists():
        return {"command": "cargo test", "how": "Cargo.toml", "language": "rust", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "pom.xml").exists():
        return {"command": "mvn -q -o test", "how": "pom.xml", "language": "java", "supported": True, "traced": False, "note": JS_NOTE}
    if (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        cmd = "./gradlew test --offline" if (repo / "gradlew").exists() else "gradle test --offline"
        return {"command": cmd, "how": "build.gradle", "language": "java", "supported": True, "traced": False, "note": JS_NOTE}
    return {"command": "python -m pytest -q", "how": "default", "language": "python", "supported": False, "traced": False,
            "note": "No test setup was found. Add a tests folder (pytest, Jest, Vitest, Mocha, go test, cargo test, "
                    "Maven or Gradle), then try again."}


def check_command(words: list[str]) -> str:
    """The language of an accepted test command, or ValueError. Only test runners: the sheet never becomes 'run
    anything'. The command is an argv list and never goes through a shell."""
    if not words:
        raise ValueError("give the test command")
    head = Path(words[0]).name.lower().removesuffix(".exe").removesuffix(".cmd")
    rest = words[1:]
    if head in ("pytest", "py.test"):
        return "python"
    if head.startswith("python") or head == "py":
        if rest[:2] in (["-m", "pytest"], ["-m", "unittest"]) or (rest and rest[0].endswith(".py") and "test" in rest[0].lower()):
            return "python"
    if head in ("npm", "pnpm", "yarn") and (rest[:1] == ["test"] or rest[:2] == ["run", "test"]):
        return "node"
    if head == "npx" and rest[:1] and rest[0] in ("jest", "vitest", "mocha"):
        return "node"
    if head == "go" and rest[:1] == ["test"]:
        return "go"
    if head == "cargo" and rest[:1] == ["test"]:
        return "rust"
    if head in ("mvn", "mvnw", "gradle", "gradlew") and "test" in rest:
        return "java"
    raise ValueError("only a test command can run here: python -m pytest, pytest, python -m unittest, npm/pnpm/yarn "
                     "test, npx jest|vitest|mocha, go test, cargo test, mvn test or gradle test")


def split(command: str) -> list[str]:
    return shlex.split(command, posix=os.name != "nt") if command else []


# ---------------------------------------------------------------------------- which backend
_DOCKER: dict = {}


def docker_ok() -> bool:
    """The daemon answers, on Linux (cached for a minute). LANTERN_SANDBOX=subprocess turns Docker off."""
    if os.environ.get("LANTERN_SANDBOX", "").lower() == "subprocess" or not sys.platform.startswith("linux"):
        return False
    if _DOCKER.get("t", 0) > time.time() - 60:
        return _DOCKER["ok"]
    ok = False
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=8)
            ok = r.returncode == 0 and bool(r.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            ok = False
    _DOCKER.update(t=time.time(), ok=ok)
    return ok


def image_for(language: str) -> str | None:
    key = f"python{sys.version_info[0]}.{sys.version_info[1]}" if language == "python" else language
    img = IMAGES.get(key)
    return None if not img or "__" in img else img


def backend_for(language: str) -> str:
    if os.environ.get("LANTERN_SANDBOX", "").lower() == "docker":
        return "docker"
    return "docker" if docker_ok() and image_for(language) else "subprocess"


def describe(repo: Path, language: str) -> dict:
    """What the sheet shows before the user clicks Run."""
    b = backend_for(language)
    if b == "docker":
        return {"name": "docker", "label": "Docker container", "image": image_for(language),
                "details": ["your project is mounted read-only at /app", "network off (--network none)",
                            "2 CPUs, 2 GB memory, 10 minutes", "runs as an unprivileged user; scratch space is wiped after"]}
    det = ["a fresh read-only copy of your project in a temp folder, deleted after",
           "your environment variables are not passed on (no keys or tokens)", "10 minutes, then everything it started is stopped"]
    if sys.platform.startswith("linux") and landlock_abi() >= 1:
        det.insert(1, "writes allowed only in its own temp folder" + (", network connections refused" if landlock_abi() >= 4 else ""))
    if language == "python":
        det.insert(1, "writing outside its temp folder and opening network connections are refused")
    return {"name": "subprocess", "label": "Restricted process on this computer", "image": None, "details": det}


# ---------------------------------------------------------------------------- Linux Landlock (used by _jail)
def landlock_abi() -> int:
    if not sys.platform.startswith("linux"):
        return 0
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        r = libc.syscall(444, None, 0, 1)   # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        return r if r > 0 else 0
    except (OSError, AttributeError):
        return 0


# ---------------------------------------------------------------------------- the Python audit hook
SITECUSTOMIZE = r'''
# Lantern test sandbox: refuse writes outside the sandbox's temp folder and any network connection.
# Installed as sitecustomize so it is in place before the tests import anything; audit hooks cannot be removed.
import os as _os, sys as _sys, socket as _socket
_W = [_os.path.realpath(p) for p in _os.environ.get("LANTERN_SANDBOX_WRITABLE", "").split(_os.pathsep) if p]
_DEV = {_os.devnull, "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
_NET = {getattr(_socket, "AF_INET", 2), getattr(_socket, "AF_INET6", 10)}
_WFLAGS = _os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_APPEND | getattr(_os, "O_TRUNC", 0)
for _p in _os.environ.get("LANTERN_SANDBOX_SITE", "").split(_os.pathsep):
    if _p and _p not in _sys.path:   # the host's packages (Docker); their .pth files name host paths, so skip them
        _sys.path.append(_p)
def _ok(path):
    try:
        p = _os.path.realpath(_os.fsdecode(path))
    except (TypeError, ValueError):
        return True
    if p in _DEV or p.upper() == "NUL" or p.startswith("\\\\.\\"):
        return True
    return any(p == w or p.startswith(w + _os.sep) for w in _W)
def _block(what):
    msg = "LANTERN-SANDBOX-BLOCKED: " + what
    try:
        _os.write(2, (msg + "\n").encode("utf-8", "replace"))
    except OSError:
        pass
    raise PermissionError(msg)
_PATHS = {"os.remove": (0,), "os.rmdir": (0,), "os.mkdir": (0,), "os.rename": (0, 1), "os.replace": (0, 1),
          "os.symlink": (1,), "os.link": (1,), "os.truncate": (0,), "os.chmod": (0,), "os.chown": (0,),
          "os.utime": (0,), "shutil.rmtree": (0,), "shutil.copyfile": (1,), "shutil.move": (1,)}
def _hook(ev, args):
    if ev == "open":
        path, mode, flags = (tuple(args) + (None, None, None))[:3]
        if isinstance(path, int) or path is None:
            return
        w = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & _WFLAGS)
        if w and not _ok(path):
            _block("write to " + _os.fsdecode(path))
    elif ev in _PATHS:
        for i in _PATHS[ev]:
            p = args[i] if i < len(args) else None
            if p is not None and not isinstance(p, int) and not _ok(p):
                _block(ev.split(".")[-1] + " " + _os.fsdecode(p))
    elif ev in ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"):
        s = args[0]
        if getattr(s, "family", None) in _NET:
            _block("network " + ev.split(".")[1] + " " + repr(args[1] if len(args) > 1 else "")[:80])
    elif ev == "socket.getaddrinfo":
        host = args[0] if args else None
        if host not in (None, "", "localhost", "127.0.0.1", "::1", b"localhost"):
            _block("network lookup " + repr(host)[:80])
_sys.addaudithook(_hook)
'''


# ---------------------------------------------------------------------------- running
class Result(dict):
    pass


def _copy(repo: Path, dst: Path) -> None:
    def ignore(d, names):
        return [n for n in names if n in SKIP]
    shutil.copytree(repo, dst, symlinks=True, ignore=ignore)


_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def _make_read_only(root: Path) -> None:
    """Take every write bit off the copy (read and execute bits are left as they were)."""
    for dirpath, _dirs, files in os.walk(root, topdown=False):
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode & ~_WRITE_BITS)
        os.chmod(dirpath, os.stat(dirpath).st_mode & ~_WRITE_BITS)


def _rm(path: Path) -> None:
    def onerr(fn, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            parent = os.path.dirname(p)
            os.chmod(parent, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            fn(p)
        except OSError:
            pass
    def owner_writable(p):   # give the owner its write bit back so the copy can be deleted
        try:
            os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
        except OSError:
            pass
    owner_writable(path)
    for dirpath, dirs, _files in os.walk(path):
        for d in dirs:
            owner_writable(os.path.join(dirpath, d))
    shutil.rmtree(path, onerror=onerr) if sys.version_info < (3, 12) else shutil.rmtree(path, onexc=onerr)


def _env_base(tmp: Path) -> dict:
    """The allow-list. Nothing else from the user's environment reaches the tests."""
    keep = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT",
            "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "VIRTUAL_ENV", "JAVA_HOME"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "TMPDIR": str(tmp), "TEMP": str(tmp), "TMP": str(tmp),
                "APPDATA": str(home), "LOCALAPPDATA": str(home), "XDG_CACHE_HOME": str(tmp / "cache"),
                "CI": "true", "TERM": "dumb", "NO_COLOR": "1", "LANTERN_SANDBOX_WRITABLE": str(tmp),
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(tmp / "pycache"), "PYTHONUTF8": "1",
                "npm_config_cache": str(tmp / "npm"), "npm_config_update_notifier": "false",
                "GOCACHE": str(tmp / "gocache"), "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "-mod=mod",
                "CARGO_TARGET_DIR": str(tmp / "target"), "CARGO_NET_OFFLINE": "true"})
    real = Path.home()
    for var, default in (("GOPATH", real / "go"), ("GOMODCACHE", real / "go" / "pkg" / "mod"),
                         ("CARGO_HOME", real / ".cargo"), ("RUSTUP_HOME", real / ".rustup")):
        v = os.environ.get(var) or (str(default) if default.exists() else None)
        if v:
            env[var] = v
    m2 = real / ".m2" / "repository"
    if m2.exists():
        env["MAVEN_OPTS"] = f"-Dmaven.repo.local={m2}"
    return env


def _python_argv(words: list[str]) -> list[str]:
    """`python -m pytest -q` -> the part after the interpreter, with pytest's cache off (it would write next to the
    tests, which the sandbox refuses)."""
    head = Path(words[0]).name.lower()
    rest = words[1:] if head.startswith("python") or head == "py" else ["-m", "pytest", *words[1:]]
    if rest[:2] == ["-m", "pytest"] and "no:cacheprovider" not in rest:
        rest = rest[:2] + ["-p", "no:cacheprovider"] + rest[2:]
    return rest


def _stream(cmd: list[str], cwd: Path, env: dict, timeout: float, log, job=None) -> tuple[int | None, str, bool]:
    """Run, streaming each output line to `log`; at the wall clock the whole process tree is killed."""
    from .remote import _kill_tree
    kw: dict = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == "win32" else {"start_new_session": True}
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", **kw)
    if job is not None:
        job(proc)
    lines: list[str] = []

    def reader():
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if len(lines) > 4000:
                del lines[:1000]
            log(line)
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    except BaseException:
        _kill_tree(proc)
        raise
    t.join(timeout=5)
    return (None if timed_out else proc.returncode), "\n".join(lines), timed_out


def _windows_job(proc) -> None:
    """Windows: put the test process in a Job Object (2 GB per process, everything killed when the job closes)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rt", "wt", "ot")]

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        job = k32.CreateJobObjectW(None, None)
        info = EXT()
        info.Basic.LimitFlags = 0x2000 | 0x100   # KILL_ON_JOB_CLOSE | PROCESS_MEMORY
        info.ProcessMemoryLimit = 2 << 30
        k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))   # ExtendedLimitInformation
        k32.OpenProcess.restype = wintypes.HANDLE
        h = k32.OpenProcess(0x1F0FFF, False, proc.pid)
        k32.AssignProcessToJobObject(job, h)
        k32.CloseHandle(h)
        proc._lantern_job = job   # closed (and the tree killed) when the Popen object goes away
    except Exception:  # noqa: BLE001 - the wall clock and the scrubbed copy still apply
        pass


def blocked_reasons(output: str) -> list[str]:
    """What the sandbox refused, from its own markers and the kernel's messages (read-only mount, no network)."""
    out, seen = [], set()
    for line in output.splitlines():
        i = line.find(MARK)
        why = None
        if i >= 0:
            why = line[i + len(MARK):].strip()
            if not why or why[0] in "\"'":   # the hook's own source line in a traceback
                continue
        elif "Read-only file system" in line:
            why = "write to a read-only file (the project is mounted read-only)"
        elif "Network is unreachable" in line or "Temporary failure in name resolution" in line:
            why = "network (the sandbox has no network)"
        if why:
            kind = "network" if why.startswith("network") else "write"
            key = (kind, why[:120])
            if key not in seen:
                seen.add(key)
                out.append({"kind": kind, "what": why[:200]})
    return out[:10]


def _map_pairs(data: dict, inner_root: str, repo: Path) -> dict:
    """Recorded filenames point into the copy or the container; point them back at the project."""
    inner = inner_root.rstrip("/\\")
    real = str(repo.resolve())
    for row in data.get("pairs", []):
        for side in ("caller", "callee"):
            f = row[side][0]
            if isinstance(f, str):
                norm = os.path.realpath(f) if not f.startswith("/app") else f
                for pre in {inner, os.path.realpath(inner)}:
                    if norm == pre or norm.startswith(pre + "/") or norm.startswith(pre + os.sep):
                        row[side][0] = real + norm[len(pre):].replace("/", os.sep)
                        break
    return data


def run(repo: Path, words: list[str], log=print, timeout: float = WALL_CLOCK, backend: str | None = None,
        cwd_rel: str = "") -> Result:
    """Run the test command `words` for `repo` in the sandbox. Returns trace data for `trace.merge_trace` (`pairs`)
    plus `backend`, `language`, `traced`, `returncode`, `timed_out`, `blocked`, `output_tail`, `stderr_tail`."""
    repo = Path(repo).resolve()
    language = check_command(words)
    backend = backend or backend_for(language)
    root = Path(tempfile.mkdtemp(prefix="lantern-sandbox-"))
    try:
        if backend == "docker":
            res = _run_docker(repo, words, language, root, log, timeout, cwd_rel)
        else:
            res = _run_subprocess(repo, words, language, root, log, timeout, cwd_rel)
    finally:
        _rm(root)
    res.update(backend=backend, language=language, traced=language == "python")
    res["blocked"] = blocked_reasons(res.get("output_tail", "") + "\n" + res.pop("_full", ""))
    res["stderr_tail"] = res.get("output_tail", "")[-2000:]
    return res


def _run_subprocess(repo, words, language, root, log, timeout, cwd_rel) -> Result:
    app, tmp, hook = root / "app", root / "tmp", root / "hook"
    tmp.mkdir()
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    log("sandbox: copying the project to a temp folder")
    _copy(repo, app)
    _make_read_only(app)
    env = _env_base(tmp)
    as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
    if as_nobody:   # root ignores file modes: run the tests as nobody, who owns only the sandbox folder and its temp
        for dirpath, _dirs, files in os.walk(tmp):
            os.chown(dirpath, 65534, 65534)
            for f in files:
                os.chown(os.path.join(dirpath, f), 65534, 65534)
        os.chown(root, 65534, 65534)   # mode stays 0700; the copy inside keeps root as owner and no write bits
    out_json = tmp / "trace.json"
    pkg_root = str(Path(__file__).resolve().parent.parent)
    if language == "python":
        env["PYTHONPATH"] = os.pathsep.join([str(hook), pkg_root, str(app)])
        cmd = [sys.executable, "-m", "lantern.tracehook", str(out_json), str(app), "--", *_python_argv(words)]
    else:
        exe = shutil.which(words[0], path=env.get("PATH")) or (str(app / words[0]) if words[0].startswith("./") else words[0])
        cmd = [exe, *words[1:]]
    cwd = app / cwd_rel if cwd_rel else app
    if os.name == "posix":
        policy = {"writable": [str(tmp)], "nobody": as_nobody, "python": language == "python",
                  "net": True}
        cmd = [sys.executable, "-I", "-m", "lantern._jail", json.dumps(policy), "--", *cmd]
        env_jail = dict(env)
        env_jail["PYTHONPATH"] = env.get("PYTHONPATH", "") if language == "python" else ""
        env = env_jail
        # -I ignores PYTHONPATH for the jail itself; it finds lantern from its own path below
        cmd[2:4] = ["-c", f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])"]
    log(f"sandbox: restricted process, running {' '.join(words)}")
    rc, output, timed_out = _stream(cmd, cwd, env, timeout, log, job=_windows_job)
    if timed_out:
        log(f"sandbox: stopped after {int(timeout)} s (the wall clock); every process it started was ended")
    data = {}
    if out_json.exists():
        try:
            data = json.loads(out_json.read_text(encoding="utf-8") or "{}")
        except ValueError:
            data = {}
    _map_pairs(data, str(app), repo)
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, output_tail=output[-6000:], _full=output)


def _site_dirs() -> list[str]:
    seen = []
    for p in sys.path:
        if p and p.rstrip("/").endswith(("site-packages", "dist-packages")) and os.path.isdir(p) and p not in seen:
            seen.append(p)
    try:
        u = site.getusersitepackages()
        if os.path.isdir(u) and u not in seen:
            seen.append(u)
    except AttributeError:
        pass
    return seen


def _run_docker(repo, words, language, root, log, timeout, cwd_rel) -> Result:
    img = image_for(language)
    if not img:
        raise RuntimeError(f"no pinned Docker image for {language}")
    out, hook = root / "out", root / "hook"
    out.mkdir()
    hook.mkdir()
    # the container runs as the user who runs Lantern (or nobody, when that is root), who owns /out
    uid, gid = (os.getuid(), os.getgid()) if os.getuid() != 0 else (65534, 65534)
    if os.getuid() == 0:
        os.chown(out, uid, gid)
    (hook / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    name = "lantern-sbx-" + uuid.uuid4().hex[:12]
    pkg = Path(__file__).resolve().parent
    args = ["docker", "run", "--rm", "--name", name, "--network", "none", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "512", "--user", f"{uid}:{gid}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,size=1g,mode=1777",  # nosec B108: the container's own tmpfs
            "-v", f"{repo}:/app:ro", "-v", f"{out}:/out:rw", "-v", f"{hook}:/opt/hook:ro",
            "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp", "-e", "CI=true", "-e", "NO_COLOR=1",
            "-e", "LANTERN_SANDBOX_WRITABLE=/tmp" + os.pathsep + "/out", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "npm_config_cache=/tmp/npm", "-e", "GOCACHE=/tmp/gocache", "-e", "GOFLAGS=-mod=mod",
            "-e", "GOPROXY=off", "-e", "GOTOOLCHAIN=local", "-e", "CARGO_TARGET_DIR=/tmp/target",
            "-e", "CARGO_NET_OFFLINE=true", "-w", "/app/" + cwd_rel if cwd_rel else "/app"]
    if language == "python":
        sites = _site_dirs()
        for i, s in enumerate(sites):
            args += ["-v", f"{s}:/opt/site/{i}:ro"]
        args += ["-v", f"{pkg}:/opt/lantern/lantern:ro",
                 "-e", "PYTHONPATH=" + ":".join(["/opt/hook", "/opt/lantern", "/app"]),
                 "-e", "LANTERN_SANDBOX_SITE=" + ":".join(f"/opt/site/{i}" for i in range(len(sites)))]
        cmd = ["python", "-m", "lantern.tracehook", "/out/trace.json", "/app", "--", *_python_argv(words)]
    else:
        env = _env_base(root)
        for var, where in (("GOMODCACHE", "/go/pkg/mod"), ("CARGO_HOME", None)):
            if env.get(var) and Path(env[var]).exists():
                if var == "CARGO_HOME":
                    reg = Path(env[var]) / "registry"
                    if reg.exists():
                        args += ["-v", f"{reg}:/usr/local/cargo/registry:ro"]
                else:
                    args += ["-v", f"{env[var]}:{where}:ro"]
        m2 = Path.home() / ".m2" / "repository"
        if language == "java" and m2.exists():
            args += ["-v", f"{m2}:/m2:ro", "-e", "MAVEN_OPTS=-Dmaven.repo.local=/m2"]
        cmd = list(words)
    log(f"sandbox: Docker ({img.split('@')[0]}, network off, project read-only), running {' '.join(words)}")
    rc, output, timed_out = _stream(args + [img, *cmd], root, {k: v for k, v in os.environ.items()}, timeout, log)
    if timed_out:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        log(f"sandbox: stopped after {int(timeout)} s (the wall clock); the container was removed")
    data = {}
    if (out / "trace.json").exists():
        try:
            data = json.loads((out / "trace.json").read_text(encoding="utf-8") or "{}")
        except ValueError:
            data = {}
    _map_pairs(data, "/app", repo)
    return Result(pairs=data.get("pairs", []), returncode=rc, timed_out=timed_out, output_tail=output[-6000:], _full=output)
